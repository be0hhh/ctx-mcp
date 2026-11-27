//! Sharded source cache, per-file load coordination, workspace indexing,
//! per-session read state, and metadata-only reboot snapshots.

mod index;
pub(crate) mod paths;
mod session;
mod snapshot;
pub mod warm;

pub use index::MissingResolution;
pub use paths::{
    default_snapshot_path, display_workspace_path, is_multimodal_or_binary_ext,
    norm_key_from_canon, norm_path, resolve_input_path, restore_caller_path_style, runtime_dir,
    shared_repo_key, should_skip_dir,
};
#[allow(unused_imports)]
pub use session::{DeltaHit, DuplicateHit, SessionReadStatus};
pub use snapshot::verify_snapshot_metadata_only;
pub use warm::{spawn_background_prewarm, PrewarmTracker};

use crate::base::security::{is_sensitive_path, is_sensitive_path_with_ws};
use crate::base::simd::{
    fast_hash64, line_slice_at, push_u32, push_usize, scan_source_bytes,
    trigram_bloom128_ascii_lower, CachePadded, FastHashMap, ScanError,
};
use crate::parser::{
    build_cleaned_code_buffer_for_ext, clean_lang_tag, extract_symbols, file_parser_kind,
    SymbolSpan,
};
use index::WorkspaceIndexCache;
use session::{DedupRing, DeltaSnapshotRing, SessionShardMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_SINGLE_FILE_CACHE_BYTES: usize = 1_048_576; // 1 MiB full-file read/cache ceiling
pub const HARD_RAM_CAP_BYTES: usize = 4usize << 30; // 4 GiB ceiling
pub const SNAPSHOT_DISK_CAP_BYTES: usize = 64 << 20; // 64 MiB max metadata-only snapshot
const SHARD_COUNT: usize = 64;
const SHARD_MASK: usize = SHARD_COUNT - 1;
const MAX_BODY_DEDUP_ENTRIES: usize = 4096;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PathId(pub u32);

#[derive(Default)]
struct PathInterner {
    to_id: FastHashMap<Arc<str>, PathId>,
    from_id: Vec<Arc<str>>,
}

impl PathInterner {
    fn intern(&mut self, key: &str) -> (PathId, Arc<str>) {
        if let Some(&id) = self.to_id.get(key) {
            return (id, Arc::clone(&self.from_id[id.0 as usize]));
        }
        let arc: Arc<str> = Arc::from(key);
        let id = PathId(self.from_id.len() as u32);
        self.from_id.push(Arc::clone(&arc));
        self.to_id.insert(Arc::clone(&arc), id);
        (id, arc)
    }

    fn get(&self, id: PathId) -> Option<&Arc<str>> {
        self.from_id.get(id.0 as usize)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct BodyDedupKey {
    content_hash64: u64,
    size_bytes: u32,
    parser_kind: u8,
    clean_lang: u8,
}

fn sub_atomic_saturating(counter: &AtomicUsize, freed: usize) {
    if freed == 0 {
        return;
    }
    let mut cur = counter.load(Ordering::Relaxed);
    loop {
        let next = cur.saturating_sub(freed);
        match counter.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
}

#[derive(Debug)]
pub struct ParsedBody {
    pub content: Arc<str>,
    pub line_offsets: Box<[u32]>,
    pub symbols: Arc<[SymbolSpan]>,
    pub content_bloom: [u64; 2],
    pub cleaned_code: OnceLock<Arc<str>>,
    pub cleaned_charge: AtomicU32,
    pub base_charge: u32,
    pub cache_owners: AtomicU32,
    pub line_count: u32,
    #[allow(dead_code)]
    pub size_bytes: u32,
    #[allow(dead_code)]
    pub content_hash64: u64,
    ram_counter: Arc<AtomicUsize>,
    acct_lock: Mutex<()>,
}

impl ParsedBody {
    #[allow(clippy::too_many_arguments)]
    fn new(
        content: Arc<str>,
        line_offsets: Box<[u32]>,
        symbols: Arc<[SymbolSpan]>,
        content_bloom: [u64; 2],
        base_charge: u32,
        line_count: u32,
        size_bytes: u32,
        content_hash64: u64,
        ram_counter: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            content,
            line_offsets,
            symbols,
            content_bloom,
            cleaned_code: OnceLock::new(),
            cleaned_charge: AtomicU32::new(0),
            base_charge,
            cache_owners: AtomicU32::new(0),
            line_count,
            size_bytes,
            content_hash64,
            ram_counter,
            acct_lock: Mutex::new(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(text: String, line_offsets: Box<[u32]>, line_count: u32) -> Arc<Self> {
        let size_bytes = text.len() as u32;
        Arc::new(Self::new(
            Arc::from(text),
            line_offsets,
            Arc::from([]),
            [0, 0],
            0,
            line_count,
            size_bytes,
            0,
            Arc::new(AtomicUsize::new(0)),
        ))
    }

    fn attach_cache_owner(&self) {
        let Ok(_g) = self.acct_lock.lock() else {
            return;
        };
        let prev = self.cache_owners.fetch_add(1, Ordering::AcqRel);
        if prev == 0 {
            let cleaned = self.cleaned_charge.load(Ordering::Acquire) as usize;
            let total = (self.base_charge as usize).saturating_add(cleaned);
            self.ram_counter.fetch_add(total, Ordering::Relaxed);
        }
    }

    fn detach_cache_owner(&self) {
        let Ok(_g) = self.acct_lock.lock() else {
            return;
        };
        let prev = self.cache_owners.load(Ordering::Acquire);
        if prev == 0 {
            return;
        }
        let next = prev - 1;
        self.cache_owners.store(next, Ordering::Release);
        if next == 0 {
            let cleaned = self.cleaned_charge.load(Ordering::Acquire) as usize;
            let total = (self.base_charge as usize).saturating_add(cleaned);
            sub_atomic_saturating(&self.ram_counter, total);
        }
    }

    fn record_cleaned_charge(&self, len: u32) {
        if len == 0 {
            return;
        }
        let Ok(_g) = self.acct_lock.lock() else {
            return;
        };
        if self.cleaned_charge.load(Ordering::Acquire) != 0 {
            return;
        }
        self.cleaned_charge.store(len, Ordering::Release);
        if self.cache_owners.load(Ordering::Acquire) > 0 {
            self.ram_counter.fetch_add(len as usize, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
pub struct CachedFile {
    pub norm_path: Arc<str>,
    pub rel_path: Box<str>,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
    pub ino: u64,
    pub content_hash64: u64,
    pub path_id: PathId,
    pub size_bytes: u32,
    pub line_count: u32,
    pub symbols: Arc<[SymbolSpan]>,
    pub body: Option<Arc<ParsedBody>>,
    pub last_access: AtomicU64,
}

impl CachedFile {
    fn without_body(&self) -> Self {
        Self {
            norm_path: Arc::clone(&self.norm_path),
            rel_path: self.rel_path.clone(),
            mtime_ns: self.mtime_ns,
            ctime_ns: self.ctime_ns,
            ino: self.ino,
            content_hash64: self.content_hash64,
            path_id: self.path_id,
            size_bytes: self.size_bytes,
            line_count: self.line_count,
            symbols: Arc::clone(&self.symbols),
            body: None,
            last_access: AtomicU64::new(self.last_access.load(Ordering::Relaxed)),
        }
    }

    #[inline]
    pub fn has_body(&self) -> bool {
        self.body.is_some()
    }

    #[inline]
    pub fn content(&self) -> Option<&str> {
        self.body.as_deref().map(|b| b.content.as_ref())
    }

    #[inline]
    pub fn content_arc(&self) -> Option<&Arc<str>> {
        self.body.as_deref().map(|b| &b.content)
    }

    #[inline]
    pub fn line_offsets(&self) -> &[u32] {
        self.body.as_deref().map_or(&[], |b| b.line_offsets.as_ref())
    }

    #[inline]
    pub fn content_bloom(&self) -> [u64; 2] {
        self.body.as_deref().map_or([0, 0], |b| b.content_bloom)
    }

    /// Lazily builds and caches the comment/string-blanked buffer once per shared `ParsedBody`.
    /// Charges RAM strictly while `cache_owners > 0` so evicted entries never leak accounting.
    pub fn cleaned_code_for_ext(&self, ext: &str, _store: &RamStore) -> Option<Arc<str>> {
        let body = self.body.as_deref()?;
        if let Some(existing) = body.cleaned_code.get() {
            return Some(Arc::clone(existing));
        }
        let built: Arc<str> = Arc::from(build_cleaned_code_buffer_for_ext(&body.content, ext));
        if body.cleaned_code.set(Arc::clone(&built)).is_ok() {
            let len = built.len().min(u32::MAX as usize) as u32;
            body.record_cleaned_charge(len);
        }
        Some(Arc::clone(body.cleaned_code.get().unwrap_or(&built)))
    }

    #[inline]
    pub fn line_slice(&self, line_1based: u32) -> &str {
        match self.body.as_deref() {
            Some(body) => line_slice_at(&body.content, &body.line_offsets, line_1based),
            None => "",
        }
    }
}

struct InflightSlot {
    done: Mutex<bool>,
    cv: Condvar,
}

struct InflightGuard<'a> {
    map: &'a Mutex<FastHashMap<Arc<str>, Arc<InflightSlot>>>,
    key: Arc<str>,
    slot: Arc<InflightSlot>,
}

impl<'a> Drop for InflightGuard<'a> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.map.lock() {
            guard.remove(&self.key);
        }
        if let Ok(mut done) = self.slot.done.lock() {
            *done = true;
        }
        self.slot.cv.notify_all();
    }
}

type FileShardMap = FastHashMap<Arc<str>, Arc<CachedFile>>;

pub struct RamStore {
    pub max_ram_bytes: usize,
    used_ram_bytes: RwLock<Arc<AtomicUsize>>,
    pub mutation_epoch: CachePadded<AtomicU64>,
    pub access_clock: CachePadded<AtomicU64>,
    pub cache_hits: CachePadded<AtomicU64>,
    pub cache_misses: CachePadded<AtomicU64>,
    pub dirty_since_save: AtomicBool,
    pub last_save_ms: AtomicU64,
    paths: RwLock<PathInterner>,
    shards: Box<[CachePadded<RwLock<FileShardMap>>; SHARD_COUNT]>,
    body_dedup: RwLock<FastHashMap<BodyDedupKey, Weak<ParsedBody>>>,
    inflight: Mutex<FastHashMap<Arc<str>, Arc<InflightSlot>>>,
    sessions: Box<[CachePadded<Mutex<SessionShardMap>>; SHARD_COUNT]>,
    dedup_ring: Mutex<DedupRing>,
    delta_ring: Mutex<DeltaSnapshotRing>,
    ws_cache: Arc<WorkspaceIndexCache>,
    pub snapshot_path: PathBuf,
}

#[inline]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[inline]
pub fn now_ms_u64() -> u64 {
    now_ms()
}

pub fn detect_ram_budget() -> usize {
    crate::base::platform::detect_ram_budget_bytes(HARD_RAM_CAP_BYTES)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileMetaStamp {
    pub mtime_ns: u64,
    pub ctime_ns: u64,
    pub ino: u64,
    pub size_bytes: u64,
}

impl FileMetaStamp {
    fn matches(self, entry: &CachedFile) -> bool {
        self.mtime_ns == entry.mtime_ns
            && self.ctime_ns == entry.ctime_ns
            && self.ino == entry.ino
            && self.size_bytes == u64::from(entry.size_bytes)
    }
}

pub fn file_stat(path: &Path) -> Result<FileMetaStamp, String> {
    stamp_metadata(
        &fs::metadata(path).map_err(|e| format!("{}: {}", path.display(), e))?,
        path,
    )
}

fn stamp_metadata(meta: &fs::Metadata, path: &Path) -> Result<FileMetaStamp, String> {
    if !meta.is_file() {
        return Err(format!("not a regular file: {}", path.display()));
    }
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0);

    #[cfg(unix)]
    let (ctime_ns, ino) = {
        use std::os::unix::fs::MetadataExt;
        let sec = meta.ctime().max(0) as u64;
        let nsec = meta.ctime_nsec().max(0) as u64;
        (sec.saturating_mul(1_000_000_000).saturating_add(nsec), meta.ino())
    };

    #[cfg(not(unix))]
    let (ctime_ns, ino) = (0u64, 0u64);

    Ok(FileMetaStamp {
        mtime_ns,
        ctime_ns,
        ino,
        size_bytes: meta.len(),
    })
}

#[inline]
fn shard_idx_for(key: &str) -> usize {
    (fast_hash64(key.as_bytes()) as usize) & SHARD_MASK
}

impl RamStore {
    pub fn new(snapshot_path: PathBuf) -> Self {
        let shards = Box::new(std::array::from_fn(|_| {
            CachePadded::new(RwLock::new(FileShardMap::default()))
        }));
        let sessions = Box::new(std::array::from_fn(|_| {
            CachePadded::new(Mutex::new(SessionShardMap::default()))
        }));
        let store = Self {
            max_ram_bytes: detect_ram_budget(),
            used_ram_bytes: RwLock::new(Arc::new(AtomicUsize::new(0))),
            mutation_epoch: CachePadded::new(AtomicU64::new(1)),
            access_clock: CachePadded::new(AtomicU64::new(1)),
            cache_hits: CachePadded::new(AtomicU64::new(0)),
            cache_misses: CachePadded::new(AtomicU64::new(0)),
            dirty_since_save: AtomicBool::new(false),
            last_save_ms: AtomicU64::new(now_ms()),
            paths: RwLock::new(PathInterner::default()),
            shards,
            body_dedup: RwLock::new(FastHashMap::default()),
            inflight: Mutex::new(FastHashMap::default()),
            sessions,
            dedup_ring: Mutex::new(DedupRing::default()),
            delta_ring: Mutex::new(DeltaSnapshotRing::default()),
            ws_cache: Arc::new(WorkspaceIndexCache::default()),
            snapshot_path,
        };
        let _ = store.load_snapshot();
        store
    }

    #[inline]
    pub fn mutation_epoch(&self) -> u64 {
        self.mutation_epoch.load(Ordering::Acquire)
    }

    #[inline]
    pub fn bump_mutation_epoch(&self) {
        self.mutation_epoch.fetch_add(1, Ordering::Release);
    }

    #[inline]
    fn current_ram_counter(&self) -> Arc<AtomicUsize> {
        let guard = self
            .used_ram_bytes
            .read()
            .unwrap_or_else(|e| e.into_inner());
        Arc::clone(&guard)
    }

    #[inline]
    pub fn used_ram_bytes(&self) -> usize {
        self.current_ram_counter().load(Ordering::Relaxed)
    }

    #[inline]
    fn next_tick(&self) -> u64 {
        self.access_clock.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn intern_path(&self, key: &str) -> (PathId, Arc<str>) {
        if let Ok(r) = self.paths.read() {
            if let Some(&id) = r.to_id.get(key) {
                if let Some(arc) = r.get(id) {
                    return (id, Arc::clone(arc));
                }
            }
        }
        let mut w = self.paths.write().unwrap_or_else(|e| e.into_inner());
        w.intern(key)
    }

    #[inline]
    pub fn ram_usage_and_budget(&self) -> (usize, usize) {
        (self.used_ram_bytes(), self.max_ram_bytes)
    }

    pub fn cached_file_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.read().map(|g| g.len()).unwrap_or(0))
            .sum()
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions
            .iter()
            .map(|s| s.lock().map(|g| g.len()).unwrap_or(0))
            .sum()
    }

    pub fn clear_all(&self) {
        if let Ok(mut counter) = self.used_ram_bytes.write() {
            *counter = Arc::new(AtomicUsize::new(0));
        }
        if let Ok(mut dedup) = self.body_dedup.write() {
            dedup.clear();
        }
        for sh in self.shards.iter() {
            if let Ok(mut g) = sh.write() {
                for (_, entry) in g.drain() {
                    if let Some(body) = entry.body.as_deref() {
                        body.detach_cache_owner();
                    }
                }
            }
        }
        for ss in self.sessions.iter() {
            if let Ok(mut g) = ss.lock() {
                g.clear();
            }
        }
        if let Ok(mut dr) = self.delta_ring.lock() {
            dr.clear();
        }
        if let Ok(mut wi) = self.ws_cache.indices.write() {
            wi.clear();
        }
        if let Ok(mut p) = self.paths.write() {
            p.to_id.clear();
            p.from_id.clear();
        }
        self.bump_mutation_epoch();
        let _ = fs::remove_file(&self.snapshot_path);
    }

    fn evict_if_needed(&self, incoming_bytes: usize) {
        if self.used_ram_bytes().saturating_add(incoming_bytes) <= self.max_ram_bytes {
            return;
        }
        let target = self
            .max_ram_bytes
            .saturating_sub(incoming_bytes)
            .saturating_sub(self.max_ram_bytes >> 4);

        // Compact 16-byte `Copy` eviction candidates (`0` String clones!).
        let mut candidates: Vec<(u64, u8, PathId)> = Vec::new();
        for (s_idx, sh) in self.shards.iter().enumerate() {
            if let Ok(guard) = sh.read() {
                for v in guard.values() {
                    if v.has_body() {
                        candidates.push((
                            v.last_access.load(Ordering::Relaxed),
                            s_idx as u8,
                            v.path_id,
                        ));
                    }
                }
            }
        }
        candidates.sort_unstable_by_key(|&(acc, _, _)| acc);

        for (_, s_idx, path_id) in candidates {
            if self.used_ram_bytes() <= target {
                break;
            }
            let key_opt = self
                .paths
                .read()
                .ok()
                .and_then(|p| p.get(path_id).cloned());
            let Some(key) = key_opt else {
                continue;
            };
            if let Ok(mut guard) = self.shards[s_idx as usize].write() {
                if let Some(existing) = guard.get(&key).cloned() {
                    if let Some(body) = existing.body.as_deref() {
                        let stripped = Arc::new(existing.without_body());
                        guard.insert(key, stripped);
                        body.detach_cache_owner();
                    }
                }
            }
        }
    }

    pub fn invalidate_path(&self, raw_path: &Path) {
        let key = norm_path(raw_path);
        let s_idx = shard_idx_for(&key);
        if let Ok(mut guard) = self.shards[s_idx].write() {
            if let Some(old) = guard.remove(key.as_str()) {
                if let Some(body) = old.body.as_deref() {
                    body.detach_cache_owner();
                }
                self.dirty_since_save.store(true, Ordering::Relaxed);
            }
        }
        self.bump_mutation_epoch();
        self.invalidate_workspace_indices();
    }

    /// Refreshes an existing file's cached body, symbols, and `content_hash64` in RAM
    /// without wiping the workspace directory index (`ws_cache`).
    pub fn refresh_file_content(
        &self,
        canon_path: &Path,
        ws_root: Option<&Path>,
    ) -> Result<Arc<CachedFile>, String> {
        let key = norm_key_from_canon(canon_path);
        let s_idx = shard_idx_for(&key);
        let old_entry = if let Ok(mut guard) = self.shards[s_idx].write() {
            guard.remove(key.as_str()).inspect(|old| {
                if let Some(body) = old.body.as_deref() {
                    body.detach_cache_owner();
                }
                self.dirty_since_save.store(true, Ordering::Relaxed);
            })
        } else {
            None
        };
        self.bump_mutation_epoch();
        if let Some(old) = old_entry {
            if let Some(content) = old.content_arc() {
                self.snapshot_delta(old.path_id, old.content_hash64, content);
            }
        }
        self.get_full_entry(canon_path, ws_root)
    }

    pub fn current_file_hash64(&self, path: &Path, ws_root: Option<&Path>) -> Option<u64> {
        let st = file_stat(path).ok()?;
        let canon = fs::canonicalize(path).ok()?;
        let key = norm_key_from_canon(&canon);
        let s_idx = shard_idx_for(&key);
        if let Ok(guard) = self.shards[s_idx].read() {
            if let Some(existing) = guard.get(key.as_str()) {
                if existing.mtime_ns == st.mtime_ns
                    && existing.ctime_ns == st.ctime_ns
                    && existing.ino == st.ino
                    && existing.size_bytes as u64 == st.size_bytes
                {
                    return Some(existing.content_hash64);
                }
            }
        }
        self.get_full_entry(&canon, ws_root)
            .ok()
            .map(|e| e.content_hash64)
    }

    pub fn get_outline_entry(
        &self,
        canon_path: &Path,
        ws_root: Option<&Path>,
    ) -> Result<Arc<CachedFile>, String> {
        self.get_entry(canon_path, ws_root, false)
    }

    pub fn get_full_entry(
        &self,
        canon_path: &Path,
        ws_root: Option<&Path>,
    ) -> Result<Arc<CachedFile>, String> {
        self.get_entry(canon_path, ws_root, true)
    }

    fn get_entry(
        &self,
        canon_path: &Path,
        ws_root: Option<&Path>,
        require_content: bool,
    ) -> Result<Arc<CachedFile>, String> {
        if is_sensitive_path_with_ws(canon_path, ws_root, false) {
            return Err(format!("refusing sensitive path: {}", canon_path.display()));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let key = norm_key_from_canon(canon_path);
        let shard = &self.shards[shard_idx_for(&key)];
        let timeout = || format!("timed out loading a stable version of {}", canon_path.display());
        let cached = |stamp: FileMetaStamp| {
            let entries = shard.read().map_err(|_| "shard lock poisoned".to_string())?;
            let entry = entries.get(key.as_str());
            let hit = entry
                .filter(|entry| stamp.matches(entry) && (!require_content || entry.has_body()));
            if let Some(hit) = hit {
                hit.last_access.store(self.next_tick(), Ordering::Relaxed);
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            Ok::<_, String>((hit.is_some(), entry.cloned()))
        };

        loop {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            let stamp = file_stat(canon_path)?;
            if stamp.size_bytes > MAX_SINGLE_FILE_CACHE_BYTES as u64 {
                return Err(format!(
                    "file exceeds 1 MiB full-cache limit ({} bytes): {}; request a line slice path:start-end",
                    stamp.size_bytes,
                    canon_path.display()
                ));
            }
            let (hit, previous) = cached(stamp)?;
            if hit {
                if let Some(entry) = previous {
                    return Ok(entry);
                }
            }

            let mut loads = self
                .inflight
                .lock()
                .map_err(|_| "inflight lock poisoned".to_string())?;
            if let Some(wait_slot) = loads.get(key.as_str()).cloned() {
                drop(loads);
                let done = wait_slot
                    .done
                    .lock()
                    .map_err(|_| "inflight slot poisoned".to_string())?;
                let (done, _) = wait_slot
                    .cv
                    .wait_timeout_while(
                        done,
                        deadline.saturating_duration_since(Instant::now()),
                        |done| !*done,
                    )
                    .map_err(|_| "inflight slot poisoned".to_string())?;
                if !*done {
                    return Err(timeout());
                }
                continue;
            }

            // A loader can publish and leave the in-flight table between the
            // first cache lookup and acquisition of the load lock.
            let (hit, previous) = cached(stamp)?;
            if hit {
                if let Some(entry) = previous {
                    return Ok(entry);
                }
            }
            let (path_id, key_arc) = match &previous {
                Some(entry) => (entry.path_id, Arc::clone(&entry.norm_path)),
                None => self.intern_path(&key),
            };
            let slot = Arc::new(InflightSlot {
                done: Mutex::new(false),
                cv: Condvar::new(),
            });
            loads.insert(Arc::clone(&key_arc), Arc::clone(&slot));
            let _loader = InflightGuard {
                map: &self.inflight,
                key: Arc::clone(&key_arc),
                slot,
            };
            drop(loads);

            if let Some(entry) = self.load_full_entry(
                canon_path,
                ws_root,
                stamp,
                (path_id, key_arc),
                previous.as_deref(),
            )? {
                return Ok(entry);
            }
        }
    }

    fn load_full_entry(
        &self,
        canon_path: &Path,
        ws_root: Option<&Path>,
        st: FileMetaStamp,
        (path_id, key_arc): (PathId, Arc<str>),
        previous: Option<&CachedFile>,
    ) -> Result<Option<Arc<CachedFile>>, String> {
        let active_counter = self.current_ram_counter();
        let read_error = |error| format!("read {}: {error}", canon_path.display());
        let file = File::open(canon_path).map_err(read_error)?;
        if stamp_metadata(&file.metadata().map_err(read_error)?, canon_path)? != st {
            return Ok(None);
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        let mut raw_bytes = Vec::with_capacity(st.size_bytes as usize);
        file.take(MAX_SINGLE_FILE_CACHE_BYTES as u64 + 1)
            .read_to_end(&mut raw_bytes)
            .map_err(read_error)?;
        if raw_bytes.len() as u64 != st.size_bytes {
            return Ok(None);
        }
        if file_stat(canon_path)? != st {
            return Ok(None);
        }

        let content_hash64 = fast_hash64(&raw_bytes);
        let dedup_key = BodyDedupKey {
            content_hash64,
            size_bytes: st.size_bytes as u32,
            parser_kind: file_parser_kind(canon_path),
            clean_lang: clean_lang_tag(canon_path),
        };

        let existing_body = self
            .body_dedup
            .read()
            .ok()
            .and_then(|map| map.get(&dedup_key).and_then(Weak::upgrade))
            .filter(|cand| {
                Arc::ptr_eq(&cand.ram_counter, &active_counter)
                    && cand.content.as_bytes() == raw_bytes.as_slice()
            });

        let body = if let Some(shared) = existing_body {
            shared
        } else {
            let scanned = scan_source_bytes(raw_bytes).map_err(|err| match err {
                ScanError::Binary => format!("binary file rejected: {}", canon_path.display()),
                ScanError::NonUtf8 => format!("non-UTF8 text file: {}", canon_path.display()),
            })?;
            let symbols: Arc<[SymbolSpan]> = match previous {
                Some(prev)
                    if prev.content_hash64 == content_hash64
                        && !prev.symbols.is_empty()
                        && prev.symbols.iter().all(|s| !s.signature.is_empty()) =>
                {
                    Arc::clone(&prev.symbols)
                }
                _ => Arc::from(extract_symbols(
                    canon_path,
                    &scanned.text,
                    &scanned.line_offsets,
                )),
            };
            let content_len = scanned.text.len();
            let charge_bytes =
                (content_len + (scanned.line_offsets.len() << 2)).min(u32::MAX as usize) as u32;
            let content_bloom = trigram_bloom128_ascii_lower(scanned.text.as_bytes());
            let built = Arc::new(ParsedBody::new(
                Arc::from(scanned.text),
                scanned.line_offsets,
                symbols,
                content_bloom,
                charge_bytes,
                scanned.line_count,
                st.size_bytes as u32,
                content_hash64,
                Arc::clone(&active_counter),
            ));
            if let Ok(mut map) = self.body_dedup.write() {
                if let Some(existing) = map.get(&dedup_key).and_then(Weak::upgrade).filter(|cand| {
                    Arc::ptr_eq(&cand.ram_counter, &active_counter)
                        && cand.content.as_bytes() == built.content.as_bytes()
                }) {
                    existing
                } else {
                    if map.len() >= MAX_BODY_DEDUP_ENTRIES && !map.contains_key(&dedup_key) {
                        map.retain(|_, w| w.strong_count() > 0);
                        if map.len() >= MAX_BODY_DEDUP_ENTRIES {
                            map.clear();
                        }
                    }
                    map.insert(dedup_key, Arc::downgrade(&built));
                    built
                }
            } else {
                built
            }
        };

        if body.cache_owners.load(Ordering::Acquire) == 0 {
            let incoming = (body.base_charge as usize)
                .saturating_add(body.cleaned_charge.load(Ordering::Acquire) as usize);
            self.evict_if_needed(incoming);
        }

        let rel_path: Box<str> = match previous {
            Some(prev) if !prev.rel_path.is_empty() => prev.rel_path.clone(),
            _ => display_workspace_path(canon_path, ws_root).into_boxed_str(),
        };

        let new_entry = Arc::new(CachedFile {
            norm_path: Arc::clone(&key_arc),
            rel_path,
            mtime_ns: st.mtime_ns,
            ctime_ns: st.ctime_ns,
            ino: st.ino,
            content_hash64,
            path_id,
            size_bytes: st.size_bytes as u32,
            line_count: body.line_count,
            symbols: Arc::clone(&body.symbols),
            body: Some(Arc::clone(&body)),
            last_access: AtomicU64::new(self.next_tick()),
        });

        if file_stat(canon_path)? != st {
            return Ok(None);
        }
        let replaced_old = {
            let mut guard = self.shards[shard_idx_for(&key_arc)]
                .write()
                .map_err(|_| "shard write poisoned".to_string())?;
            if !Arc::ptr_eq(&body.ram_counter, &self.current_ram_counter()) {
                return Ok(Some(new_entry));
            }
            body.attach_cache_owner();
            let old = guard.insert(key_arc, Arc::clone(&new_entry));
            if let Some(ref old_entry) = old {
                if let Some(old_body) = old_entry.body.as_deref() {
                    old_body.detach_cache_owner();
                }
            }
            self.dirty_since_save.store(true, Ordering::Relaxed);
            old
        };
        if let Some(old) = replaced_old {
            if old.content_hash64 != content_hash64 {
                self.bump_mutation_epoch();
                if let Some(content) = old.content_arc() {
                    self.snapshot_delta(old.path_id, old.content_hash64, content);
                }
            }
        }

        Ok(Some(new_entry))
    }

    pub fn stream_large_slice(
        path: &Path,
        start_line: usize,
        end_line: usize,
        max_bytes: usize,
    ) -> Result<(String, usize, usize), String> {
        if is_sensitive_path(path) {
            return Err(format!("refusing sensitive path: {}", path.display()));
        }
        let f = File::open(path).map_err(|e| format!("{}: {}", path.display(), e))?;
        let mut reader = BufReader::new(f);
        let mut buf = Vec::with_capacity(256);
        let mut line_no = 0usize;
        let mut out = String::with_capacity(max_bytes.min(16_384));
        let s = start_line.max(1);
        let e = end_line.max(s);
        let mut actual_end = s;

        loop {
            buf.clear();
            let n = reader
                .read_until(b'\n', &mut buf)
                .map_err(|err| err.to_string())?;
            if n == 0 {
                break;
            }
            if line_no == 0 && buf.iter().take(4096).any(|&b| b == 0) {
                return Err(format!("binary file rejected: {}", path.display()));
            }
            line_no += 1;
            if line_no < s {
                continue;
            }
            if line_no > e {
                break;
            }
            let line_str = String::from_utf8_lossy(&buf);
            let trimmed_nl = line_str.trim_end_matches(&['\r', '\n'][..]);
            if out.len() + trimmed_nl.len() + 14 > max_bytes {
                out.push_str("... [truncated at max_bytes]\n");
                break;
            }
            push_usize(&mut out, line_no);
            out.push_str(": ");
            out.push_str(trimmed_nl);
            out.push('\n');
            actual_end = line_no;
        }
        Ok((out, s, actual_end))
    }

    pub fn format_outline_compact(entry: &CachedFile, max_symbols: usize) -> String {
        let mut out = String::with_capacity(128 + max_symbols * 28);
        out.push_str(&entry.rel_path);
        out.push_str(" (");
        push_u32(&mut out, entry.line_count);
        if entry.symbols.is_empty() {
            out.push_str("L, ");
            push_u32(&mut out, entry.size_bytes);
            out.push_str("B): [no top-level symbols]");
            return out;
        }
        out.push_str("L): ");
        for (i, sym) in entry.symbols.iter().take(max_symbols).enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(sym.kind.as_str());
            out.push(' ');
            out.push_str(&sym.name);
            out.push_str(" [L");
            push_u32(&mut out, sym.start_line);
            out.push_str("-L");
            push_u32(&mut out, sym.end_line);
            out.push(']');
        }
        if entry.symbols.len() > max_symbols {
            out.push_str(", +");
            push_usize(&mut out, entry.symbols.len() - max_symbols);
            out.push_str(" more");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_rechecks_the_file_after_another_loader_finishes() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-cache-wait-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("fixture.cpp");
        fs::write(&path, "int cached;\n").unwrap();
        let store = RamStore::new(dir.join("snapshot"));
        let cached = store.get_full_entry(&path, Some(&dir)).unwrap();
        let key = Arc::clone(&cached.norm_path);
        let slot = Arc::new(InflightSlot {
            done: Mutex::new(false),
            cv: Condvar::new(),
        });
        store
            .inflight
            .lock()
            .unwrap()
            .insert(Arc::clone(&key), Arc::clone(&slot));
        let owner = InflightGuard {
            map: &store.inflight,
            key,
            slot: Arc::clone(&slot),
        };
        fs::write(&path, "int edited_once;\n").unwrap();

        std::thread::scope(|scope| {
            let read = scope.spawn(|| store.get_full_entry(&path, Some(&dir)).unwrap());
            let deadline = Instant::now() + Duration::from_secs(3);
            while Arc::strong_count(&slot) < 4 && Instant::now() < deadline {
                std::thread::yield_now();
            }
            let joined_load = Arc::strong_count(&slot) >= 4;
            fs::write(&path, "int edited_a_second_time;\n").unwrap();
            drop(owner);
            assert!(joined_load, "reader did not enter the existing load");
            let loaded = read.join().unwrap();
            assert_eq!(loaded.content(), Some("int edited_a_second_time;\n"));
            assert_eq!(cached.content(), Some("int cached;\n"));
        });
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_changed_file_stamp_refuses_publication() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-cache-stamp-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("fixture.cpp");
        fs::write(&path, "int before;\n").unwrap();
        let store = RamStore::new(dir.join("snapshot"));
        let old_stamp = file_stat(&path).unwrap();
        let key = store.intern_path(&norm_key_from_canon(&path));
        fs::write(&path, "int after_first_write;\n").unwrap();
        assert!(store
            .load_full_entry(&path, Some(&dir), old_stamp, key, None)
            .unwrap()
            .is_none());
        assert_eq!(store.cached_file_count(), 0);
        assert_eq!(
            store.get_outline_entry(&path, Some(&dir)).unwrap().content(),
            Some("int after_first_write;\n")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shorthand_root_resolves_nested_dirs_stem_tokens_and_compact_segments() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-root-resolve-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(dir.join("graph/resolver")).unwrap();
        let resolve = dir.join("graph/resolver/resolve_graph.py");
        let scanner = dir.join("graph/resolver/manifest_scanner.py");
        fs::write(
            &resolve,
            "def resolve_graph():\n    return scan_manifests()\n",
        )
        .unwrap();
        fs::write(&scanner, "def scan_manifests():\n    return []\n").unwrap();

        let store = RamStore::new(dir.join("snapshot"));
        // Tier 3: nested directory segment `resolver`
        let by_dir = store.find_workspace_paths("resolver", &dir, 16);
        assert_eq!(by_dir.len(), 2);
        // Tier 4a: stem token `manifest`
        let by_token = store.find_workspace_paths("manifest", &dir, 16);
        assert_eq!(by_token.len(), 1);
        assert!(by_token[0].ends_with("manifest_scanner.py"));
        // Tier 4b: compact consecutive directory segments `graphresolver`
        let by_compact = store.find_workspace_paths("graphresolver", &dir, 16);
        assert_eq!(by_compact.len(), 2);
        // Generic stem still refused on fallback
        assert!(store.find_workspace_paths("main", &dir, 16).is_empty());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn find_workspace_dirs_resolves_ancestor_suffix_and_guards_generic_single() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-dir-resolve-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(dir.join("src/src/Exchanges/Binance/Spot")).unwrap();
        fs::create_dir_all(dir.join("src/src/Exchanges/Binance/Futures")).unwrap();
        fs::create_dir_all(dir.join("src/src/Core/Math")).unwrap();
        fs::create_dir_all(dir.join("src/src/Core/FastMath")).unwrap();
        fs::create_dir_all(dir.join("a/config")).unwrap();
        fs::create_dir_all(dir.join("b/config")).unwrap();
        fs::create_dir_all(dir.join("c/config")).unwrap();

        fs::write(
            dir.join("src/src/Exchanges/Binance/Spot/Bbo.hpp"),
            "struct Bbo {};\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/src/Exchanges/Binance/Futures/Trades.hpp"),
            "struct Trades {};\n",
        )
        .unwrap();
        fs::write(dir.join("src/src/Core/Math/FastDiv.hpp"), "struct FastDiv {};\n").unwrap();
        fs::write(dir.join("src/src/Core/FastMath/Other.hpp"), "struct Other {};\n").unwrap();
        fs::write(dir.join("a/config/x.toml"), "[a]\n").unwrap();
        fs::write(dir.join("b/config/y.toml"), "[b]\n").unwrap();
        fs::write(dir.join("c/config/z.toml"), "[c]\n").unwrap();

        let store = RamStore::new(dir.join("snapshot"));
        let binance = store.find_workspace_dirs("Exchanges/Binance", &dir, 8);
        assert_eq!(binance.len(), 1);
        assert!(binance[0].ends_with("src/src/Exchanges/Binance"));

        let binance_ci = store.find_workspace_dirs("./exchanges\\binance/**", &dir, 8);
        assert_eq!(binance_ci.len(), 1);
        assert!(binance_ci[0].ends_with("src/src/Exchanges/Binance"));

        let math = store.find_workspace_dirs("Math", &dir, 8);
        assert_eq!(math.len(), 1);
        assert!(math[0].ends_with("src/src/Core/Math"));

        // Generic single-segment directory ambiguous across >2 parents returns empty
        assert!(store.find_workspace_dirs("config", &dir, 8).is_empty());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn parsed_body_dedup_shares_arc_separates_parser_kinds_evicts_and_clears_safely() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-body-dedup-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(dir.join("wt1")).unwrap();
        fs::create_dir_all(dir.join("wt2")).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();

        let code = "pub fn shared_fn(x: u64) -> u64 {\n    x + 42\n}\n";
        let p1 = dir.join("wt1/lib.rs");
        let p2 = dir.join("wt2/lib.rs");
        fs::write(&p1, code).unwrap();
        fs::write(&p2, code).unwrap();

        // Identical bytes under CMakeLists.txt vs notes.txt MUST NOT collide in dedup.
        let cmake_txt = "add_library(demo STATIC a.cpp)\n";
        let cm = dir.join("wt1/CMakeLists.txt");
        let notes = dir.join("wt1/notes.txt");
        fs::write(&cm, cmake_txt).unwrap();
        fs::write(&notes, cmake_txt).unwrap();

        let mut store = RamStore::new(dir.join("snap.bin"));
        let e1 = store.get_full_entry(&p1, Some(&dir)).unwrap();
        let ram_one = store.used_ram_bytes();
        assert!(ram_one > 0);
        let e2 = store.get_full_entry(&p2, Some(&dir)).unwrap();
        assert_eq!(store.used_ram_bytes(), ram_one, "identical files must charge 1x RAM");
        assert!(Arc::ptr_eq(
            e1.body.as_ref().unwrap(),
            e2.body.as_ref().unwrap()
        ));
        assert_eq!(e1.body.as_ref().unwrap().cache_owners.load(Ordering::Acquire), 2);

        // Lazy cleaned_code charges once while cache_owners == 2
        let _ = e1.cleaned_code_for_ext("rs", &store).unwrap();
        let ram_with_clean = store.used_ram_bytes();
        assert!(ram_with_clean > ram_one);
        let _ = e2.cleaned_code_for_ext("rs", &store).unwrap();
        assert_eq!(store.used_ram_bytes(), ram_with_clean);

        // Evicting 1 of 2 keeps 1x charge; evicting 2 of 2 releases to 0
        store.invalidate_path(&p1);
        assert_eq!(store.used_ram_bytes(), ram_with_clean);
        assert_eq!(e1.body.as_ref().unwrap().cache_owners.load(Ordering::Acquire), 1);
        store.invalidate_path(&p2);
        assert_eq!(store.used_ram_bytes(), 0);
        assert_eq!(e1.body.as_ref().unwrap().cache_owners.load(Ordering::Acquire), 0);

        // CMakeLists.txt vs notes.txt must have distinct ParsedBody & symbols
        let e_cm = store.get_full_entry(&cm, Some(&dir)).unwrap();
        let e_notes = store.get_full_entry(&notes, Some(&dir)).unwrap();
        assert!(!Arc::ptr_eq(
            e_cm.body.as_ref().unwrap(),
            e_notes.body.as_ref().unwrap()
        ));
        assert!(!e_cm.symbols.is_empty());
        assert!(e_notes.symbols.is_empty());

        // Forced eviction path strips bodies and releases shared charge cleanly
        store.clear_all();
        let live_before_clear = store.get_full_entry(&p1, Some(&dir)).unwrap();
        let _live2 = store.get_full_entry(&p2, Some(&dir)).unwrap();
        assert!(store.used_ram_bytes() > 0);
        store.max_ram_bytes = 1;
        store.evict_if_needed(1);
        assert_eq!(store.used_ram_bytes(), 0);
        // clear_all while live Arc<CachedFile> exists causes zero underflow
        store.max_ram_bytes = 1 << 20;
        let held = store.get_full_entry(&p1, Some(&dir)).unwrap();
        assert!(store.used_ram_bytes() > 0);
        store.clear_all();
        assert_eq!(store.used_ram_bytes(), 0);
        assert_eq!(live_before_clear.content(), Some(code));
        assert_eq!(held.content(), Some(code));
        drop(held);
        assert_eq!(store.used_ram_bytes(), 0);

        // External disk mutation bumps mutation_epoch on load_full_entry
        let ep0 = store.mutation_epoch();
        let _ = store.get_full_entry(&p1, Some(&dir)).unwrap();
        fs::write(&p1, "pub fn shared_fn(x: u64) -> u64 {\n    x + 99\n}\n").unwrap();
        let _ = store.get_full_entry(&p1, Some(&dir)).unwrap();
        assert!(store.mutation_epoch() > ep0);

        fs::remove_dir_all(dir).unwrap();
    }
}
