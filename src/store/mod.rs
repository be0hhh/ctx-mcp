//! Sharded source cache, per-file load coordination, workspace indexing,
//! per-session read state, and metadata-only reboot snapshots.

mod index;
mod paths;
mod session;
mod snapshot;

pub use index::MissingResolution;
pub use paths::{
    default_snapshot_path, display_workspace_path, is_multimodal_or_binary_ext,
    norm_key_from_canon, norm_path, resolve_input_path, restore_caller_path_style, runtime_dir,
    should_skip_dir,
};
pub use snapshot::verify_snapshot_metadata_only;

use crate::base::security::{is_sensitive_path, is_sensitive_path_lexical};
use crate::base::simd::{
    fast_hash64, line_slice_at, push_u32, push_usize, scan_source_bytes, CachePadded, FastHashMap,
    ScanError,
};
use crate::parser::{extract_symbols, SymbolSpan};
use index::WorkspaceIndexCache;
use session::{DedupRing, SessionShardMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_SINGLE_FILE_CACHE_BYTES: usize = 1_048_576; // 1 MiB full-file read/cache ceiling
pub const HARD_RAM_CAP_BYTES: usize = 4usize << 30; // 4 GiB ceiling
pub const SNAPSHOT_DISK_CAP_BYTES: usize = 64 << 20; // 64 MiB max metadata-only snapshot
const SHARD_COUNT: usize = 64;
const SHARD_MASK: usize = SHARD_COUNT - 1;

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
    pub ram_charge: u32,
    pub line_offsets: Box<[u32]>,
    pub symbols: Arc<[SymbolSpan]>,
    pub content: Option<Arc<str>>,
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
            ram_charge: 0,
            line_offsets: Box::new([]),
            symbols: Arc::clone(&self.symbols),
            content: None,
            last_access: AtomicU64::new(self.last_access.load(Ordering::Relaxed)),
        }
    }

    #[inline]
    pub fn line_slice(&self, line_1based: u32) -> &str {
        match self.content.as_deref() {
            Some(text) => line_slice_at(text, &self.line_offsets, line_1based),
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
    pub used_ram_bytes: CachePadded<AtomicUsize>,
    pub access_clock: CachePadded<AtomicU64>,
    pub cache_hits: CachePadded<AtomicU64>,
    pub cache_misses: CachePadded<AtomicU64>,
    pub dirty_since_save: AtomicBool,
    pub last_save_ms: AtomicU64,
    paths: RwLock<PathInterner>,
    shards: Box<[CachePadded<RwLock<FileShardMap>>; SHARD_COUNT]>,
    inflight: Mutex<FastHashMap<Arc<str>, Arc<InflightSlot>>>,
    sessions: Box<[CachePadded<Mutex<SessionShardMap>>; SHARD_COUNT]>,
    dedup_ring: Mutex<DedupRing>,
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
    if let Ok(val) = std::env::var("AGENT_CTX_MAX_RAM_MB") {
        if let Ok(mb) = val.trim().parse::<usize>() {
            if mb >= 16 {
                return (mb << 20).min(HARD_RAM_CAP_BYTES);
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    let trimmed = rest.trim_start();
                    let digits = trimmed.bytes().take_while(|b| b.is_ascii_digit()).count();
                    if let Ok(kb) = trimmed[..digits].parse::<usize>() {
                        let half = (kb >> 1) << 10;
                        return half.clamp(128 << 20, HARD_RAM_CAP_BYTES);
                    }
                }
            }
        }
    }
    HARD_RAM_CAP_BYTES
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
            used_ram_bytes: CachePadded::new(AtomicUsize::new(0)),
            access_clock: CachePadded::new(AtomicU64::new(1)),
            cache_hits: CachePadded::new(AtomicU64::new(0)),
            cache_misses: CachePadded::new(AtomicU64::new(0)),
            dirty_since_save: AtomicBool::new(false),
            last_save_ms: AtomicU64::new(now_ms()),
            paths: RwLock::new(PathInterner::default()),
            shards,
            inflight: Mutex::new(FastHashMap::default()),
            sessions,
            dedup_ring: Mutex::new(DedupRing::default()),
            ws_cache: Arc::new(WorkspaceIndexCache::default()),
            snapshot_path,
        };
        let _ = store.load_snapshot();
        store
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

    fn sub_ram_bytes(&self, freed: usize) {
        let mut cur = self.used_ram_bytes.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(freed);
            match self.used_ram_bytes.compare_exchange_weak(
                cur,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
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
        for sh in self.shards.iter() {
            if let Ok(mut g) = sh.write() {
                g.clear();
            }
        }
        for ss in self.sessions.iter() {
            if let Ok(mut g) = ss.lock() {
                g.clear();
            }
        }
        if let Ok(mut wi) = self.ws_cache.indices.write() {
            wi.clear();
        }
        self.used_ram_bytes.store(0, Ordering::Relaxed);
        let _ = fs::remove_file(&self.snapshot_path);
    }

    fn evict_if_needed(&self, incoming_bytes: usize) {
        if self
            .used_ram_bytes
            .load(Ordering::Relaxed)
            .saturating_add(incoming_bytes)
            <= self.max_ram_bytes
        {
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
                    if v.content.is_some() && v.ram_charge > 0 {
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
            if self.used_ram_bytes.load(Ordering::Relaxed) <= target {
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
                if let Some(existing) = guard.get(&key) {
                    if existing.content.is_some() && existing.ram_charge > 0 {
                        let freed = existing.ram_charge as usize;
                        let stripped = Arc::new(existing.without_body());
                        guard.insert(key, stripped);
                        self.sub_ram_bytes(freed);
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
                if old.content.is_some() && old.ram_charge > 0 {
                    self.sub_ram_bytes(old.ram_charge as usize);
                }
                self.dirty_since_save.store(true, Ordering::Relaxed);
            }
        }
        self.invalidate_workspace_indices();
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
        if is_sensitive_path_lexical(canon_path) {
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
                .filter(|entry| stamp.matches(entry) && (!require_content || entry.content.is_some()));
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
                return Ok(previous.expect("cache hit has an entry"));
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
                return Ok(previous.expect("cache hit has an entry"));
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
        let scanned = scan_source_bytes(raw_bytes);
        if file_stat(canon_path)? != st {
            return Ok(None);
        }
        let scanned = scanned.map_err(|err| match err {
            ScanError::Binary => format!("binary file rejected: {}", canon_path.display()),
            ScanError::NonUtf8 => format!("non-UTF8 text file: {}", canon_path.display()),
        })?;

        let content_hash64 = fast_hash64(scanned.text.as_bytes());
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
        let charge_bytes = content_len + (scanned.line_offsets.len() << 2);
        self.evict_if_needed(charge_bytes);

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
            line_count: scanned.line_count,
            ram_charge: charge_bytes as u32,
            line_offsets: scanned.line_offsets,
            symbols,
            content: Some(Arc::from(scanned.text)),
            last_access: AtomicU64::new(self.next_tick()),
        });

        if file_stat(canon_path)? != st {
            return Ok(None);
        }
        {
            let mut guard = self.shards[shard_idx_for(&key_arc)]
                .write()
                .map_err(|_| "shard write poisoned".to_string())?;
            if let Some(old) = guard.insert(key_arc, Arc::clone(&new_entry)) {
                if old.content.is_some() && old.ram_charge > 0 {
                    self.sub_ram_bytes(old.ram_charge as usize);
                }
            }
            self.used_ram_bytes
                .fetch_add(charge_bytes, Ordering::Relaxed);
            self.dirty_since_save.store(true, Ordering::Relaxed);
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
            assert_eq!(
                loaded.content.as_deref(),
                Some("int edited_a_second_time;\n")
            );
            assert_eq!(cached.content.as_deref(), Some("int cached;\n"));
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
            store
                .get_outline_entry(&path, Some(&dir))
                .unwrap()
                .content
                .as_deref(),
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
}
