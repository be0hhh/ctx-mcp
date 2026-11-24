//! Sharded concurrent RAM store (`64` 64B-cache-padded `RwLock` file shards +
//! RAII `InflightGuard` singleflight disk loader + `64` 64B-cache-padded `Mutex`
//! agent-session shards + `PathId(u32)` interning + `32B` POD `ReadSpan` +
//! arena-backed `WorkspaceFiles` with 64-bit trigram Bloom filter +
//! `0600` metadata-only `ACTXSNP2` reboot snapshot).

use crate::parser::{extract_symbols, SymbolKind, SymbolSpan};
use crate::security::{
    ensure_private_dir, find_superproject_root, is_sensitive_path, write_private_0600,
};
use crate::simd::{
    fast_hash64, fast_hash64_ascii_lower, line_slice_at, push_u32, push_usize, scan_source_bytes,
    trigram_bloom64_ascii_lower, CachePadded, ScanError,
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_SINGLE_FILE_CACHE_BYTES: usize = 1_048_576; // 1 MiB full-file read/cache ceiling
pub const HARD_RAM_CAP_BYTES: usize = 4usize << 30; // 4 GiB ceiling
pub const SNAPSHOT_DISK_CAP_BYTES: usize = 64 << 20; // 64 MiB max metadata-only snapshot
pub const SESSION_WINDOW_STEPS: u64 = 30;
const SHARD_COUNT: usize = 64;
const SHARD_MASK: usize = SHARD_COUNT - 1;
const MAX_SESSIONS_PER_SHARD: usize = 32; // 2,048 concurrent sessions across 64 shards
const WORKSPACE_INDEX_TTL_MS: u64 = 5_000;
const MAX_INDEXED_WORKSPACE_FILES: usize = 25_000;
const DEDUP_RING_SLOTS: usize = 2048;
const DEDUP_RING_MASK: usize = DEDUP_RING_SLOTS - 1;

pub const SNAPSHOT_MAGIC: &[u8; 8] = b"ACTXSNP2";
pub const SNAPSHOT_FORMAT_TAG: u32 = 3;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PathId(pub u32);

#[derive(Default)]
struct PathInterner {
    to_id: HashMap<Arc<str>, PathId>,
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
    pub fnv64: u64,
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
            fnv64: self.fnv64,
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

/// Exact 32-byte POD read span (`2` per 64B cache line, `Copy`, `0` heap allocations).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReadSpan {
    pub fnv64: u64,
    pub step_seq: u64,
    pub path_id: PathId,
    pub start_line: u32,
    pub end_line: u32,
    pub strikes: u8,
    pub _pad: [u8; 3],
}

const _: [(); 32] = [(); std::mem::size_of::<ReadSpan>()];

#[derive(Clone, Debug, Default)]
pub struct SessionState {
    pub step_seq: u64,
    pub last_step_ms: u64,
    pub reads: Vec<ReadSpan>,
    pub startup_injected: bool,
}

#[derive(Clone, Debug)]
pub struct DuplicateHit {
    pub covered_start: usize,
    pub covered_end: usize,
    pub total_lines: usize,
    pub unread_ranges: Vec<(usize, usize)>,
    pub outline_summary: String,
    pub rel_path: String,
}

#[derive(Clone, Debug)]
pub enum MissingResolution {
    Unique(PathBuf),
    Ambiguous(Vec<PathBuf>),
    NotFound,
}

struct InflightSlot {
    done: Mutex<bool>,
    cv: Condvar,
}

struct InflightGuard<'a> {
    map: &'a Mutex<HashMap<Arc<str>, Arc<InflightSlot>>>,
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

/// Exact 24-byte arena-indexed file entry (`0` per-file `String` or `PathBuf` allocations).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IndexedFile {
    pub name_hash: u64,
    pub trigram_bloom: u64,
    pub rel_off: u32,
    pub rel_len: u16,
    pub name_off: u16,
}

const _: [(); 24] = [(); std::mem::size_of::<IndexedFile>()];

pub struct WorkspaceFiles {
    pub built_ms: u64,
    pub root: PathBuf,
    pub arena: Box<[u8]>,
    pub entries: Box<[IndexedFile]>,
    pub by_name_hash: HashMap<u64, Box<[u32]>>,
    pub by_stem_hash: HashMap<u64, Box<[u32]>>,
}

impl WorkspaceFiles {
    #[inline]
    pub fn rel_str(&self, item: &IndexedFile) -> &str {
        let s = item.rel_off as usize;
        let e = s + item.rel_len as usize;
        // SAFETY: Only valid UTF-8 relative paths are pushed into `arena`.
        unsafe { std::str::from_utf8_unchecked(&self.arena[s..e]) }
    }

    #[inline]
    pub fn file_name(&self, item: &IndexedFile) -> &str {
        let s = item.rel_off as usize + item.name_off as usize;
        let e = item.rel_off as usize + item.rel_len as usize;
        unsafe { std::str::from_utf8_unchecked(&self.arena[s..e]) }
    }

    #[inline]
    pub fn file_stem(&self, item: &IndexedFile) -> &str {
        let fname = self.file_name(item);
        match fname.rfind('.') {
            Some(dot) if dot > 0 => &fname[..dot],
            _ => fname,
        }
    }

    #[inline]
    pub fn abs_path(&self, item: &IndexedFile) -> PathBuf {
        self.root.join(self.rel_str(item))
    }
}

#[derive(Default)]
struct WorkspaceIndexCache {
    indices: RwLock<HashMap<PathBuf, Arc<WorkspaceFiles>>>,
    prewarming: Mutex<Vec<PathBuf>>,
}

struct DedupRing {
    slots: Box<[(u64, u64); DEDUP_RING_SLOTS]>,
    cursor: usize,
}

impl Default for DedupRing {
    fn default() -> Self {
        Self {
            slots: Box::new([(0u64, 0u64); DEDUP_RING_SLOTS]),
            cursor: 0,
        }
    }
}

type FileShardMap = HashMap<Arc<str>, Arc<CachedFile>>;
type SessionShardMap = HashMap<Box<str>, SessionState>;

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
    inflight: Mutex<HashMap<Arc<str>, Arc<InflightSlot>>>,
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

pub fn runtime_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("AGENT_CTX_RUNTIME_DIR") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    #[cfg(unix)]
    {
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            if !xdg.trim().is_empty() && Path::new(&xdg).is_dir() {
                return PathBuf::from(xdg).join("agent-ctx");
            }
        }
        let uid = unix_uid_string();
        #[cfg(target_os = "linux")]
        if !uid.is_empty() && uid.bytes().all(|c| c.is_ascii_digit()) {
            let user_run = Path::new("/run/user").join(&uid);
            if user_run.is_dir() {
                return user_run.join("agent-ctx");
            }
        }
        let shm = Path::new("/dev/shm");
        if shm.is_dir() {
            return shm.join(format!("agent-ctx-{}", uid));
        }
        return std::env::temp_dir().join(format!("agent-ctx-{}", uid));
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.trim().is_empty() {
                return PathBuf::from(local).join("agent-ctx");
            }
        }
        std::env::temp_dir().join("agent-ctx")
    }
}

pub fn default_snapshot_path() -> PathBuf {
    if let Ok(custom) = std::env::var("AGENT_CTX_SNAPSHOT_PATH") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    #[cfg(unix)]
    {
        if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            if !xdg.trim().is_empty() {
                return PathBuf::from(xdg).join("agent-ctx").join("snapshot.bin");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.trim().is_empty() {
                return PathBuf::from(home)
                    .join(".cache")
                    .join("agent-ctx")
                    .join("snapshot.bin");
            }
        }
        std::env::temp_dir().join("agent-ctx-snapshot.bin")
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.trim().is_empty() {
                return PathBuf::from(local).join("agent-ctx").join("snapshot.bin");
            }
        }
        std::env::temp_dir().join("agent-ctx-snapshot.bin")
    }
}

#[cfg(unix)]
fn unix_uid_string() -> String {
    if let Ok(meta) = fs::metadata("/proc/self") {
        use std::os::unix::fs::MetadataExt;
        return meta.uid().to_string();
    }
    std::env::var("USER").unwrap_or_else(|_| "user".to_string())
}

pub fn norm_path(path: &Path) -> String {
    let resolved = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    norm_key_from_canon(&resolved)
}

pub fn norm_key_from_canon(canon: &Path) -> String {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut s = canon.to_string_lossy().into_owned();
    #[cfg(windows)]
    {
        if let Some(stripped) = s.strip_prefix("\\\\?\\") {
            s = stripped.to_string();
        }
        s = s.replace('\\', "/").to_ascii_lowercase();
    }
    s
}

/// Formats `path` as an exact forward-slash path relative to `ws_root` (or its detected
/// superproject `.git` root). Fast-paths already-canonical paths without redundant syscalls.
pub fn display_workspace_path(path: &Path, ws_root: Option<&Path>) -> String {
    if let Some(root) = ws_root {
        if let Ok(rel) = path.strip_prefix(root) {
            if !rel.as_os_str().is_empty() {
                let raw = rel.to_string_lossy();
                return if raw.contains('\\') {
                    raw.replace('\\', "/")
                } else {
                    raw.into_owned()
                };
            }
        }
    }

    let canon_p = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let root_opt = ws_root
        .map(|r| fs::canonicalize(r).unwrap_or_else(|_| r.to_path_buf()))
        .or_else(|| find_superproject_root(&canon_p));

    if let Some(root) = root_opt {
        if let Ok(rel) = canon_p.strip_prefix(&root) {
            let s = rel.to_string_lossy().replace('\\', "/");
            if !s.is_empty() {
                return s;
            }
        }
    }
    let s = canon_p.to_string_lossy().replace('\\', "/");
    #[cfg(windows)]
    if let Some(stripped) = s.strip_prefix("//?/") {
        return stripped.to_string();
    }
    s
}

/// Translates Windows UNC WSL paths (`\\wsl.localhost\<Distro>\...`, `\\wsl$\<Distro>\...`)
/// and mounted Windows drive paths (`C:\...` -> `/mnt/c/...`) into Unix paths when running
/// on Unix / WSL2 so Windows Desktop App MCP & hook payloads resolve natively in RAM.
pub fn translate_host_path_str(raw: &str) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        let trimmed = raw.trim().trim_matches('"').trim_matches('\'');
        let norm = trimmed.replace('\\', "/");
        for prefix in ["//wsl.localhost/", "//wsl$/"] {
            if norm.len() > prefix.len() && norm[..prefix.len()].eq_ignore_ascii_case(prefix) {
                let after = &norm[prefix.len()..];
                if let Some((_distro, rest)) = after.split_once('/') {
                    return Some(PathBuf::from(format!("/{}", rest.trim_start_matches('/'))));
                }
                return Some(PathBuf::from("/"));
            }
        }
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
        {
            let drive = (bytes[0] as char).to_ascii_lowercase();
            let mnt_drive = PathBuf::from(format!("/mnt/{}", drive));
            if mnt_drive.is_dir() {
                let tail = norm[3..].trim_start_matches('/');
                return Some(if tail.is_empty() {
                    mnt_drive
                } else {
                    mnt_drive.join(tail)
                });
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = raw;
    }
    None
}

/// Restores the caller's original Windows UNC or drive-letter path style when rewriting
/// a resolved Unix path back to a Windows Desktop App client over WSL2.
pub fn restore_caller_path_style(raw_original: &str, resolved: &Path) -> String {
    #[cfg(unix)]
    {
        let trimmed = raw_original.trim().trim_matches('"').trim_matches('\'');
        let use_backslash = trimmed.contains('\\');
        let norm = trimmed.replace('\\', "/");
        for prefix in ["//wsl.localhost/", "//wsl$/"] {
            if norm.len() > prefix.len() && norm[..prefix.len()].eq_ignore_ascii_case(prefix) {
                let raw_prefix = &trimmed[..prefix.len()];
                let after = &norm[prefix.len()..];
                let distro = after.split('/').next().unwrap_or("");
                if !distro.is_empty() {
                    let rel = resolved.to_string_lossy();
                    let sep = if use_backslash { '\\' } else { '/' };
                    let body = if use_backslash {
                        rel.trim_start_matches('/').replace('/', "\\")
                    } else {
                        rel.trim_start_matches('/').to_string()
                    };
                    let head = if use_backslash {
                        raw_prefix.replace('/', "\\")
                    } else {
                        raw_prefix.replace('\\', "/")
                    };
                    return if body.is_empty() {
                        format!("{}{}", head, distro)
                    } else {
                        format!("{}{}{}{}", head, distro, sep, body)
                    };
                }
            }
        }
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
        {
            let drive_char = bytes[0] as char;
            let mnt_prefix = format!("/mnt/{}", drive_char.to_ascii_lowercase());
            let res_str = resolved.to_string_lossy();
            if res_str == mnt_prefix || res_str.starts_with(&format!("{}/", mnt_prefix)) {
                let tail = res_str[mnt_prefix.len()..].trim_start_matches('/');
                let sep = if use_backslash { '\\' } else { '/' };
                let formatted_tail = if use_backslash {
                    tail.replace('/', "\\")
                } else {
                    tail.to_string()
                };
                return format!("{}:{}{}", drive_char, sep, formatted_tail);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = raw_original;
    }
    resolved.to_string_lossy().into_owned()
}

pub fn resolve_input_path(raw: &str, cwd: Option<&Path>) -> PathBuf {
    let trimmed = raw.trim().trim_matches('"').trim_matches('\'');
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    if let Some(translated) = translate_host_path_str(trimmed) {
        return translated;
    }
    let p = PathBuf::from(trimmed);
    if p.is_absolute() {
        p
    } else if let Some(base) = cwd {
        base.join(p)
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

pub fn is_multimodal_or_binary_ext(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    let mut buf = [0u8; 12];
    if ext.len() > buf.len() || !ext.is_ascii() {
        return false;
    }
    for (i, b) in ext.bytes().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    let low = unsafe { std::str::from_utf8_unchecked(&buf[..ext.len()]) };
    matches!(
        low,
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "bmp"
            | "ico"
            | "pdf"
            | "mp3"
            | "wav"
            | "ogg"
            | "mp4"
            | "mov"
            | "webm"
            | "zip"
            | "tar"
            | "gz"
            | "xz"
            | "zst"
            | "7z"
            | "o"
            | "a"
            | "so"
            | "dll"
            | "exe"
            | "dylib"
            | "wasm"
            | "sqlite"
            | "db"
            | "pb"
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileMetaStamp {
    pub mtime_ns: u64,
    pub ctime_ns: u64,
    pub ino: u64,
    pub size_bytes: u64,
}

pub fn file_stat(path: &Path) -> Result<FileMetaStamp, String> {
    let meta = fs::metadata(path).map_err(|e| format!("{}: {}", path.display(), e))?;
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

fn should_skip_index_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "__pycache__"
            | ".venv"
            | "venv"
            | ".cache"
            | ".serena"
            | "dist"
            | ".next"
    ) || name.starts_with("build")
}

fn is_generic_basename(file_name: &str) -> bool {
    matches!(
        file_name.to_ascii_lowercase().as_str(),
        "cmakelists.txt"
            | "readme.md"
            | "agents.md"
            | "claude.md"
            | "gemini.md"
            | "skill.md"
            | "main.cpp"
            | "main.rs"
            | "mod.rs"
            | "lib.rs"
            | "index.ts"
            | "index.js"
            | "__init__.py"
            | "facts.hpp"
            | "cold.hpp"
            | "order.hpp"
            | "bbo.hpp"
            | "trades.hpp"
            | "depth.hpp"
            | "userdata.hpp"
            | "funding.hpp"
            | "pricelimit.hpp"
            | "restpublic.hpp"
            | "config.hpp"
            | "types.hpp"
    )
}

fn is_generic_stem(stem: &str) -> bool {
    matches!(
        stem.to_ascii_lowercase().as_str(),
        "cmakelists"
            | "readme"
            | "agents"
            | "claude"
            | "gemini"
            | "skill"
            | "main"
            | "mod"
            | "lib"
            | "index"
            | "__init__"
            | "facts"
            | "cold"
            | "order"
            | "bbo"
            | "trades"
            | "depth"
            | "userdata"
            | "funding"
            | "pricelimit"
            | "restpublic"
            | "config"
            | "types"
            | "manifest"
            | "startup"
            | "profile"
            | "secret"
    )
}

fn build_workspace_index(canon_root: &Path) -> WorkspaceFiles {
    let mut rel_list: Vec<String> = Vec::with_capacity(2048);
    walk_workspace_rel_paths(canon_root, canon_root, &mut rel_list);
    rel_list.sort_unstable();

    let total_bytes: usize = rel_list.iter().map(|s| s.len()).sum();
    let mut arena = Vec::with_capacity(total_bytes);
    let mut entries = Vec::with_capacity(rel_list.len());
    let mut temp_by_hash: HashMap<u64, Vec<u32>> = HashMap::with_capacity(rel_list.len());
    let mut temp_by_stem: HashMap<u64, Vec<u32>> = HashMap::with_capacity(rel_list.len());

    for rel in rel_list {
        if rel.len() > u16::MAX as usize || arena.len() + rel.len() > u32::MAX as usize {
            continue;
        }
        let rel_off = arena.len() as u32;
        let rel_len = rel.len() as u16;
        let name_off = rel.rfind('/').map_or(0, |idx| idx + 1) as u16;
        let fname = &rel[name_off as usize..];
        let stem = match fname.rfind('.') {
            Some(dot) if dot > 0 => &fname[..dot],
            _ => fname,
        };
        let name_hash = fast_hash64_ascii_lower(fname.as_bytes());
        let stem_hash = fast_hash64_ascii_lower(stem.as_bytes());
        let trigram_bloom = trigram_bloom64_ascii_lower(rel.as_bytes());
        arena.extend_from_slice(rel.as_bytes());
        let item_idx = entries.len() as u32;
        entries.push(IndexedFile {
            name_hash,
            trigram_bloom,
            rel_off,
            rel_len,
            name_off,
        });
        temp_by_hash.entry(name_hash).or_default().push(item_idx);
        temp_by_stem.entry(stem_hash).or_default().push(item_idx);
    }

    let by_name_hash = temp_by_hash
        .into_iter()
        .map(|(h, v)| (h, v.into_boxed_slice()))
        .collect();
    let by_stem_hash = temp_by_stem
        .into_iter()
        .map(|(h, v)| (h, v.into_boxed_slice()))
        .collect();

    WorkspaceFiles {
        built_ms: now_ms(),
        root: canon_root.to_path_buf(),
        arena: arena.into_boxed_slice(),
        entries: entries.into_boxed_slice(),
        by_name_hash,
        by_stem_hash,
    }
}

fn walk_workspace_rel_paths(root: &Path, dir: &Path, out: &mut Vec<String>) {
    if out.len() >= MAX_INDEXED_WORKSPACE_FILES {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        if out.len() >= MAX_INDEXED_WORKSPACE_FILES {
            break;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let dname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !should_skip_index_dir(dname) {
                walk_workspace_rel_paths(root, &path, out);
            }
        } else if meta.is_file() && !is_sensitive_path(&path) && !is_multimodal_or_binary_ext(&path) {
            if let Ok(rel) = path.strip_prefix(root) {
                if let Some(rel_str) = rel.to_str() {
                    let norm = if rel_str.contains('\\') {
                        rel_str.replace('\\', "/")
                    } else {
                        rel_str.to_string()
                    };
                    if !norm.is_empty() {
                        out.push(norm);
                    }
                }
            }
        }
    }
}

fn common_parent_suffix_score(a: &Path, b: &Path) -> usize {
    let mut a_comps = a.parent().into_iter().flat_map(Path::components).rev();
    let mut b_comps = b.parent().into_iter().flat_map(Path::components).rev();
    let mut score = 0usize;
    while let (Some(ca), Some(cb)) = (a_comps.next(), b_comps.next()) {
        if ca.as_os_str().eq_ignore_ascii_case(cb.as_os_str()) {
            score += 1;
        } else {
            break;
        }
    }
    score
}

impl RamStore {
    pub fn new(snapshot_path: PathBuf) -> Self {
        let shards = Box::new(std::array::from_fn(|_| {
            CachePadded::new(RwLock::new(HashMap::new()))
        }));
        let sessions = Box::new(std::array::from_fn(|_| {
            CachePadded::new(Mutex::new(HashMap::new()))
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
            inflight: Mutex::new(HashMap::new()),
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

    pub fn invalidate_workspace_indices(&self) {
        if let Ok(mut wi) = self.ws_cache.indices.write() {
            wi.clear();
        }
    }

    pub fn prewarm_workspace_index_async(&self, ws_root: &Path) {
        let canon_root = fs::canonicalize(ws_root).unwrap_or_else(|_| ws_root.to_path_buf());
        let now = now_ms();
        if self
            .ws_cache
            .indices
            .read()
            .ok()
            .and_then(|g| g.get(&canon_root).cloned())
            .is_some_and(|idx| now.saturating_sub(idx.built_ms) <= WORKSPACE_INDEX_TTL_MS)
        {
            return;
        }
        if let Ok(mut inflight) = self.ws_cache.prewarming.lock() {
            if inflight.contains(&canon_root) || inflight.len() >= 8 {
                return;
            }
            inflight.push(canon_root.clone());
        } else {
            return;
        }
        let cache = Arc::clone(&self.ws_cache);
        let _ = std::thread::Builder::new()
            .name("ctx-ws-prewarm".into())
            .spawn(move || {
                let built = Arc::new(build_workspace_index(&canon_root));
                if let Ok(mut w) = cache.indices.write() {
                    w.insert(canon_root.clone(), built);
                }
                if let Ok(mut inflight) = cache.prewarming.lock() {
                    inflight.retain(|p| p != &canon_root);
                }
            });
    }

    pub fn workspace_index(&self, ws_root: &Path) -> Arc<WorkspaceFiles> {
        let canon_root = fs::canonicalize(ws_root).unwrap_or_else(|_| ws_root.to_path_buf());
        let now = now_ms();
        if let Some(hit) = self
            .ws_cache
            .indices
            .read()
            .ok()
            .and_then(|g| g.get(&canon_root).cloned())
            .filter(|idx| now.saturating_sub(idx.built_ms) <= WORKSPACE_INDEX_TTL_MS)
        {
            return hit;
        }
        let built = Arc::new(build_workspace_index(&canon_root));
        if let Ok(mut w) = self.ws_cache.indices.write() {
            w.insert(canon_root, Arc::clone(&built));
        }
        built
    }

    /// Fast trigram-Bloom + hash-indexed lookup for shorthand file, bare module stem, or path suffix queries
    /// (e.g. `"PositionTable.hpp"`, `"StartupStreamBoundary"`, or `"Startup/Boundary/StartupStreamBoundary"`).
    pub fn find_workspace_paths(
        &self,
        raw_query: &str,
        ws_root: &Path,
        max_matches: usize,
    ) -> Vec<PathBuf> {
        let trimmed = raw_query
            .trim()
            .trim_start_matches("./")
            .trim_end_matches("/**")
            .trim_end_matches("/*")
            .trim_end_matches('/');
        if trimmed.is_empty() || max_matches == 0 {
            return Vec::new();
        }
        let idx = self.workspace_index(ws_root);
        let norm_q = if trimmed.contains('\\') {
            trimmed.replace('\\', "/")
        } else {
            trimmed.to_string()
        };

        if !norm_q.contains('/') {
            let h = fast_hash64_ascii_lower(norm_q.as_bytes());
            if let Some(indices) = idx.by_name_hash.get(&h) {
                let mut exact = Vec::new();
                let mut ci = Vec::new();
                for &entry_i in indices.iter() {
                    let it = &idx.entries[entry_i as usize];
                    let fname = idx.file_name(it);
                    if fname == norm_q {
                        let abs = idx.abs_path(it);
                        if abs.is_file() {
                            exact.push(abs);
                            if exact.len() >= max_matches {
                                break;
                            }
                        }
                    } else if fname.eq_ignore_ascii_case(&norm_q) && ci.len() < max_matches {
                        let abs = idx.abs_path(it);
                        if abs.is_file() {
                            ci.push(abs);
                        }
                    }
                }
                let found = if !exact.is_empty() { exact } else { ci };
                if !found.is_empty() {
                    return found;
                }
            }

            if !norm_q.contains('.') {
                let Some(stem_indices) = idx.by_stem_hash.get(&h) else {
                    return Vec::new();
                };
                let mut exact_stem = Vec::new();
                let mut ci_stem = Vec::new();
                for &entry_i in stem_indices.iter() {
                    let it = &idx.entries[entry_i as usize];
                    let stem = idx.file_stem(it);
                    if stem == norm_q {
                        let abs = idx.abs_path(it);
                        if abs.is_file() {
                            exact_stem.push(abs);
                            if exact_stem.len() >= max_matches {
                                break;
                            }
                        }
                    } else if stem.eq_ignore_ascii_case(&norm_q) && ci_stem.len() < max_matches {
                        let abs = idx.abs_path(it);
                        if abs.is_file() {
                            ci_stem.push(abs);
                        }
                    }
                }
                let pool = if !exact_stem.is_empty() { exact_stem } else { ci_stem };
                if is_generic_stem(&norm_q) && pool.len() > 2 {
                    let first_parent = pool.first().and_then(|p| p.parent());
                    if !pool.iter().all(|p| p.parent() == first_parent) {
                        return Vec::new();
                    }
                }
                return pool;
            }
            return Vec::new();
        }

        let tail_has_ext = norm_q.rsplit('/').next().is_some_and(|seg| seg.contains('.'));
        let q_bloom = trigram_bloom64_ascii_lower(norm_q.as_bytes());
        let mut out = Vec::new();
        for it in idx.entries.iter() {
            if (it.trigram_bloom & q_bloom) != q_bloom {
                continue;
            }
            let rel = idx.rel_str(it);
            let target_rel = if tail_has_ext {
                rel
            } else {
                match rel.rfind('.') {
                    Some(dot) if dot > it.name_off as usize => &rel[..dot],
                    _ => rel,
                }
            };
            if target_rel.len() >= norm_q.len() {
                let tail_start = target_rel.len() - norm_q.len();
                let boundary_ok = tail_start == 0 || target_rel.as_bytes()[tail_start - 1] == b'/';
                if boundary_ok && target_rel[tail_start..].eq_ignore_ascii_case(&norm_q) {
                    let abs = idx.abs_path(it);
                    if abs.is_file() {
                        out.push(abs);
                        if out.len() >= max_matches {
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    pub fn resolve_missing_path(&self, missing: &Path, ws_root: &Path) -> MissingResolution {
        let Some(fname) = missing.file_name().and_then(|s| s.to_str()) else {
            return MissingResolution::NotFound;
        };
        let index_arc = self.workspace_index(ws_root);
        let h = fast_hash64_ascii_lower(fname.as_bytes());
        let Some(raw_indices) = index_arc.by_name_hash.get(&h) else {
            return MissingResolution::NotFound;
        };

        let mut exact_case = Vec::new();
        let mut ci_pool = Vec::new();
        for &entry_i in raw_indices.iter() {
            let it = &index_arc.entries[entry_i as usize];
            let cand_name = index_arc.file_name(it);
            if cand_name == fname {
                let abs = index_arc.abs_path(it);
                if abs.is_file() {
                    exact_case.push(abs);
                }
            } else if cand_name.eq_ignore_ascii_case(fname) {
                let abs = index_arc.abs_path(it);
                if abs.is_file() {
                    ci_pool.push(abs);
                }
            }
        }

        let mut pool = if !exact_case.is_empty() {
            exact_case
        } else {
            ci_pool
        };

        if pool.is_empty() {
            return MissingResolution::NotFound;
        }
        if pool.len() == 1 && !is_generic_basename(fname) {
            return MissingResolution::Unique(pool.remove(0));
        }
        pool.sort_by(|a, b| {
            common_parent_suffix_score(b, missing)
                .cmp(&common_parent_suffix_score(a, missing))
                .then_with(|| a.cmp(b))
        });
        pool.truncate(8);
        MissingResolution::Ambiguous(pool)
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

    pub fn current_file_fnv64(&self, path: &Path, ws_root: Option<&Path>) -> Option<u64> {
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
                    return Some(existing.fnv64);
                }
            }
        }
        self.get_full_entry(&canon, ws_root).ok().map(|e| e.fnv64)
    }

    pub fn get_outline_entry(
        &self,
        canon_path: &Path,
        ws_root: Option<&Path>,
    ) -> Result<Arc<CachedFile>, String> {
        if is_sensitive_path(canon_path) {
            return Err(format!("refusing sensitive path: {}", canon_path.display()));
        }
        let st = file_stat(canon_path)?;
        if st.size_bytes as usize > MAX_SINGLE_FILE_CACHE_BYTES {
            return Err(format!(
                "file exceeds 1 MiB cache limit ({} bytes)",
                st.size_bytes
            ));
        }
        let key = norm_key_from_canon(canon_path);
        let s_idx = shard_idx_for(&key);
        if let Ok(guard) = self.shards[s_idx].read() {
            if let Some(existing) = guard.get(key.as_str()) {
                if existing.mtime_ns == st.mtime_ns
                    && existing.ctime_ns == st.ctime_ns
                    && existing.ino == st.ino
                    && existing.size_bytes as u64 == st.size_bytes
                {
                    existing
                        .last_access
                        .store(self.next_tick(), Ordering::Relaxed);
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(Arc::clone(existing));
                }
            }
        }
        self.get_full_entry(canon_path, ws_root)
    }

    pub fn get_full_entry(
        &self,
        canon_path: &Path,
        ws_root: Option<&Path>,
    ) -> Result<Arc<CachedFile>, String> {
        if is_sensitive_path(canon_path) {
            return Err(format!("refusing sensitive path: {}", canon_path.display()));
        }
        let st = file_stat(canon_path)?;
        if st.size_bytes as usize > MAX_SINGLE_FILE_CACHE_BYTES {
            return Err(format!(
                "file exceeds 1 MiB full-cache limit ({} bytes): {}; request a line slice path:start-end",
                st.size_bytes,
                canon_path.display()
            ));
        }

        let raw_key = norm_key_from_canon(canon_path);
        let s_idx = shard_idx_for(&raw_key);

        let prev_cached = {
            let guard = self.shards[s_idx]
                .read()
                .map_err(|_| "shard lock poisoned".to_string())?;
            if let Some(existing) = guard.get(raw_key.as_str()) {
                if existing.mtime_ns == st.mtime_ns
                    && existing.ctime_ns == st.ctime_ns
                    && existing.ino == st.ino
                    && existing.size_bytes as u64 == st.size_bytes
                    && existing.content.is_some()
                {
                    existing
                        .last_access
                        .store(self.next_tick(), Ordering::Relaxed);
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(Arc::clone(existing));
                }
                Some(Arc::clone(existing))
            } else {
                None
            }
        };

        let (path_id, key_arc) = match &prev_cached {
            Some(prev) => (prev.path_id, Arc::clone(&prev.norm_path)),
            None => self.intern_path(&raw_key),
        };

        let inflight_guard = {
            let mut map = self
                .inflight
                .lock()
                .map_err(|_| "inflight lock poisoned".to_string())?;
            if let Some(wait_slot) = map.get(&key_arc).cloned() {
                drop(map);
                if let Ok(done_guard) = wait_slot.done.lock() {
                    let _ = wait_slot
                        .cv
                        .wait_timeout_while(done_guard, Duration::from_secs(5), |done| !*done);
                }
                if let Ok(guard) = self.shards[s_idx].read() {
                    if let Some(loaded) = guard.get(&key_arc) {
                        if loaded.content.is_some() {
                            loaded
                                .last_access
                                .store(self.next_tick(), Ordering::Relaxed);
                            self.cache_hits.fetch_add(1, Ordering::Relaxed);
                            return Ok(Arc::clone(loaded));
                        }
                    }
                }
                None
            } else {
                let slot = Arc::new(InflightSlot {
                    done: Mutex::new(false),
                    cv: Condvar::new(),
                });
                map.insert(Arc::clone(&key_arc), Arc::clone(&slot));
                Some(InflightGuard {
                    map: &self.inflight,
                    key: Arc::clone(&key_arc),
                    slot,
                })
            }
        };

        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        let raw_bytes =
            fs::read(canon_path).map_err(|e| format!("read {}: {}", canon_path.display(), e))?;
        let scanned = scan_source_bytes(raw_bytes).map_err(|err| match err {
            ScanError::Binary => format!("binary file rejected: {}", canon_path.display()),
            ScanError::NonUtf8 => format!("non-UTF8 text file: {}", canon_path.display()),
        })?;

        let fnv64 = fnv1a_64(scanned.text.as_bytes());
        let symbols: Arc<[SymbolSpan]> = match &prev_cached {
            Some(prev)
                if prev.fnv64 == fnv64
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

        let rel_path: Box<str> = match &prev_cached {
            Some(prev) if !prev.rel_path.is_empty() => prev.rel_path.clone(),
            _ => display_workspace_path(canon_path, ws_root).into_boxed_str(),
        };

        let new_entry = Arc::new(CachedFile {
            norm_path: Arc::clone(&key_arc),
            rel_path,
            mtime_ns: st.mtime_ns,
            ctime_ns: st.ctime_ns,
            ino: st.ino,
            fnv64,
            path_id,
            size_bytes: st.size_bytes as u32,
            line_count: scanned.line_count,
            ram_charge: charge_bytes as u32,
            line_offsets: scanned.line_offsets,
            symbols,
            content: Some(Arc::from(scanned.text)),
            last_access: AtomicU64::new(self.next_tick()),
        });

        {
            let mut guard = self.shards[s_idx]
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

        drop(inflight_guard);
        Ok(new_entry)
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

    fn with_session_mut<R>(
        &self,
        session_key: &str,
        f: impl FnOnce(&mut SessionState) -> R,
    ) -> Option<R> {
        let s_idx = shard_idx_for(session_key);
        let mut map = self.sessions[s_idx].lock().ok()?;
        if !map.contains_key(session_key) && map.len() >= MAX_SESSIONS_PER_SHARD {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, v)| v.last_step_ms)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }
        let now = now_ms();
        if let Some(existing) = map.get_mut(session_key) {
            existing.last_step_ms = now;
            return Some(f(existing));
        }
        let mut fresh = SessionState {
            last_step_ms: now,
            ..SessionState::default()
        };
        let res = f(&mut fresh);
        map.insert(session_key.into(), fresh);
        Some(res)
    }

    pub fn has_startup_settled(&self, session_key: &str) -> bool {
        let s_idx = shard_idx_for(session_key);
        let Ok(map) = self.sessions[s_idx].lock() else {
            return false;
        };
        map.get(session_key)
            .map(|s| s.startup_injected)
            .unwrap_or(false)
    }

    pub fn try_mark_startup_injected(&self, session_key: &str) -> bool {
        self.with_session_mut(session_key, |sess| {
            if sess.startup_injected {
                false
            } else {
                sess.startup_injected = true;
                true
            }
        })
        .unwrap_or(false)
    }

    pub fn record_read(
        &self,
        session_key: &str,
        canon_path: &Path,
        ws_root: Option<&Path>,
        start_line: usize,
        end_line: usize,
    ) {
        let Ok(entry) = self.get_outline_entry(canon_path, ws_root) else {
            return;
        };
        let pid = entry.path_id;
        let fnv64 = entry.fnv64;
        let s = start_line.max(1) as u32;
        let e = end_line.max(start_line.max(1)) as u32;

        let _ = self.with_session_mut(session_key, |sess| {
            sess.step_seq = sess.step_seq.saturating_add(1);
            let step = sess.step_seq;
            let mut merged_s = s;
            let mut merged_e = e;
            sess.reads.retain(|r| {
                if r.path_id == pid {
                    if r.fnv64 != fnv64 {
                        return false;
                    }
                    if r.end_line.saturating_add(1) >= merged_s
                        && merged_e.saturating_add(1) >= r.start_line
                    {
                        merged_s = merged_s.min(r.start_line);
                        merged_e = merged_e.max(r.end_line);
                        return false;
                    }
                }
                true
            });
            sess.reads.push(ReadSpan {
                fnv64,
                step_seq: step,
                path_id: pid,
                start_line: merged_s,
                end_line: merged_e,
                strikes: 0,
                _pad: [0; 3],
            });
        });
    }

    pub fn clear_session(&self, session_key: &str) {
        let s_idx = shard_idx_for(session_key);
        if let Ok(mut map) = self.sessions[s_idx].lock() {
            map.remove(session_key);
        }
    }

    pub fn bump_session_step(&self, session_key: &str) -> u64 {
        self.with_session_mut(session_key, |sess| {
            sess.step_seq = sess.step_seq.saturating_add(1);
            sess.step_seq
        })
        .unwrap_or(0)
    }

    pub fn check_duplicate_read(
        &self,
        session_key: &str,
        canon_path: &Path,
        ws_root: Option<&Path>,
        req_start: Option<usize>,
        req_end: Option<usize>,
    ) -> Option<DuplicateHit> {
        let entry = self.get_outline_entry(canon_path, ws_root).ok()?;
        let total_lines = (entry.line_count as usize).max(1);
        let fnv64 = entry.fnv64;
        let pid = entry.path_id;

        let s = req_start.unwrap_or(1).max(1) as u32;
        let e = req_end.unwrap_or(total_lines).min(total_lines).max(s as usize) as u32;

        let s_idx = shard_idx_for(session_key);
        let mut map = self.sessions[s_idx].lock().ok()?;
        let sess = map.get_mut(session_key)?;
        let cur_step = sess.step_seq;

        sess.reads.retain(|sp| sp.path_id != pid || sp.fnv64 == fnv64);

        for span in sess.reads.iter_mut() {
            if span.path_id == pid
                && span.fnv64 == fnv64
                && cur_step.saturating_sub(span.step_seq) <= SESSION_WINDOW_STEPS
                && span.start_line <= s
                && span.end_line >= e
            {
                if span.strikes >= 1 {
                    span.strikes = 0;
                    span.step_seq = cur_step;
                    return None;
                }
                span.strikes = span.strikes.saturating_add(1);
                let cov_s = span.start_line as usize;
                let cov_e = span.end_line as usize;
                let mut unread = Vec::with_capacity(2);
                if cov_s > 1 {
                    unread.push((1, cov_s - 1));
                }
                if cov_e < total_lines {
                    unread.push((cov_e + 1, total_lines));
                }
                return Some(DuplicateHit {
                    covered_start: cov_s,
                    covered_end: cov_e,
                    total_lines,
                    unread_ranges: unread,
                    outline_summary: Self::format_outline_compact(&entry, 10),
                    rel_path: entry.rel_path.to_string(),
                });
            }
        }
        None
    }

    pub fn check_and_mark_dedup(&self, dedup_key: &str) -> bool {
        let now = now_ms();
        let key_hash = fast_hash64(dedup_key.as_bytes()).max(1);
        let Ok(mut ring) = self.dedup_ring.lock() else {
            return false;
        };
        for &(h, ts) in ring.slots.iter() {
            if h == key_hash && now.saturating_sub(ts) < 15_000 {
                return true;
            }
        }
        let idx = ring.cursor;
        ring.slots[idx] = (key_hash, now);
        ring.cursor = (idx + 1) & DEDUP_RING_MASK;
        false
    }

    // --- Metadata-Only `0600` Reboot Snapshot (`ACTXSNP2`, format_tag=3, zero raw source) ---

    pub fn save_snapshot_if_dirty(&self, force: bool) -> Result<(), String> {
        if !self.dirty_since_save.load(Ordering::Relaxed) && !force {
            return Ok(());
        }
        let now = now_ms();
        let last = self.last_save_ms.load(Ordering::Relaxed);
        if !force && now.saturating_sub(last) < 45_000 {
            return Ok(());
        }
        self.save_snapshot()
    }

    pub fn save_snapshot(&self) -> Result<(), String> {
        if let Some(parent) = self.snapshot_path.parent() {
            ensure_private_dir(parent)?;
        }

        let mut entries: Vec<Arc<CachedFile>> = Vec::new();
        for sh in self.shards.iter() {
            if let Ok(guard) = sh.read() {
                entries.extend(guard.values().cloned());
            }
        }
        entries.sort_unstable_by(|a, b| {
            b.last_access
                .load(Ordering::Relaxed)
                .cmp(&a.last_access.load(Ordering::Relaxed))
        });

        let mut payload = Vec::with_capacity(64 * 1024);
        let mut count: u32 = 0;
        for entry in entries {
            let approx = 64 + entry.norm_path.len() + entry.rel_path.len() + entry.symbols.len() * 36;
            if payload.len() + approx > SNAPSHOT_DISK_CAP_BYTES {
                break;
            }
            write_str(&mut payload, &entry.norm_path);
            write_str(&mut payload, &entry.rel_path);
            payload.extend_from_slice(&entry.mtime_ns.to_le_bytes());
            payload.extend_from_slice(&entry.ctime_ns.to_le_bytes());
            payload.extend_from_slice(&entry.ino.to_le_bytes());
            payload.extend_from_slice(&entry.fnv64.to_le_bytes());
            payload.extend_from_slice(&entry.size_bytes.to_le_bytes());
            payload.extend_from_slice(&entry.line_count.to_le_bytes());
            payload.extend_from_slice(&(entry.symbols.len() as u32).to_le_bytes());
            for sym in entry.symbols.iter() {
                payload.push(sym.kind as u8);
                write_str(&mut payload, &sym.name);
                payload.extend_from_slice(&sym.start_line.to_le_bytes());
                payload.extend_from_slice(&sym.end_line.to_le_bytes());
            }
            count += 1;
        }

        let checksum = fnv1a_64(&payload);
        let mut full = Vec::with_capacity(24 + payload.len());
        full.extend_from_slice(SNAPSHOT_MAGIC);
        full.extend_from_slice(&SNAPSHOT_FORMAT_TAG.to_le_bytes());
        full.extend_from_slice(&count.to_le_bytes());
        full.extend_from_slice(&checksum.to_le_bytes());
        full.extend_from_slice(&payload);

        write_private_0600(&self.snapshot_path, &full)?;
        self.dirty_since_save.store(false, Ordering::Relaxed);
        self.last_save_ms.store(now_ms(), Ordering::Relaxed);
        Ok(())
    }

    pub fn load_snapshot(&self) -> Result<usize, String> {
        if !self.snapshot_path.is_file() {
            return Ok(0);
        }
        let mut f = File::open(&self.snapshot_path).map_err(|e| e.to_string())?;
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < 24 || len as usize > SNAPSHOT_DISK_CAP_BYTES + 1024 {
            return Err("snapshot size out of bounds".to_string());
        }
        let mut raw = Vec::with_capacity(len as usize);
        f.read_to_end(&mut raw).map_err(|e| e.to_string())?;

        if &raw[0..8] != SNAPSHOT_MAGIC {
            return Err("snapshot magic mismatch (expected ACTXSNP2)".to_string());
        }
        let tag = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        if tag != SNAPSHOT_FORMAT_TAG {
            return Err("snapshot format mismatch".to_string());
        }
        let count = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;
        let expected_sum = u64::from_le_bytes(raw[16..24].try_into().unwrap());
        let body = &raw[24..];
        if fnv1a_64(body) != expected_sum {
            return Err("snapshot checksum mismatch".to_string());
        }

        let mut cur = 0usize;
        let mut loaded = 0usize;
        for _ in 0..count {
            let norm = read_str_slice(body, &mut cur)?;
            let rel = read_str_slice(body, &mut cur)?;
            let mtime_ns = read_u64(body, &mut cur)?;
            let ctime_ns = read_u64(body, &mut cur)?;
            let ino = read_u64(body, &mut cur)?;
            let fnv64 = read_u64(body, &mut cur)?;
            let size_bytes = read_u32(body, &mut cur)?;
            let line_count = read_u32(body, &mut cur)?;
            let sym_count = read_u32(body, &mut cur)? as usize;
            if sym_count > 100_000 {
                return Err("corrupt symbol count".to_string());
            }
            let mut symbols = Vec::with_capacity(sym_count.min(1024));
            for _ in 0..sym_count {
                let kind_tag = read_u8(body, &mut cur)?;
                let kind = SymbolKind::from_tag(kind_tag)
                    .ok_or_else(|| "invalid symbol kind tag in snapshot".to_string())?;
                let name = read_str_slice(body, &mut cur)?;
                let start_line = read_u32(body, &mut cur)?;
                let end_line = read_u32(body, &mut cur)?;
                symbols.push(SymbolSpan {
                    kind,
                    name: name.into(),
                    signature: "".into(),
                    start_line,
                    end_line,
                });
            }
            let (path_id, key_arc) = self.intern_path(norm);
            let s_idx = shard_idx_for(norm);
            let tick = self.next_tick();
            if let Ok(mut guard) = self.shards[s_idx].write() {
                guard.insert(
                    Arc::clone(&key_arc),
                    Arc::new(CachedFile {
                        norm_path: key_arc,
                        rel_path: rel.into(),
                        mtime_ns,
                        ctime_ns,
                        ino,
                        fnv64,
                        path_id,
                        size_bytes,
                        line_count,
                        ram_charge: 0,
                        line_offsets: Box::new([]),
                        symbols: Arc::from(symbols),
                        content: None,
                        last_access: AtomicU64::new(tick),
                    }),
                );
                loaded += 1;
            }
        }
        Ok(loaded)
    }
}

pub fn verify_snapshot_metadata_only(path: &Path) -> Result<(u32, u64), String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!("snapshot permissions {:o} are wider than 0600", mode));
        }
    }
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    if raw.len() < 24 {
        return Err("snapshot header truncated".to_string());
    }
    if &raw[0..8] != SNAPSHOT_MAGIC {
        return Err("snapshot magic is not ACTXSNP2".to_string());
    }
    let tag = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    if tag != SNAPSHOT_FORMAT_TAG {
        return Err(format!("unexpected snapshot format tag {}", tag));
    }
    let count = u32::from_le_bytes(raw[12..16].try_into().unwrap());
    let expected_sum = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    if fnv1a_64(&raw[24..]) != expected_sum {
        return Err("snapshot FNV-1a checksum mismatch".to_string());
    }
    Ok((count, meta.len()))
}

pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[inline]
fn write_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

#[inline]
fn read_u8(buf: &[u8], cur: &mut usize) -> Result<u8, String> {
    if *cur + 1 > buf.len() {
        return Err("truncated u8".to_string());
    }
    let v = buf[*cur];
    *cur += 1;
    Ok(v)
}

#[inline]
fn read_u32(buf: &[u8], cur: &mut usize) -> Result<u32, String> {
    if *cur + 4 > buf.len() {
        return Err("truncated u32".to_string());
    }
    let v = u32::from_le_bytes(buf[*cur..*cur + 4].try_into().unwrap());
    *cur += 4;
    Ok(v)
}

#[inline]
fn read_u64(buf: &[u8], cur: &mut usize) -> Result<u64, String> {
    if *cur + 8 > buf.len() {
        return Err("truncated u64".to_string());
    }
    let v = u64::from_le_bytes(buf[*cur..*cur + 8].try_into().unwrap());
    *cur += 8;
    Ok(v)
}

#[inline]
fn read_str_slice<'a>(buf: &'a [u8], cur: &mut usize) -> Result<&'a str, String> {
    let len = read_u32(buf, cur)? as usize;
    if len > (MAX_SINGLE_FILE_CACHE_BYTES << 1) || *cur + len > buf.len() {
        return Err("truncated string".to_string());
    }
    let s = std::str::from_utf8(&buf[*cur..*cur + len])
        .map_err(|_| "invalid UTF-8 in snapshot".to_string())?;
    *cur += len;
    Ok(s)
}
