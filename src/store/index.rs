//! Arena-packed workspace file index with identity-hashed name/stem buckets,
//! trigram-Bloom path suffix search, and ancestor directory-suffix resolution.

use super::paths::{is_multimodal_or_binary_ext, should_skip_dir};
use super::{now_ms, RamStore};
use crate::base::security::is_sensitive_path_lexical;
use crate::base::simd::{
    fast_hash64_ascii_lower, trigram_bloom64_ascii_lower, FastHashMap, IdentityHashMap,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

const WORKSPACE_INDEX_TTL_MS: u64 = 5_000;
const MAX_INDEXED_WORKSPACE_FILES: usize = 25_000;

#[derive(Clone, Debug)]
pub enum MissingResolution {
    Unique(PathBuf),
    Ambiguous(Vec<PathBuf>),
    NotFound,
}

/// Exact 16-byte arena-indexed file entry (4 entries per 64B cache line;
/// `0` per-file `String` or `PathBuf` allocations).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IndexedFile {
    pub trigram_bloom: u64,
    pub rel_off: u32,
    pub rel_len: u16,
    pub name_off: u16,
}

const _: [(); 16] = [(); std::mem::size_of::<IndexedFile>()];

pub struct WorkspaceFiles {
    pub built_ms: u64,
    pub root: PathBuf,
    pub arena: Box<[u8]>,
    pub entries: Box<[IndexedFile]>,
    pub by_name_hash: IdentityHashMap<u64, Box<[u32]>>,
    pub by_stem_hash: IdentityHashMap<u64, Box<[u32]>>,
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
        // SAFETY: `name_off` points immediately after an ASCII `/` (or `0`) inside valid UTF-8.
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
pub(super) struct WorkspaceIndexCache {
    pub(super) indices: RwLock<FastHashMap<PathBuf, Arc<WorkspaceFiles>>>,
    pub(super) prewarming: Mutex<Vec<PathBuf>>,
}

fn is_generic_basename(file_name: &str) -> bool {
    const GENERIC: &[&str] = &[
        "cmakelists.txt",
        "readme.md",
        "agents.md",
        "claude.md",
        "gemini.md",
        "skill.md",
        "main.cpp",
        "main.rs",
        "mod.rs",
        "lib.rs",
        "index.ts",
        "index.js",
        "__init__.py",
        "config.hpp",
        "types.hpp",
    ];
    GENERIC.iter().any(|&g| file_name.eq_ignore_ascii_case(g))
}

fn is_generic_stem(stem: &str) -> bool {
    const GENERIC: &[&str] = &[
        "cmakelists",
        "readme",
        "agents",
        "claude",
        "gemini",
        "skill",
        "main",
        "mod",
        "lib",
        "index",
        "__init__",
        "config",
        "types",
        "manifest",
        "profile",
        "secret",
    ];
    GENERIC.iter().any(|&g| stem.eq_ignore_ascii_case(g))
}

fn stem_has_token_ci(stem: &str, query: &str) -> bool {
    let bytes = stem.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= bytes.len() {
        let is_sep = i == bytes.len() || bytes[i] == b'_' || bytes[i] == b'-';
        let is_camel = i > start
            && i < bytes.len()
            && bytes[i].is_ascii_uppercase()
            && (bytes[i - 1].is_ascii_lowercase() || bytes[i - 1].is_ascii_digit());
        if is_sep || is_camel {
            if i > start && stem[start..i].eq_ignore_ascii_case(query) {
                return true;
            }
            start = if is_sep { i + 1 } else { i };
        }
        i += 1;
    }
    false
}

fn parent_segments_compact_match(rel: &str, q_compact: &[u8]) -> bool {
    let Some((parent, _)) = rel.rsplit_once('/') else {
        return false;
    };
    let mut segs = [""; 16];
    let mut n_segs = 0usize;
    for seg in parent.split('/').filter(|s| !s.is_empty()) {
        if n_segs >= segs.len() {
            break;
        }
        segs[n_segs] = seg;
        n_segs += 1;
    }
    for start in 0..n_segs {
        let mut matched = 0usize;
        let mut ok = true;
        for &seg in &segs[start..n_segs] {
            for b in seg.bytes().filter(u8::is_ascii_alphanumeric) {
                if matched >= q_compact.len() || b.to_ascii_lowercase() != q_compact[matched] {
                    ok = false;
                    break;
                }
                matched += 1;
            }
            if !ok {
                break;
            }
            if matched == q_compact.len() {
                return true;
            }
        }
    }
    false
}

fn build_workspace_index(canon_root: &Path) -> WorkspaceFiles {
    let mut rel_list: Vec<String> = Vec::with_capacity(2048);
    walk_workspace_rel_paths(canon_root, canon_root, &mut rel_list);
    rel_list.sort_unstable();

    let total_bytes: usize = rel_list.iter().map(|s| s.len()).sum();
    let mut arena = Vec::with_capacity(total_bytes);
    let mut entries = Vec::with_capacity(rel_list.len());
    let mut temp_by_hash: IdentityHashMap<u64, Vec<u32>> =
        IdentityHashMap::with_capacity_and_hasher(rel_list.len(), Default::default());
    let mut temp_by_stem: IdentityHashMap<u64, Vec<u32>> =
        IdentityHashMap::with_capacity_and_hasher(rel_list.len(), Default::default());

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
            if !should_skip_dir(dname) {
                walk_workspace_rel_paths(root, &path, out);
            }
        } else if meta.is_file()
            && !is_sensitive_path_lexical(&path)
            && !is_multimodal_or_binary_ext(&path)
        {
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

    /// Universal segment-bounded ancestor directory-suffix lookup (e.g. `"Exchanges/Binance"` ->
    /// `src/src/Exchanges/Binance`, `"Core/Math"` -> `src/src/Core/Math`).
    pub fn find_workspace_dirs(
        &self,
        raw_query: &str,
        ws_root: &Path,
        max_dirs: usize,
    ) -> Vec<PathBuf> {
        let trimmed_raw = raw_query.trim();
        let replaced;
        let s = if trimmed_raw.contains('\\') {
            replaced = trimmed_raw.replace('\\', "/");
            replaced.as_str()
        } else {
            trimmed_raw
        };
        let norm_q = s
            .trim_start_matches("./")
            .trim_end_matches('/')
            .trim_end_matches("/**")
            .trim_end_matches("/*")
            .trim_end_matches('/');
        if norm_q.is_empty() || norm_q == "." || max_dirs == 0 {
            return Vec::new();
        }

        let idx = self.workspace_index(ws_root);
        let q_bloom = trigram_bloom64_ascii_lower(norm_q.as_bytes());
        let mut seen: FastHashMap<&str, ()> = FastHashMap::default();
        let mut matched_ancs: Vec<&str> = Vec::new();

        for it in idx.entries.iter() {
            if (it.trigram_bloom & q_bloom) != q_bloom {
                continue;
            }
            let rel = idx.rel_str(it);
            for (slash_idx, &b) in rel.as_bytes().iter().enumerate() {
                if b != b'/' {
                    continue;
                }
                if slash_idx < norm_q.len() {
                    continue;
                }
                let anc = &rel[..slash_idx];
                let tail_start = anc.len() - norm_q.len();
                let boundary_ok = tail_start == 0 || anc.as_bytes()[tail_start - 1] == b'/';
                if boundary_ok
                    && anc[tail_start..].eq_ignore_ascii_case(norm_q)
                    && seen.insert(anc, ()).is_none()
                {
                    matched_ancs.push(anc);
                }
            }
        }

        if matched_ancs.is_empty() {
            return Vec::new();
        }
        matched_ancs.sort_unstable();

        let generic_single = !norm_q.contains('/') && is_generic_stem(norm_q);
        let limit = if generic_single { max_dirs.max(3) } else { max_dirs };
        let mut out = Vec::with_capacity(matched_ancs.len().min(limit));
        for anc in matched_ancs {
            let abs = idx.root.join(anc);
            if abs.is_dir() {
                out.push(abs);
                if out.len() >= limit {
                    break;
                }
            }
        }
        if generic_single && out.len() > 2 {
            let first_parent = out.first().and_then(|p| p.parent());
            if !out.iter().all(|p| p.parent() == first_parent) {
                return Vec::new();
            }
        }
        out.truncate(max_dirs);
        out
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
                if let Some(stem_indices) = idx.by_stem_hash.get(&h) {
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
                        } else if stem.eq_ignore_ascii_case(&norm_q) && ci_stem.len() < max_matches
                        {
                            let abs = idx.abs_path(it);
                            if abs.is_file() {
                                ci_stem.push(abs);
                            }
                        }
                    }
                    let pool = if !exact_stem.is_empty() {
                        exact_stem
                    } else {
                        ci_stem
                    };
                    if !pool.is_empty() {
                        if is_generic_stem(&norm_q) && pool.len() > 2 {
                            let first_parent = pool.first().and_then(|p| p.parent());
                            if !pool.iter().all(|p| p.parent() == first_parent) {
                                return Vec::new();
                            }
                        }
                        return pool;
                    }
                }

                // Tier 3: nested directory segment match (e.g. `resolver` -> `graph/resolver/*`).
                if norm_q.len() >= 3 {
                    let mut dir_hits = Vec::new();
                    for it in idx.entries.iter() {
                        let rel = idx.rel_str(it);
                        if let Some((parent, _)) = rel.rsplit_once('/') {
                            if parent.split('/').any(|seg| seg.eq_ignore_ascii_case(&norm_q)) {
                                let abs = idx.abs_path(it);
                                if abs.is_file() {
                                    dir_hits.push(abs);
                                    if dir_hits.len() >= max_matches {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if !dir_hits.is_empty() {
                        if is_generic_stem(&norm_q) && dir_hits.len() > 2 {
                            let first_parent = dir_hits.first().and_then(|p| p.parent());
                            if !dir_hits.iter().all(|p| p.parent() == first_parent) {
                                return Vec::new();
                            }
                        }
                        return dir_hits;
                    }
                }

                // Tier 4: stem word token or consecutive directory segments match
                // (e.g. `manifest` -> `manifest_scanner.py`, `graphresolver` -> `graph/resolver/*`).
                if norm_q.len() >= 4 {
                    let q_compact: Vec<u8> = norm_q
                        .bytes()
                        .filter(u8::is_ascii_alphanumeric)
                        .map(|b| b.to_ascii_lowercase())
                        .collect();
                    if q_compact.len() >= 4 {
                        let mut token_hits = Vec::new();
                        for it in idx.entries.iter() {
                            let stem = idx.file_stem(it);
                            let rel = idx.rel_str(it);
                            let matched = stem_has_token_ci(stem, &norm_q)
                                || parent_segments_compact_match(rel, &q_compact);
                            if matched {
                                let abs = idx.abs_path(it);
                                if abs.is_file() {
                                    token_hits.push(abs);
                                    if token_hits.len() >= max_matches {
                                        break;
                                    }
                                }
                            }
                        }
                        if !token_hits.is_empty() {
                            if is_generic_stem(&norm_q) && token_hits.len() > 2 {
                                let first_parent = token_hits.first().and_then(|p| p.parent());
                                if !token_hits.iter().all(|p| p.parent() == first_parent) {
                                    return Vec::new();
                                }
                            }
                            return token_hits;
                        }
                    }
                }
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
}
