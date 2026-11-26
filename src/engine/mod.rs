// Core concurrent context operations over `BrokerService`:
//   - `op_inspect` (batch directory/slice triage: lines, size flags, namespaces, includes, symbols)
//   - `op_read_for_host` (up to 1 MiB without 800-line truncation)
//   - `op_outline` (fast structural outline, served from `ACTXSNP2` metadata when unchanged)
//   - `op_symbols` (`path#Symbol` extraction)
//   - `op_search` / `op_search_batch` (in-RAM SIMD search, bounded `rg`, and pure-Rust fallback)
//   - `op_memo` (`put | get | list | clear` with automatic `[STALE]` verification)
//   - `op_elf_audit` (native Rust ELF64 + ASM static inspector) and `op_status`.

pub mod elf_audit;
pub mod outline;
pub mod read;
pub mod search;
pub mod symbols;

pub use elf_audit::op_elf_audit;
pub use outline::{op_inspect, op_outline};
pub use read::op_read_for_host;
pub use search::{
    cap_text, op_search, op_search_batch, parse_shorthand_search_spec, SearchError, SearchOptions,
    SEARCH_RESPONSE_BYTES,
};
pub use symbols::op_symbols;

use crate::base::json::Json;
use crate::base::security::{admit_file_in_workspace, is_sensitive_path};
use crate::broker::{contains_known_secret, MemoFileLink};
use crate::rpc::BrokerService;
use crate::store::{
    is_multimodal_or_binary_ext, norm_key_from_canon, resolve_input_path, should_skip_dir,
    MAX_SINGLE_FILE_CACHE_BYTES,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

pub const DEFAULT_READ_MAX_BYTES: usize = 1_048_576; // 1 MiB
pub const DEFAULT_INSPECT_MAX_BYTES: usize = 9_000; // Fits under Antigravity's ~10 KB MCP inline cap
pub const AGY_MCP_DEFAULT_MAX_BYTES: usize = 9_000;
pub const AGY_MCP_INLINE_CAP: usize = 9_200;

pub fn is_safe_shorthand_candidate(raw: &str) -> bool {
    let t = raw.trim().trim_matches('"').trim_matches('\'');
    !t.is_empty()
        && !t.starts_with('/')
        && !t.starts_with('\\')
        && !t.starts_with("~/")
        && !t.contains("..")
        && !(t.len() >= 2 && t.as_bytes()[1] == b':')
}

pub fn is_searchable_source_file(path: &Path, meta: &fs::Metadata) -> bool {
    meta.is_file()
        && meta.len() <= MAX_SINGLE_FILE_CACHE_BYTES as u64
        && !is_sensitive_path(path)
        && !is_multimodal_or_binary_ext(path)
}

pub fn walk_source_dir(dir: &Path, out: &mut Vec<PathBuf>, max_files: usize) {
    if out.len() >= max_files {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|x| x.path())).collect();
    entries.sort();

    for path in entries {
        if out.len() >= max_files {
            break;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !should_skip_dir(name) {
                walk_source_dir(&path, out, max_files);
            }
        } else if is_searchable_source_file(&path, &meta) {
            out.push(path);
        }
    }
}

pub fn collect_target_files(
    svc: &BrokerService,
    targets: &[String],
    cwd: Option<&Path>,
    max_files: usize,
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let mut out = Vec::new();
    let mut first_refusal: Option<String> = None;

    for raw in targets {
        if out.len() >= max_files {
            break;
        }
        let cleaned = raw
            .trim()
            .trim_end_matches("/**")
            .trim_end_matches("/*");
        if cleaned.is_empty() {
            continue;
        }
        let mut p = resolve_input_path(cleaned, cwd);
        if !p.exists() && is_safe_shorthand_candidate(cleaned) && !is_sensitive_path(&p) {
            if let Some(ws_root) = cwd.and_then(|c| svc.allowlist.register_hint(c, false)) {
                let dirs = svc.store.find_workspace_dirs(cleaned, &ws_root, 8);
                if !dirs.is_empty() {
                    let mut any_admitted_dir = false;
                    for dir in dirs {
                        if out.len() >= max_files {
                            break;
                        }
                        match svc.allowlist.admit_dir(&dir, cwd) {
                            Ok((canon_dir, wr)) => {
                                any_admitted_dir = true;
                                let mut sub = Vec::new();
                                walk_source_dir(
                                    &canon_dir,
                                    &mut sub,
                                    max_files.saturating_sub(out.len()),
                                );
                                for f in sub {
                                    if !out.iter().any(|(existing, _)| existing == &f) {
                                        out.push((f, wr.clone()));
                                    }
                                }
                            }
                            Err(e) => {
                                if first_refusal.is_none() {
                                    first_refusal = Some(e);
                                }
                            }
                        }
                    }
                    if any_admitted_dir {
                        continue;
                    }
                } else {
                    let found = svc.store.find_workspace_paths(cleaned, &ws_root, 8);
                    if found.len() == 1 {
                        p = found.into_iter().next().unwrap();
                    } else if found.len() > 1 {
                        for cand in found {
                            if out.len() >= max_files {
                                break;
                            }
                            if let Ok((canon_f, wr)) = svc.allowlist.admit_file(&cand, cwd) {
                                if canon_f.is_file()
                                    && !is_multimodal_or_binary_ext(&canon_f)
                                    && !out.iter().any(|(existing, _)| existing == &canon_f)
                                {
                                    out.push((canon_f, wr));
                                }
                            }
                        }
                        continue;
                    }
                }
            }
        }
        if p.is_dir() {
            match svc.allowlist.admit_dir(&p, cwd) {
                Ok((canon_dir, ws_root)) => {
                    let mut sub = Vec::new();
                    walk_source_dir(&canon_dir, &mut sub, max_files.saturating_sub(out.len()));
                    for f in sub {
                        out.push((f, ws_root.clone()));
                    }
                }
                Err(e) => {
                    if first_refusal.is_none() {
                        first_refusal = Some(e);
                    }
                }
            }
        } else {
            match svc.allowlist.admit_file(&p, cwd) {
                Ok((canon_f, ws_root)) => {
                    if canon_f.is_file() && !is_multimodal_or_binary_ext(&canon_f) {
                        out.push((canon_f, ws_root));
                    }
                }
                Err(e) => {
                    if first_refusal.is_none() {
                        first_refusal = Some(e);
                    }
                }
            }
        }
    }
    if out.is_empty() {
        if let Some(err) = first_refusal {
            return Err(err);
        }
    }
    Ok(out)
}

pub fn op_memo(
    svc: &BrokerService,
    action: &str,
    topic: &str,
    summary: &str,
    kind: Option<&str>,
    trusted_author: Option<&str>,
    paths: &[String],
    cwd: Option<&Path>,
) -> Result<Json, String> {
    let base = cwd
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let ws_root = svc
        .allowlist
        .register_hint(&base, false)
        .ok_or_else(|| "cannot resolve workspace root for memo".to_string())?;
    let ws_norm = norm_key_from_canon(&ws_root);

    match action {
        "put" => {
            let mut links = Vec::new();
            for raw_p in paths {
                if contains_known_secret(raw_p) {
                    return Err("REFUSED: memo link contains known secret material".to_string());
                }
                let resolved = resolve_input_path(raw_p, Some(&base));
                let canon = admit_file_in_workspace(&resolved, &ws_root)?;
                let rel = canon
                    .strip_prefix(&ws_root)
                    .expect("admitted file must be inside its workspace")
                    .to_str()
                    .ok_or_else(|| "memo linked path must be UTF-8".to_string())?;
                if contains_known_secret(rel) {
                    return Err("REFUSED: memo link contains known secret material".to_string());
                }
                if links.iter().any(|link: &MemoFileLink| link.abs_path == canon) {
                    return Err("memo link paths must be unique".to_string());
                }
                let hash = svc
                    .store
                    .current_file_hash64(&canon, Some(&ws_root))
                    .ok_or_else(|| "cannot hash memo linked file".to_string())?;
                links.push(MemoFileLink {
                    rel_path: rel.to_string(),
                    abs_path: canon,
                    hash64_at_put: Some(hash),
                });
            }
            let text = svc
                .broker
                .put_memo(&ws_norm, topic, summary, kind, trusted_author, links)?;
            Ok(Json::obj(vec![("text", Json::Str(text))]))
        }
        "list" => {
            let memos = svc.broker.list_memos(&ws_norm, &ws_root, topic, &svc.store)?;
            Ok(Json::obj(vec![("memos", Json::Arr(memos))]))
        }
        "get" => {
            let memo = svc.broker.get_memo(&ws_norm, &ws_root, topic, &svc.store)?;
            Ok(Json::obj(vec![("memo", memo)]))
        }
        "clear" => {
            let topic = topic.trim();
            let text = svc
                .broker
                .clear_memos(&ws_norm, (!topic.is_empty()).then_some(topic))?;
            Ok(Json::obj(vec![("text", Json::Str(text))]))
        }
        other => Err(format!(
            "unknown memo action `{}` (expected put | get | list | clear)",
            other
        )),
    }
}

pub fn op_status(svc: &BrokerService) -> Json {
    let capsules = svc.broker.capsules.status();
    let used = svc.store.used_ram_bytes.load(Ordering::Relaxed);
    Json::obj(vec![
        ("cached_files", Json::Int(svc.store.cached_file_count() as i64)),
        ("used_ram_bytes", Json::Int(used as i64)),
        ("used_ram_mb", Json::Int((used >> 20) as i64)),
        ("max_ram_mb", Json::Int((svc.store.max_ram_bytes >> 20) as i64)),
        (
            "active_sessions",
            Json::Int(svc.store.active_session_count() as i64),
        ),
        (
            "staged_capsules",
            capsules.get("pending").cloned().unwrap_or(Json::Int(0)),
        ),
        ("capsules", capsules),
        ("memo_entries", Json::Int(svc.broker.memo_count() as i64)),
        (
            "allowed_roots",
            Json::Int(svc.allowlist.root_count() as i64),
        ),
        (
            "active_subprocs",
            Json::Int(svc.subproc_sem.active_count() as i64),
        ),
        ("peak_subprocs", Json::Int(svc.subproc_sem.peak_count() as i64)),
        (
            "cache_hits",
            Json::Int(svc.store.cache_hits.load(Ordering::Relaxed) as i64),
        ),
        (
            "cache_misses",
            Json::Int(svc.store.cache_misses.load(Ordering::Relaxed) as i64),
        ),
        (
            "snapshot_path",
            Json::Str(svc.store.snapshot_path.to_string_lossy().into_owned()),
        ),
        ("snapshot_exists", Json::Bool(svc.store.snapshot_path.is_file())),
    ])
}
