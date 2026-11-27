// Core concurrent context operations over `BrokerService`:
//   - `op_inspect` (batch directory/slice triage: lines, size flags, namespaces, includes, symbols)
//   - `op_read_for_host` (up to 1 MiB without 800-line truncation)
//   - `op_outline` (fast structural outline, served from `ACTXSNP2` metadata when unchanged)
//   - `op_symbols` (`path#Symbol` extraction)
//   - `op_search` / `op_search_batch` (in-RAM SIMD search, bounded `rg`, and pure-Rust fallback)
//   - `op_memo` (`put | get | list | clear` with automatic `[STALE]` verification)
//   - `op_elf_audit` (native Rust ELF64 + ASM static inspector) and `op_status`.

pub mod compact;
pub mod elf_audit;
pub mod outline;
pub mod read;
pub mod search;
pub mod symbols;

#[allow(unused_imports)]
pub use elf_audit::op_elf_audit;
pub use elf_audit::op_elf_audit_with_baseline;
#[allow(unused_imports)]
pub use outline::op_outline;
pub use outline::{op_inspect, op_outline_with_options};
pub use read::op_read_for_host;
pub use search::{
    cap_text, op_search, op_search_batch, parse_shorthand_search_spec, SearchError, SearchOptions,
    SEARCH_RESPONSE_BYTES,
};
#[allow(unused_imports)]
pub use symbols::{op_symbols, op_symbols_with_options};

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
pub const AGY_MCP_DEFAULT_MAX_BYTES: usize = 9_000; // Fits under Antigravity's ~10 KB MCP inline cap
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
                        if let Some(first) = found.into_iter().next() {
                            p = first;
                        }
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

#[allow(dead_code)]
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
    op_memo_full(
        svc,
        action,
        topic,
        summary,
        kind,
        trusted_author,
        None,
        paths,
        false,
        false,
        AGY_MCP_DEFAULT_MAX_BYTES,
        cwd,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn op_memo_full(
    svc: &BrokerService,
    action: &str,
    topic: &str,
    summary: &str,
    kind: Option<&str>,
    trusted_author: Option<&str>,
    session_key: Option<&str>,
    paths: &[String],
    force: bool,
    raw: bool,
    max_bytes: usize,
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
                    .map_err(|_| "memo linked file escaped workspace root".to_string())?
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
            let removed_packs = svc
                .broker
                .packs
                .remove_pack(&ws_norm, (!topic.is_empty()).then_some(topic));
            let msg = if removed_packs > 0 {
                format!("{text} Cleared {removed_packs} pack(s).")
            } else {
                text
            };
            Ok(Json::obj(vec![("text", Json::Str(msg))]))
        }
        "changes" => {
            let since_seq = topic.trim().parse::<u64>().unwrap_or(0);
            let (head, events) = svc.broker.changes.changes_since(&ws_norm, since_seq, 64);
            Ok(Json::obj(vec![(
                "changes",
                crate::broker::change_feed::ChangeFeed::to_json(head, &events),
            )]))
        }
        "pack" => {
            let name = topic.trim();
            let pol = crate::base::ext::policy();
            if pol.list_virtual_packs(&ws_root).iter().any(|&v| v == name)
                || pol.resolve_virtual_pack(&ws_root, name).is_some()
            {
                return Err(format!(
                    "REFUSED: pack name `{name}` is reserved by a built-in virtual pack"
                ));
            }
            let opt_summary = (!summary.trim().is_empty()).then_some(summary);
            let author = trusted_author.unwrap_or("unknown");
            let text = svc
                .broker
                .packs
                .put_pack(&ws_norm, name, paths.to_vec(), opt_summary, author)?;
            Ok(Json::obj(vec![("text", Json::Str(text))]))
        }
        "pack_get" => {
            let text = materialize_pack_for_workspace(
                svc,
                &ws_root,
                topic.trim(),
                session_key,
                force,
                raw,
                max_bytes,
            )?;
            Ok(Json::obj(vec![("text", Json::Str(text))]))
        }
        "packs" => {
            let mut out = String::from("Shared Context Packs:\n");
            let pol = crate::base::ext::policy();
            let mut count = 0usize;
            for &vname in pol.list_virtual_packs(&ws_root) {
                if let Some((_label, sels)) = pol.resolve_virtual_pack(&ws_root, vname) {
                    out.push_str(&format!("- {vname} [virtual, {} selector(s)]: {}\n", sels.len(), sels.join(", ")));
                    count += 1;
                }
            }
            for p in svc.broker.packs.list_packs(&ws_norm) {
                out.push_str(&format!("- {} [shared, {} selector(s), by {}]: {}\n", p.name, p.selectors.len(), p.author, p.selectors.join(", ")));
                count += 1;
            }
            if count == 0 {
                out.push_str("(none)\n");
            }
            Ok(Json::obj(vec![("text", Json::Str(out))]))
        }
        other => Err(format!(
            "unknown memo action `{}` (expected put | get | list | clear | changes | pack | pack_get | packs)",
            other
        )),
    }
}

pub fn materialize_pack_for_workspace(
    svc: &BrokerService,
    ws_root: &Path,
    pack_name: &str,
    session_key: Option<&str>,
    force: bool,
    raw: bool,
    max_bytes: usize,
) -> Result<String, String> {
    if pack_name.is_empty() {
        return Err("pack_get requires a non-empty `topic` pack name".to_string());
    }
    let ws_norm = norm_key_from_canon(ws_root);
    let budget = max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES);
    let pol = crate::base::ext::policy();
    let (is_virtual, summary, selectors): (bool, Option<String>, Vec<String>) =
        if let Some((label, sels)) = pol.resolve_virtual_pack(ws_root, pack_name) {
            (true, (!label.trim().is_empty()).then_some(label), sels)
        } else if let Some(spec) = svc.broker.packs.get_pack(&ws_norm, pack_name) {
            (false, spec.summary, spec.selectors)
        } else {
            return Err(format!("shared pack `{pack_name}` not found"));
        };

    let mut digest_seed = Vec::with_capacity(256);
    digest_seed.extend_from_slice(pack_name.as_bytes());
    digest_seed.push(if raw { 1 } else { 0 });
    digest_seed.extend_from_slice(&(budget as u64).to_le_bytes());
    if let Some(ref s) = summary {
        if contains_known_secret(s) {
            return Err("REFUSED: pack summary contains known secret material".to_string());
        }
        digest_seed.extend_from_slice(s.as_bytes());
    }

    let mut body = String::with_capacity(budget.min(8192));
    if let Some(ref s) = summary {
        if is_virtual {
            body.push_str("[Pack Summary]: ");
        } else {
            body.push_str("[Memo Note (untrusted)]: ");
        }
        body.push_str(s.trim());
        body.push('\n');
    }

    let mut resolved_ok = 0usize;
    for (idx, sel) in selectors.iter().enumerate() {
        if body.len() >= budget.saturating_sub(96) {
            let rem_sels: Vec<&str> = selectors[idx..].iter().map(String::as_str).collect();
            body.push_str(&format!(
                "... [truncated at max_bytes; remaining: {} — fetch via ctx_symbols]\n",
                rem_sels.join(", ")
            ));
            break;
        }
        let Some((file_part, anchor_kind)) = parse_pack_selector(sel) else {
            continue;
        };
        let cand = resolve_input_path(file_part, Some(ws_root));
        let canon = match admit_file_in_workspace(&cand, ws_root) {
            Ok(c) => c,
            Err(e) => {
                body.push_str(&format!("=== {sel} [{e}] ===\n"));
                continue;
            }
        };
        if crate::base::security::is_sensitive_path_with_ws(&canon, Some(ws_root), false) {
            body.push_str(&format!("=== {sel} [REFUSED: sensitive path] ===\n"));
            continue;
        }
        let Ok(entry) = svc.store.get_full_entry(&canon, Some(ws_root)) else {
            body.push_str(&format!("=== {sel} [ERROR: unreadable] ===\n"));
            continue;
        };
        let Some(full_text) = entry.content.as_deref() else {
            continue;
        };
        if contains_known_secret(full_text) {
            body.push_str(&format!("=== {} [REFUSED: secret material] ===\n", entry.rel_path));
            continue;
        }
        digest_seed.extend_from_slice(&entry.content_hash64.to_le_bytes());
        digest_seed.extend_from_slice(sel.as_bytes());

        let total_lines = (entry.line_count as usize).max(1);
        let (s_ln, e_ln, label) = match anchor_kind {
            PackAnchor::Symbol(q) => {
                let Some(sym) = entry
                    .symbols
                    .iter()
                    .find(|sym| symbols::symbol_matches_query(&sym.name, q))
                else {
                    body.push_str(&format!(
                        "=== {}#{} [NOT FOUND] ===\n",
                        entry.rel_path, q
                    ));
                    continue;
                };
                (
                    (sym.start_line as usize).max(1),
                    (sym.end_line as usize).min(total_lines),
                    format!("{}#{}", entry.rel_path, sym.name),
                )
            }
            PackAnchor::Lines(s, e) => (
                s.clamp(1, total_lines),
                e.clamp(s.clamp(1, total_lines), total_lines),
                format!("{}:{}-{}", entry.rel_path, s, e),
            ),
            PackAnchor::Whole => (1, total_lines.min(200), entry.rel_path.to_string()),
        };

        let mut raw_slice = String::new();
        for ln in s_ln..=e_ln {
            raw_slice.push_str(entry.line_slice(ln as u32));
            raw_slice.push('\n');
        }
        let ext = canon.extension().and_then(|e| e.to_str()).unwrap_or("");
        let rendered = if !raw && compact::is_doc_or_config_ext(ext) {
            compact::compact_text_for_ext(ext, &raw_slice, true)
        } else {
            raw_slice
        };
        let header = format!("=== {label} [L{s_ln}-L{e_ln}] ===\n");
        let avail = budget.saturating_sub(body.len() + 96);
        if header.len() >= avail {
            let rem_sels: Vec<&str> = selectors[idx..].iter().map(String::as_str).collect();
            body.push_str(&format!(
                "... [truncated at max_bytes; remaining: {} — fetch via ctx_symbols]\n",
                rem_sels.join(", ")
            ));
            break;
        }
        body.push_str(&header);
        let rem = avail.saturating_sub(header.len());
        if rendered.len() <= rem {
            body.push_str(&rendered);
            if !rendered.ends_with('\n') {
                body.push('\n');
            }
        } else {
            let mut cut = rem;
            while cut > 0 && !rendered.is_char_boundary(cut) {
                cut -= 1;
            }
            body.push_str(&rendered[..cut]);
            let next_sels: Vec<&str> = selectors[idx + 1..].iter().map(String::as_str).collect();
            if next_sels.is_empty() {
                body.push_str("\n... [truncated at max_bytes]\n");
            } else {
                body.push_str(&format!(
                    "\n... [truncated at max_bytes; remaining: {} — fetch via ctx_symbols]\n",
                    next_sels.join(", ")
                ));
            }
        }
        resolved_ok += 1;
    }

    let digest = crate::base::simd::fast_hash64(&digest_seed);
    if let Some(sk) = session_key.filter(|s| !s.is_empty()) {
        if svc
            .broker
            .packs
            .check_and_mark_delivered(sk, &ws_norm, pack_name, digest, force)
        {
            return Ok(format!(
                "[UNCHANGED pack:{pack_name} @{digest:016x} ({}B)]\n",
                body.len()
            ));
        }
    }
    let mut final_out = String::with_capacity(body.len() + 96);
    final_out.push_str(&format!(
        "[pack:{pack_name} @{digest:016x}, {resolved_ok}/{} section(s){}]\n",
        selectors.len(),
        if raw { ", raw" } else { ", compact" }
    ));
    final_out.push_str(&body);
    Ok(final_out)
}

enum PackAnchor<'a> {
    Symbol(&'a str),
    Lines(usize, usize),
    Whole,
}

fn parse_pack_selector(sel: &str) -> Option<(&str, PackAnchor<'_>)> {
    let t = sel.trim();
    if t.is_empty() {
        return None;
    }
    if let Some((p, sym)) = t.split_once('#') {
        let sym = sym.trim();
        if !p.trim().is_empty() && !sym.is_empty() {
            return Some((p.trim(), PackAnchor::Symbol(sym)));
        }
    }
    if let Some((p, range)) = t.rsplit_once(':') {
        if let Some((s, e)) = range.split_once('-') {
            if let (Ok(sn), Ok(en)) = (s.trim().parse::<usize>(), e.trim().parse::<usize>()) {
                if sn >= 1 && en >= sn && !p.trim().is_empty() {
                    return Some((p.trim(), PackAnchor::Lines(sn, en)));
                }
            }
        }
    }
    Some((t, PackAnchor::Whole))
}

pub fn op_status(svc: &BrokerService) -> Json {
    let capsules = svc.broker.capsules.status();
    let used = svc.store.used_ram_bytes.load(Ordering::Relaxed);
    let wmode = crate::base::mode::current_write_mode(None);
    Json::obj(vec![
        (
            "build_flavor",
            Json::Str(crate::base::ext::policy().build_flavor().to_string()),
        ),
        ("write_enabled", Json::Bool(wmode.enabled)),
        (
            "write_mode_source",
            Json::Str(wmode.source.as_str().to_string()),
        ),
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
