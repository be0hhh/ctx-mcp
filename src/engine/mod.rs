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
#[allow(unused_imports)]
pub use search::{
    cap_text, op_search, op_search_batch, parse_shorthand_search_spec, SearchError, SearchOptions,
    CLI_BATCH_SEARCH_BYTES, MAX_CLI_SEARCH_RESPONSE_BYTES, SEARCH_RESPONSE_BYTES,
};
#[allow(unused_imports)]
pub use symbols::{op_symbols, op_symbols_with_options};

use crate::base::json::Json;
use crate::base::security::{admit_file_in_workspace, is_sensitive_path};
use crate::broker::{contains_known_secret, MemoFileLink};
use crate::rpc::BrokerService;
use crate::store::{
    is_multimodal_or_binary_ext, resolve_input_path, shared_repo_key, should_skip_dir,
    MAX_SINGLE_FILE_CACHE_BYTES,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

pub const DEFAULT_READ_MAX_BYTES: usize = 1_048_576; // 1 MiB
pub const AGY_MCP_DEFAULT_MAX_BYTES: usize = 9_000; // Fits under Antigravity's ~10 KB MCP inline cap
pub const AGY_MCP_INLINE_CAP: usize = 9_200;
pub const AGY_CLI_DEFAULT_MAX_BYTES: usize = 9_200; // Fits under Antigravity's ~10,240 B run_command inline cap (incl. wrapper + PTY CRLF)
pub const AGY_CLI_INLINE_CAP: usize = 9_600;
const _: () = assert!(AGY_CLI_INLINE_CAP > AGY_MCP_INLINE_CAP);

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
        None,
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
    limit: Option<usize>,
    cwd: Option<&Path>,
) -> Result<Json, String> {
    let base = cwd
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let ws_root = svc
        .allowlist
        .register_hint(&base, false)
        .ok_or_else(|| "cannot resolve workspace root for memo".to_string())?;
    let ws_norm = shared_repo_key(&ws_root);

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
                    rel_path: rel.replace('\\', "/"),
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
            let eff_limit = limit.unwrap_or(30).clamp(1, 200);
            let (head, all_events) = svc.broker.changes.changes_since(&ws_norm, since_seq, 1024);
            let tail_start = all_events.len().saturating_sub(eff_limit);
            let mut omitted_older = tail_start;
            let cap = max_bytes.max(256);
            let mut rows = match crate::broker::change_feed::ChangeFeed::to_json(
                head,
                &all_events[tail_start..],
            ) {
                Json::Obj(fields) => fields
                    .into_iter()
                    .find_map(|(k, v)| match (k.as_ref(), v) {
                        ("events", Json::Arr(arr)) => Some(arr),
                        _ => None,
                    })
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            let row_lens: Vec<usize> = rows.iter().map(|r| r.to_json_string().len()).collect();
            let mut body_bytes: usize = row_lens
                .iter()
                .sum::<usize>()
                .saturating_add(row_lens.len().saturating_sub(1));
            let head_digits =
                crate::base::simd::decimal_digits(usize::try_from(head).unwrap_or(usize::MAX));
            let exact_len = |body: usize, omitted: usize| -> usize {
                let base = 25usize.saturating_add(head_digits).saturating_add(body);
                if omitted > 0 {
                    base.saturating_add(17)
                        .saturating_add(crate::base::simd::decimal_digits(omitted))
                } else {
                    base
                }
            };
            let mut drop_n = 0usize;
            while drop_n < row_lens.len() && exact_len(body_bytes, omitted_older) > cap {
                body_bytes = body_bytes.saturating_sub(row_lens[drop_n]);
                if drop_n + 1 < row_lens.len() {
                    body_bytes = body_bytes.saturating_sub(1);
                }
                drop_n += 1;
                omitted_older += 1;
            }
            if drop_n > 0 {
                rows.drain(..drop_n);
            }
            let build_doc = |ev_rows: Vec<Json>, omitted: usize| -> Json {
                let mut fields = vec![
                    (std::borrow::Cow::Borrowed("head_seq"), Json::Int(head as i64)),
                    (std::borrow::Cow::Borrowed("events"), Json::Arr(ev_rows)),
                ];
                if omitted > 0 {
                    fields.push((
                        std::borrow::Cow::Borrowed("omitted_older"),
                        Json::Int(omitted as i64),
                    ));
                }
                Json::Obj(fields)
            };
            let mut payload = build_doc(rows, omitted_older);
            while payload.to_json_string().len() > cap {
                let Json::Obj(mut fields) = payload else {
                    break;
                };
                let Some(mut ev_rows) = fields.iter_mut().find_map(|(k, v)| {
                    if k.as_ref() == "events" {
                        match std::mem::replace(v, Json::Null) {
                            Json::Arr(arr) => Some(arr),
                            other => {
                                *v = other;
                                None
                            }
                        }
                    } else {
                        None
                    }
                }) else {
                    payload = Json::Obj(fields);
                    break;
                };
                if ev_rows.is_empty() {
                    payload = build_doc(ev_rows, omitted_older);
                    break;
                }
                ev_rows.remove(0);
                omitted_older += 1;
                payload = build_doc(ev_rows, omitted_older);
            }
            Ok(Json::obj(vec![("changes", payload)]))
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
    let ws_norm = shared_repo_key(ws_root);
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

    let format_rem_note = |rem_sels: &[String]| -> String {
        if rem_sels.is_empty() {
            return "... [truncated at max_bytes]\n".to_string();
        }
        let mut list = String::new();
        let mut shown = 0usize;
        for sel in rem_sels.iter().take(4) {
            let sep_len = if shown > 0 { 2 } else { 0 };
            if shown > 0 && list.len() + sep_len + sel.len() > 140 {
                break;
            }
            if shown > 0 {
                list.push_str(", ");
            }
            if sel.len() > 140 {
                let mut end = 140;
                while end > 0 && !sel.is_char_boundary(end) {
                    end -= 1;
                }
                list.push_str(&sel[..end]);
                list.push_str("...");
            } else {
                list.push_str(sel);
            }
            shown += 1;
        }
        let hidden = rem_sels.len().saturating_sub(shown);
        if hidden > 0 {
            format!("... [truncated at max_bytes; remaining: {list} (+{hidden} more) — fetch via ctx_symbols]\n")
        } else {
            format!("... [truncated at max_bytes; remaining: {list} — fetch via ctx_symbols]\n")
        }
    };

    // Reserve room for the `[pack:...]` header (~96B) plus the capped truncation footer (~224B).
    let body_cap = budget.saturating_sub(320).max(512);
    let mut resolved_ok = 0usize;
    for (idx, sel) in selectors.iter().enumerate() {
        if body.len() >= body_cap {
            body.push_str(&format_rem_note(&selectors[idx..]));
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
        let Some(full_text) = entry.content() else {
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
        let avail = body_cap.saturating_sub(body.len());
        if header.len() >= avail {
            body.push_str(&format_rem_note(&selectors[idx..]));
            break;
        }
        body.push_str(&header);
        let rem = avail.saturating_sub(header.len());
        if rendered.len() <= rem {
            body.push_str(&rendered);
            if !rendered.ends_with('\n') {
                body.push('\n');
            }
            resolved_ok += 1;
        } else {
            let mut cut = rem;
            while cut > 0 && !rendered.is_char_boundary(cut) {
                cut -= 1;
            }
            body.push_str(&rendered[..cut]);
            if !body.ends_with('\n') {
                body.push('\n');
            }
            body.push_str(&format_rem_note(&selectors[idx + 1..]));
            resolved_ok += 1;
            break;
        }
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
    let used = svc.store.used_ram_bytes();
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

#[cfg(test)]
mod pack_cap_tests {
    use super::*;
    use crate::rpc::execute_request;
    use std::fs;

    #[test]
    fn pack_get_and_agy_cli_outline_strictly_stay_within_budget() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-pack-outline-cap-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        let deep = dir.join("src/module_alpha/subsystem_beta/component_gamma");
        fs::create_dir_all(&deep).unwrap();
        let mut selectors = Vec::new();
        for i in 0..16 {
            let fname = format!("long_component_handler_{i:02}.rs");
            let mut body = String::new();
            for j in 0..60 {
                body.push_str(&format!(
                    "pub fn handle_event_{i:02}_{j:02}(val: u64) -> u64 {{ val.wrapping_add({j}) }}\n"
                ));
            }
            fs::write(deep.join(&fname), &body).unwrap();
            selectors.push(format!(
                "src/module_alpha/subsystem_beta/component_gamma/{fname}:1-60"
            ));
        }

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        let ws = svc.allowlist.register_hint(&dir, true).unwrap();
        let ws_key = crate::store::paths::shared_repo_key(&ws);
        svc.broker
            .packs
            .put_pack(&ws_key, "big-pack", selectors, Some("Big pack".into()), "test")
            .unwrap();

        let rendered = materialize_pack_for_workspace(
            &svc,
            &ws,
            "big-pack",
            Some("agy:test-pack"),
            false,
            false,
            AGY_CLI_DEFAULT_MAX_BYTES,
        )
        .unwrap();
        assert!(
            rendered.len() <= AGY_CLI_DEFAULT_MAX_BYTES,
            "pack_get exceeded budget: {} > {}",
            rendered.len(),
            AGY_CLI_DEFAULT_MAX_BYTES
        );
        assert_eq!(
            rendered.matches("truncated at max_bytes").count(),
            1,
            "duplicate truncation note in:\n{rendered}"
        );

        let tok = svc
            .broker
            .capsules
            .issue_cli_lease("agy:outline-worker".into(), ws.clone())
            .unwrap();
        let outline_req = Json::obj(vec![
            ("op", Json::Str("outline".into())),
            ("cwd", Json::Str(ws.to_string_lossy().into_owned())),
            ("paths", Json::Arr(vec![Json::Str("src".into())])),
            ("cli_token", Json::Str(tok)),
        ]);
        let outline_res = execute_request(&svc, &outline_req);
        assert_eq!(outline_res.get_bool("ok"), Some(true), "{outline_res:?}");
        let outline_txt = outline_res.get_str("text").unwrap();
        assert!(
            outline_txt.len() <= AGY_CLI_DEFAULT_MAX_BYTES + 128,
            "agy cli outline exceeded budget: {}",
            outline_txt.len()
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn memo_changes_enforces_limit_tail_selection_since_seq_and_strict_max_bytes() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-memo-changes-cap-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir_all(&dir).unwrap();
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        let ws = svc.allowlist.register_hint(&dir, true).unwrap();
        let ws_key = crate::store::paths::shared_repo_key(&ws);

        for i in 1..=50u64 {
            svc.broker.changes.record_change(
                &ws_key,
                &format!("src/subsystem_alpha/component_beta/handler_module_{i:03}.rs"),
                vec![
                    format!("@handle_request_entry_{i:03}"),
                    format!("@validate_payload_frame_{i:03}"),
                    format!("@commit_state_transition_{i:03}"),
                ],
                "agy:worker-changes-test-0123456789abcdef",
                1_700_000_000_000 + i,
            );
        }

        // 1. Default limit (30) returns newest tail (21..=50) with omitted_older=20.
        let def_res = op_memo_full(
            &svc,
            "changes",
            "0",
            "",
            None,
            None,
            None,
            &[],
            false,
            false,
            65_536,
            None,
            Some(&ws),
        )
        .unwrap();
        let def_doc = def_res.get("changes").unwrap();
        let def_evs = def_doc.get("events").and_then(Json::as_arr).unwrap();
        assert_eq!(def_doc.get_i64("head_seq"), Some(50));
        assert_eq!(def_evs.len(), 30);
        assert_eq!(def_evs.first().and_then(|e| e.get_i64("seq")), Some(21));
        assert_eq!(def_evs.last().and_then(|e| e.get_i64("seq")), Some(50));
        assert_eq!(def_doc.get_i64("omitted_older"), Some(20));

        // 2. When all events after since_seq fit within limit & max_bytes, omitted_older is absent.
        let since_res = op_memo_full(
            &svc,
            "changes",
            "40",
            "",
            None,
            None,
            None,
            &[],
            false,
            false,
            65_536,
            None,
            Some(&ws),
        )
        .unwrap();
        let since_doc = since_res.get("changes").unwrap();
        let since_evs = since_doc.get("events").and_then(Json::as_arr).unwrap();
        assert_eq!(since_evs.len(), 10);
        assert_eq!(since_evs.first().and_then(|e| e.get_i64("seq")), Some(41));
        assert!(since_doc.get("omitted_older").is_none());

        // 3. Explicit limit=5 with since_seq=30 takes tail (46..=50), omitted_older=15.
        let lim_res = op_memo_full(
            &svc,
            "changes",
            "30",
            "",
            None,
            None,
            None,
            &[],
            false,
            false,
            65_536,
            Some(5),
            Some(&ws),
        )
        .unwrap();
        let lim_doc = lim_res.get("changes").unwrap();
        let lim_evs = lim_doc.get("events").and_then(Json::as_arr).unwrap();
        assert_eq!(lim_evs.len(), 5);
        assert_eq!(lim_evs.first().and_then(|e| e.get_i64("seq")), Some(46));
        assert_eq!(lim_doc.get_i64("omitted_older"), Some(15));

        // 4. limit=0 clamps to 1 (newest event seq=50, omitted_older=49).
        let zero_res = op_memo_full(
            &svc,
            "changes",
            "0",
            "",
            None,
            None,
            None,
            &[],
            false,
            false,
            65_536,
            Some(0),
            Some(&ws),
        )
        .unwrap();
        let zero_doc = zero_res.get("changes").unwrap();
        let zero_evs = zero_doc.get("events").and_then(Json::as_arr).unwrap();
        assert_eq!(zero_evs.len(), 1);
        assert_eq!(zero_evs[0].get_i64("seq"), Some(50));
        assert_eq!(zero_doc.get_i64("omitted_older"), Some(49));

        // 5. Strict max_bytes cap (AGY CLI 9200B & tight 2000B & ultra-tight 256B) produces valid JSON <= cap.
        for cap in [AGY_CLI_DEFAULT_MAX_BYTES, AGY_MCP_DEFAULT_MAX_BYTES, 2_000, 256] {
            let capped = op_memo_full(
                &svc,
                "changes",
                "0",
                "",
                None,
                None,
                None,
                &[],
                false,
                false,
                cap,
                Some(200),
                Some(&ws),
            )
            .unwrap();
            let doc = capped.get("changes").unwrap();
            let raw = doc.to_json_string();
            assert!(
                raw.len() <= cap,
                "changes JSON exceeded cap={cap}: len={}",
                raw.len()
            );
            let parsed = crate::base::json::parse(&raw).expect("valid JSON");
            let evs = parsed.get("events").and_then(Json::as_arr).unwrap();
            let omitted = parsed.get_i64("omitted_older").unwrap_or(0) as usize;
            assert_eq!(evs.len() + omitted, 50, "cap={cap}");
            if let Some(last) = evs.last() {
                assert_eq!(last.get_i64("seq"), Some(50), "must retain newest tail");
            }
            if cap == 256 {
                assert!(evs.is_empty() && omitted == 50, "cap=256: {raw}");
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
