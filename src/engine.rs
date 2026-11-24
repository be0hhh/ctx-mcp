//! Core concurrent context operations over `BrokerService`:
//!   - `op_inspect` (batch directory/slice triage: lines, size flags, namespaces, includes, symbols)
//!   - `op_read` (up to 1 MiB without 800-line truncation)
//!   - `op_outline` (fast structural outline, served from `ACTXSNP2` metadata when unchanged)
//!   - `op_symbols` (`path#Symbol` extraction)
//!   - `op_search` (bounded `SubprocSemaphore(8)` `rg` + pure-Rust fallback, workspace-relative paths)
//!   - `op_memo` (`put | get | list | clear` with automatic `[STALE]` verification)
//!   - `op_elf_audit` and `op_status`.

use crate::broker::MemoFileLink;
use crate::json::Json;
use crate::parser::{SymbolKind, SymbolSpan};
use crate::protocol::BrokerService;
use crate::security::is_sensitive_path;
use crate::simd::{push_u32, push_usize, search_lines_literals};
use crate::store::{
    display_workspace_path, is_multimodal_or_binary_ext, norm_key_from_canon, resolve_input_path,
    CachedFile, MissingResolution, RamStore, MAX_SINGLE_FILE_CACHE_BYTES,
};
use std::fs;
use std::io::{self, BufRead, BufReader, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_READ_MAX_BYTES: usize = 1_048_576; // 1 MiB

pub fn parse_path_slice_spec(spec: &str) -> (&str, Option<(usize, usize)>) {
    let trimmed = spec.trim();
    if let Some(colon_idx) = trimmed.rfind(':') {
        if colon_idx > 1 {
            let tail = &trimmed[colon_idx + 1..];
            if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit() || c == '-') {
                let path_part = &trimmed[..colon_idx];
                if let Some((a, b)) = tail.split_once('-') {
                    if let (Ok(s), Ok(e)) = (a.parse::<usize>(), b.parse::<usize>()) {
                        return (path_part, Some((s.max(1), e.max(s.max(1)))));
                    }
                } else if let Ok(line) = tail.parse::<usize>() {
                    let s = line.saturating_sub(20).max(1);
                    let e = line.saturating_add(40);
                    return (path_part, Some((s, e)));
                }
            }
        }
    }
    (trimmed, None)
}

pub fn op_read(
    svc: &BrokerService,
    specs: &[String],
    max_bytes: usize,
    force: bool,
    session_key: Option<&str>,
    cwd: Option<&Path>,
) -> Result<String, String> {
    if specs.is_empty() {
        return Err("provide at least one file path".to_string());
    }
    let budget = max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES << 1);
    let mut out = String::new();
    let mut any_ok = false;

    for (index, spec) in specs.iter().enumerate() {
        let (raw_p, slice) = parse_path_slice_spec(spec);
        let resolved = resolve_input_path(raw_p, cwd);
        if is_sensitive_path(&resolved) {
            out.push_str(&format!("=== {} [REFUSED: sensitive path] ===\n", raw_p));
            continue;
        }
        if !resolved.exists() {
            let mut hint_note = String::new();
            if let Some(ws_root) = cwd.and_then(|c| svc.allowlist.register_hint(c, false)) {
                match svc.store.resolve_missing_path(&resolved, &ws_root) {
                    MissingResolution::Unique(real) => {
                        hint_note = format!(
                            " (moved to `{}`)",
                            display_workspace_path(&real, Some(&ws_root))
                        );
                    }
                    MissingResolution::Ambiguous(cands) => {
                        let rels: Vec<String> = cands
                            .iter()
                            .take(5)
                            .map(|p| display_workspace_path(p, Some(&ws_root)))
                            .collect();
                        hint_note = format!(" (candidates: {})", rels.join(", "));
                    }
                    MissingResolution::NotFound => {}
                }
            }
            out.push_str(&format!(
                "=== {} [ERROR: file does not exist{}] ===\n",
                raw_p, hint_note
            ));
            continue;
        }

        let (canon, ws_root) = match svc.allowlist.admit_file(&resolved, cwd) {
            Ok(pair) => pair,
            Err(msg) => {
                out.push_str(&format!("=== {} [{}] ===\n", raw_p, msg));
                continue;
            }
        };

        let meta = match fs::metadata(&canon) {
            Ok(m) if m.is_file() => m,
            Ok(_) => {
                out.push_str(&format!(
                    "=== {} [ERROR: is a directory; use `ctx outline`] ===\n",
                    raw_p
                ));
                continue;
            }
            Err(e) => {
                out.push_str(&format!("=== {} [ERROR: {}] ===\n", raw_p, e));
                continue;
            }
        };

        if !force {
            if let Some(sk) = session_key {
                let (rs, re) = match slice {
                    Some((s, e)) => (Some(s), Some(e)),
                    None => (None, None),
                };
                if let Some(dup) =
                    svc.store
                        .check_duplicate_read(sk, &canon, Some(&ws_root), rs, re)
                {
                    any_ok = true;
                    out.push_str(&format!(
                        "=== {} [ALREADY IN CONTEXT: lines {}-{} of {} unchanged; pass --force to reload] ===\nOutline: {}\n\n",
                        dup.rel_path,
                        dup.covered_start,
                        dup.covered_end,
                        dup.total_lines,
                        dup.outline_summary
                    ));
                    continue;
                }
            }
        }

        if meta.len() as usize > MAX_SINGLE_FILE_CACHE_BYTES {
            let rel = display_workspace_path(&canon, Some(&ws_root));
            if let Some((s, e)) = slice {
                let remain = budget.saturating_sub(out.len());
                if remain < 256 {
                    out.push_str("... [batch max_bytes reached]\n");
                    break;
                }
                match RamStore::stream_large_slice(&canon, s, e, remain) {
                    Ok((text, actual_s, actual_e)) => {
                        any_ok = true;
                        out.push_str(&format!(
                            "=== {} (lines {}-{}, large file {}B) ===\n{}\n",
                            rel,
                            actual_s,
                            actual_e,
                            meta.len(),
                            text
                        ));
                    }
                    Err(err) => out.push_str(&format!("=== {} [ERROR: {}] ===\n", rel, err)),
                }
            } else {
                out.push_str(&format!(
                    "=== {} [FILE > 1 MiB ({} bytes): pass explicit slice {}:1-400] ===\n",
                    rel,
                    meta.len(),
                    rel
                ));
            }
            continue;
        }

        match svc.store.get_full_entry(&canon, Some(&ws_root)) {
            Ok(entry) => {
                any_ok = true;
                let total = (entry.line_count as usize).max(1);
                let (s, e) = match slice {
                    Some((a, b)) => (a.min(total).max(1), b.min(total).max(1)),
                    None => (1, total),
                };

                let cap_note = format!(
                    "... [output capped at {budget} bytes; {} later paths left unread]\n",
                    specs.len() - index - 1
                );
                let content_limit = budget - cap_note.len() - 1;
                let approx_cap = (entry.size_bytes as usize + (e - s + 2) * 8).min(budget);
                let mut section = String::with_capacity(approx_cap.max(128));
                section.push_str("=== ");
                section.push_str(&entry.rel_path);
                section.push_str(" (lines ");
                push_usize(&mut section, s);
                section.push('-');
                push_usize(&mut section, e);
                section.push_str(" of ");
                push_usize(&mut section, total);
                section.push_str(", ");
                push_u32(&mut section, entry.size_bytes);
                section.push_str("B) ===\n");

                if out.len() + section.len() > content_limit {
                    out.push_str(&format!(
                        "... [output capped at {budget} bytes; {} paths left unread]\n",
                        specs.len() - index
                    ));
                    break;
                }
                let mut actual_end = None;
                let mut clipped = false;
                let max_present = entry.line_count as usize;
                for ln in s..=e {
                    if ln == 0 || ln > max_present {
                        break;
                    }
                    let line = entry.line_slice(ln as u32);
                    let row_len = decimal_digits(ln) + 2 + line.len() + 1;
                    if out.len() + section.len() + row_len > content_limit {
                        section.push_str(&cap_note);
                        clipped = true;
                        break;
                    }
                    push_usize(&mut section, ln);
                    section.push_str(": ");
                    section.push_str(line);
                    section.push('\n');
                    actual_end = Some(ln);
                }
                section.push('\n');
                out.push_str(&section);
                if let (Some(sk), Some(actual_end)) = (session_key, actual_end) {
                    svc.store
                        .record_read(sk, &canon, Some(&ws_root), s, actual_end);
                }
                if clipped {
                    break;
                }
            }
            Err(err) => {
                out.push_str(&format!("=== {} [ERROR: {}] ===\n", raw_p, err));
            }
        }

        if out.len() >= budget {
            break;
        }
    }
    if !any_ok {
        return Err(out.trim().to_string());
    }
    Ok(out)
}

#[inline]
fn decimal_digits(mut n: usize) -> usize {
    let mut d = 1usize;
    while n >= 10 {
        n /= 10;
        d += 1;
    }
    d
}

fn is_safe_shorthand_candidate(raw: &str) -> bool {
    let t = raw.trim().trim_matches('"').trim_matches('\'');
    !t.is_empty()
        && !t.starts_with('/')
        && !t.starts_with('\\')
        && !t.starts_with("~/")
        && !t.contains("..")
        && !(t.len() >= 2 && t.as_bytes()[1] == b':')
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
        if !p.exists() && !Path::new(cleaned).is_absolute() {
            if let Some(ws_root) = cwd.and_then(|c| svc.allowlist.register_hint(c, false)) {
                let alt1 = ws_root.join("src").join("src").join(cleaned);
                let alt2 = ws_root.join("src").join(cleaned);
                if alt1.exists() {
                    p = alt1;
                } else if alt2.exists() {
                    p = alt2;
                } else if is_safe_shorthand_candidate(cleaned) {
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

fn should_skip_dir(name: &str) -> bool {
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

pub fn op_outline(
    svc: &BrokerService,
    targets: &[String],
    max_files: usize,
    max_bytes: usize,
    cwd: Option<&Path>,
) -> Result<String, String> {
    if targets.is_empty() {
        return Err("provide at least one file or directory path".to_string());
    }
    let cap = max_files.clamp(1, 200);
    let files = collect_target_files(svc, targets, cwd, cap)?;
    if files.is_empty() {
        return Ok("No matching readable text source files found.".to_string());
    }

    let many_files = files.len() > 10;
    let budget = if max_bytes > 0 {
        max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES)
    } else if many_files {
        9_500
    } else {
        65_536
    };
    let sym_cap = if many_files { 12 } else { 80 };

    let mut out = String::with_capacity(budget.min(8192));
    let total_files = files.len();
    for (idx, (file, ws_root)) in files.into_iter().enumerate() {
        let mut block = String::with_capacity(256);
        match svc.store.get_outline_entry(&file, Some(&ws_root)) {
            Ok(entry) => {
                block.push_str("## ");
                block.push_str(&entry.rel_path);
                block.push_str(" (");
                push_u32(&mut block, entry.line_count);
                block.push_str(" lines, ");
                push_u32(&mut block, entry.size_bytes);
                block.push_str(" bytes)\n");
                if entry.symbols.is_empty() {
                    block.push_str("  (no structural symbols extracted)\n");
                } else {
                    for sym in entry.symbols.iter().take(sym_cap) {
                        block.push_str("  [L");
                        push_u32(&mut block, sym.start_line);
                        block.push_str("-L");
                        push_u32(&mut block, sym.end_line);
                        block.push_str("] ");
                        block.push_str(sym.kind.as_str());
                        block.push(' ');
                        block.push_str(&sym.name);
                        if !many_files && !sym.signature.is_empty() {
                            block.push_str(" — ");
                            block.push_str(&sym.signature);
                        }
                        block.push('\n');
                    }
                    if entry.symbols.len() > sym_cap {
                        block.push_str("  ... +");
                        push_usize(&mut block, entry.symbols.len() - sym_cap);
                        block.push_str(" more symbols\n");
                    }
                }
            }
            Err(err) => {
                block.push_str(&format!(
                    "## {} [skip: {}]\n",
                    display_workspace_path(&file, Some(&ws_root)),
                    err
                ));
            }
        }
        if !out.is_empty() && out.len() + block.len() + 96 > budget {
            out.push_str(&format!(
                "... (+{} more files omitted at {}B budget; use `ctx_inspect` for multi-folder triage)\n",
                total_files - idx,
                budget
            ));
            break;
        }
        out.push_str(&block);
    }
    Ok(out)
}

fn compact_include_label(raw: &str) -> String {
    let norm_owned: String;
    let clean: &str = if raw.contains('\\') {
        norm_owned = raw.replace('\\', "/");
        &norm_owned
    } else {
        raw
    };
    let mut rev_parts = clean.split('/').filter(|s| !s.is_empty()).rev();
    let Some(last) = rev_parts.next() else {
        return String::new();
    };
    if let Some(prev) = rev_parts.next() {
        let mut s = String::with_capacity(prev.len() + 1 + last.len());
        s.push_str(prev);
        s.push('/');
        s.push_str(last);
        s
    } else {
        last.to_string()
    }
}

fn extract_header_facts(entry: &CachedFile) -> (Vec<String>, Vec<String>) {
    let mut namespaces: Vec<String> = Vec::new();
    let mut local_inc: Vec<String> = Vec::new();
    let mut sys_inc: Vec<String> = Vec::new();
    let scan_lines = entry.line_count.min(300);

    for ln in 1..=scan_lines {
        let trimmed = entry.line_slice(ln).trim();
        if let Some(rest) = trimmed.strip_prefix("#include") {
            let after = rest.trim_start();
            if let Some(q) = after.strip_prefix('"') {
                if let Some((inc, _)) = q.split_once('"') {
                    let lbl = compact_include_label(inc);
                    if !lbl.is_empty() && !local_inc.contains(&lbl) && local_inc.len() < 24 {
                        local_inc.push(lbl);
                    }
                }
            } else if let Some(a) = after.strip_prefix('<') {
                if let Some((inc, _)) = a.split_once('>') {
                    let inner = compact_include_label(inc);
                    let mut lbl = String::with_capacity(inner.len() + 2);
                    lbl.push('<');
                    lbl.push_str(&inner);
                    lbl.push('>');
                    if !sys_inc.contains(&lbl) && sys_inc.len() < 12 {
                        sys_inc.push(lbl);
                    }
                }
            }
            continue;
        }
        if namespaces.len() < 2 {
            if let Some(rest) = trimmed.strip_prefix("namespace ") {
                if !rest.contains('=') {
                    let after = rest.trim_start();
                    let nlen = after
                        .bytes()
                        .take_while(|&b| b.is_ascii_alphanumeric() || b == b':' || b == b'_')
                        .count();
                    let ns = &after[..nlen];
                    if !ns.is_empty()
                        && ns != "detail"
                        && !ns.ends_with("_detail")
                        && !ns.ends_with("::detail")
                        && !namespaces.iter().any(|existing| existing == ns)
                    {
                        namespaces.push(ns.to_string());
                    }
                }
            }
        }
    }
    local_inc.extend(sys_inc);
    (namespaces, local_inc)
}

pub fn op_inspect(
    svc: &BrokerService,
    targets: &[String],
    max_files: usize,
    max_bytes: usize,
    warn_lines: usize,
    cwd: Option<&Path>,
) -> Result<String, String> {
    if targets.is_empty() {
        return Err("provide at least one file or directory path".to_string());
    }
    let cap = max_files.clamp(1, 250);
    let budget = max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES);
    let warn_l = warn_lines.clamp(50, 50_000);
    let files = collect_target_files(svc, targets, cwd, cap)?;
    if files.is_empty() {
        return Ok("No matching readable text source files found.".to_string());
    }

    struct InspectItem {
        entry: std::sync::Arc<crate::store::CachedFile>,
        namespaces: Vec<String>,
        includes: Vec<String>,
    }

    let mut items: Vec<InspectItem> = Vec::with_capacity(files.len());
    let mut skipped: Vec<String> = Vec::new();

    for (file, ws_root) in files {
        match svc.store.get_full_entry(&file, Some(&ws_root)) {
            Ok(entry) => {
                let (namespaces, includes) = extract_header_facts(&entry);
                items.push(InspectItem {
                    entry,
                    namespaces,
                    includes,
                });
            }
            Err(err) => {
                skipped.push(format!(
                    "{} [skip: {}]",
                    display_workspace_path(&file, Some(&ws_root)),
                    err
                ));
            }
        }
    }

    let mut flagged: Vec<(usize, &str)> = items
        .iter()
        .filter(|it| (it.entry.line_count as usize) >= warn_l)
        .map(|it| (it.entry.line_count as usize, &*it.entry.rel_path))
        .collect();
    flagged.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));

    let mut out = String::with_capacity(budget.min(8192));
    if flagged.is_empty() {
        out.push_str(&format!(
            "=== Slice Inspect: {} files (0 >= {}L) ===\n",
            items.len(),
            warn_l
        ));
    } else {
        let mut top_flags: Vec<String> = flagged
            .iter()
            .take(10)
            .map(|(lc, path)| {
                if *lc > 800 {
                    format!("{} ({}L [OVER 800L])", path, lc)
                } else {
                    format!("{} ({}L)", path, lc)
                }
            })
            .collect();
        if flagged.len() > 10 {
            top_flags.push(format!("+{} more", flagged.len() - 10));
        }
        out.push_str(&format!(
            "=== Slice Inspect: {} files ({} >= {}L: {}) ===\n",
            items.len(),
            flagged.len(),
            warn_l,
            top_flags.join(", ")
        ));
    }

    let sym_show = if items.len() > 35 { 4 } else { 6 };
    let inc_show = if items.len() > 35 { 4 } else { 6 };

    for (idx, it) in items.iter().enumerate() {
        let lc = it.entry.line_count as usize;
        let mut row = String::with_capacity(224);
        row.push_str("- ");
        row.push_str(&it.entry.rel_path);
        row.push_str(" (");
        push_usize(&mut row, lc);
        row.push_str("L, ");
        push_u32(&mut row, it.entry.size_bytes);
        row.push('B');
        row.push(')');
        if lc > 800 {
            row.push_str(" [OVER 800L]");
        } else if lc >= warn_l {
            row.push_str(" [>=");
            push_usize(&mut row, warn_l);
            row.push_str("L]");
        }
        if !it.namespaces.is_empty() {
            row.push_str(" | ns: ");
            for (i, ns) in it.namespaces.iter().enumerate() {
                if i > 0 {
                    row.push_str(", ");
                }
                row.push_str(ns);
            }
        }
        if !it.includes.is_empty() {
            row.push_str(" | inc: ");
            for (i, inc) in it.includes.iter().take(inc_show).enumerate() {
                if i > 0 {
                    row.push_str(", ");
                }
                row.push_str(inc);
            }
            if it.includes.len() > inc_show {
                row.push_str(" (+");
                push_usize(&mut row, it.includes.len() - inc_show);
                row.push(')');
            }
        }
        if !it.entry.symbols.is_empty() {
            let has_primary = it
                .entry
                .symbols
                .iter()
                .any(|s| s.kind != SymbolKind::Namespace && s.kind != SymbolKind::Using);
            let mut count_matching = 0usize;
            for s in it.entry.symbols.iter() {
                let keep = if has_primary {
                    s.kind != SymbolKind::Namespace && s.kind != SymbolKind::Using
                } else {
                    s.kind != SymbolKind::Namespace
                };
                if !keep {
                    continue;
                }
                if count_matching == 0 {
                    row.push_str(" | ");
                } else if count_matching < sym_show {
                    row.push_str(", ");
                }
                if count_matching < sym_show {
                    row.push_str(s.kind.as_str());
                    row.push(' ');
                    row.push_str(&s.name);
                    row.push_str(" [L");
                    push_u32(&mut row, s.start_line);
                    row.push_str("-L");
                    push_u32(&mut row, s.end_line);
                    row.push(']');
                }
                count_matching += 1;
            }
            if count_matching > sym_show {
                row.push_str(" (+");
                push_usize(&mut row, count_matching - sym_show);
                row.push(')');
            }
        }
        row.push('\n');

        let reserve = if idx + 1 < items.len() { 96 } else { 0 };
        if out.len() + row.len() + reserve > budget {
            out.push_str(&format!(
                "... (+{} more files omitted at {}B budget; pass narrower paths or larger max_bytes)\n",
                items.len() - idx,
                budget
            ));
            return Ok(out);
        }
        out.push_str(&row);
    }

    for sk in skipped {
        let line = format!("- {}\n", sk);
        if out.len() + line.len() > budget {
            break;
        }
        out.push_str(&line);
    }

    Ok(out)
}

pub fn op_symbols(
    svc: &BrokerService,
    requests: &[String],
    max_bytes: usize,
    compact: bool,
    session_key: Option<&str>,
    cwd: Option<&Path>,
) -> Result<String, String> {
    if requests.is_empty() {
        return Err("provide at least one `path#SymbolName` request".to_string());
    }
    let budget = max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES);
    let cap_note = "... [truncated at max_bytes]\n";
    let limit = budget - cap_note.len();
    let mut out = String::new();
    let mut any_ok = false;

    for req in requests {
        if out.len() >= limit {
            if out.len() == limit {
                out.push_str(cap_note);
            }
            break;
        }
        let Some((raw_path, sym_query)) = req.split_once('#') else {
            out.push_str(&format!(
                "=== {} [ERROR: expected format path#SymbolName] ===\n",
                req
            ));
            continue;
        };
        let query = sym_query.trim();
        let mut resolved = resolve_input_path(raw_path, cwd);
        if !resolved.exists() && is_safe_shorthand_candidate(raw_path) && !is_sensitive_path(&resolved) {
            if let Some(ws_hint) = cwd.and_then(|c| svc.allowlist.register_hint(c, false)) {
                let alt1 = ws_hint.join("src").join("src").join(raw_path.trim());
                let alt2 = ws_hint.join("src").join(raw_path.trim());
                if alt1.is_file() {
                    resolved = alt1;
                } else if alt2.is_file() {
                    resolved = alt2;
                } else {
                    let found = svc.store.find_workspace_paths(raw_path, &ws_hint, 6);
                    if found.len() == 1 {
                        resolved = found.into_iter().next().unwrap();
                    } else if found.len() > 1 {
                        let colons_suffix = format!("::{}", query);
                        let mut matched_cand: Option<PathBuf> = None;
                        for cand in &found {
                            if let Ok((cf, wr)) = svc.allowlist.admit_file(cand, cwd) {
                                if let Ok(entry) = svc.store.get_outline_entry(&cf, Some(&wr)) {
                                    let has_sym = entry.symbols.iter().any(|s| {
                                        &*s.name == query
                                            || s.name.ends_with(&colons_suffix)
                                            || s.name.eq_ignore_ascii_case(query)
                                    });
                                    if has_sym {
                                        let is_impl = cf
                                            .extension()
                                            .and_then(|e| e.to_str())
                                            .is_some_and(|e| matches!(e, "cpp" | "cc" | "cxx" | "c"));
                                        if matched_cand.is_none() || is_impl {
                                            matched_cand = Some(cand.clone());
                                            if is_impl {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        resolved = matched_cand.unwrap_or_else(|| found.into_iter().next().unwrap());
                    }
                }
            }
        }
        let (canon, ws_root) = match svc.allowlist.admit_file(&resolved, cwd) {
            Ok(pair) => pair,
            Err(msg) => {
                out.push_str(&format!("=== {} [{}] ===\n", raw_path, msg));
                continue;
            }
        };

        match svc.store.get_full_entry(&canon, Some(&ws_root)) {
            Ok(entry) => {
                any_ok = true;
                let colons_suffix = format!("::{}", query);
                let matches: Vec<&SymbolSpan> = entry
                    .symbols
                    .iter()
                    .filter(|s| {
                        &*s.name == query
                            || s.name.ends_with(&colons_suffix)
                            || s.name.eq_ignore_ascii_case(query)
                    })
                    .collect();

                if matches.is_empty() {
                    let avail = RamStore::format_outline_compact(&entry, 15);
                    out.push_str(&format!(
                        "=== {}#{} [NOT FOUND] ===\nAvailable: {}\n\n",
                        entry.rel_path, query, avail
                    ));
                    continue;
                }

                let total_lines = entry.line_count as usize;
                let mut spans_to_record = Vec::new();
                let mut clipped = false;

                for sym in matches {
                    let s = (sym.start_line as usize).max(1);
                    let end = (sym.end_line as usize).min(total_lines);
                    let requested_end = if compact { end.min(s.saturating_add(23)) } else { end };
                    let header = |last: usize| {
                        let continuation = if last < end {
                            format!("; continue with {}:{}-{}", entry.rel_path, last + 1, end)
                        } else {
                            String::new()
                        };
                        format!(
                            "=== {}#{} ({} [L{}-L{}]{}) ===\n",
                            entry.rel_path,
                            sym.name,
                            sym.kind.as_str(),
                            s,
                            last,
                            continuation
                        )
                    };
                    let header_reserve = if end > s {
                        header(end - 1).len()
                    } else {
                        header(end).len()
                    };
                    let mut body = String::with_capacity((requested_end.saturating_sub(s) + 1) * 48);
                    let mut actual_end = None;
                    for ln in s..=requested_end {
                        let line = entry.line_slice(ln as u32);
                        let row_len = decimal_digits(ln) + 2 + line.len() + 1;
                        if out.len() + header_reserve + body.len() + row_len + 1 > limit {
                            break;
                        }
                        push_usize(&mut body, ln);
                        body.push_str(": ");
                        body.push_str(line);
                        body.push('\n');
                        actual_end = Some(ln);
                    }
                    if let Some(last) = actual_end {
                        out.push_str(&header(last));
                        out.push_str(&body);
                        out.push('\n');
                        spans_to_record.push((s, last));
                    }
                    if actual_end != Some(requested_end) {
                        out.push_str(cap_note);
                        clipped = true;
                        break;
                    }
                }

                if let Some(sk) = session_key {
                    for (s, e) in spans_to_record {
                        svc.store.record_read(sk, &canon, Some(&ws_root), s, e);
                    }
                }
                if clipped {
                    return Ok(out);
                }
            }
            Err(err) => {
                out.push_str(&format!("=== {} [ERROR: {}] ===\n", raw_path, err));
            }
        }
        if out.len() >= budget {
            break;
        }
    }
    if out.len() > limit {
        let mut end = limit;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push_str(cap_note);
    }
    if !any_ok {
        return Err(out.trim().to_string());
    }
    Ok(out)
}

#[derive(Debug)]
pub enum SearchError {
    Busy,
    Timeout,
    Failed(String),
}

const SEARCH_TIMEOUT: Duration = Duration::from_secs(5);
const SEARCH_RESPONSE_BYTES: usize = 8 * 1024;
const SEARCH_SNIPPET_CHARS: usize = 200;
const RG_RECORD_LIMIT: usize = 16 * 1024;
const RG_DIAGNOSTIC_LIMIT: usize = 4 * 1024;

struct SearchHit {
    path: PathBuf,
    workspace: PathBuf,
    line: usize,
    snippet: String,
}

struct SearchCollection<'a> {
    svc: &'a BrokerService,
    cwd: Option<&'a Path>,
    deadline: Instant,
    cap: usize,
    hits: Vec<SearchHit>,
}

fn search_time_left(deadline: Instant) -> Result<Duration, SearchError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(SearchError::Timeout)
}

fn search_snippet(text: &str) -> String {
    text.trim().chars().take(SEARCH_SNIPPET_CHARS).collect()
}

pub fn op_search(
    svc: &BrokerService,
    query: &str,
    roots: &[String],
    max_results: usize,
    with_scopes: bool,
    context_lines: usize,
    cwd: Option<&Path>,
) -> Result<String, SearchError> {
    if query.trim().is_empty() {
        return Err(SearchError::Failed("query must not be empty".to_string()));
    }
    let permit = svc
        .subproc_sem
        .try_acquire()
        .map_err(SearchError::Failed)?
        .ok_or(SearchError::Busy)?;
    let deadline = Instant::now() + SEARCH_TIMEOUT;
    let hits = collect_search_hits(svc, query, roots, max_results, cwd, deadline)?;
    drop(permit);
    if hits.is_empty() {
        return Ok(format!("0 matches for `{}`.", query.trim()));
    }
    if !with_scopes {
        return Ok(format_compact_search(svc, &hits, context_lines.min(4), SEARCH_RESPONSE_BYTES));
    }

    let matched_count = hits.len();
    let mut rows = String::with_capacity(matched_count * 96);
    for SearchHit { path, workspace, line, snippet } in hits {
        let scope_tag: String;
        let rel_disp = if let Ok(entry) = svc.store.get_outline_entry(&path, Some(&workspace)) {
            let enclosing = entry
                .symbols
                .iter()
                .filter(|s| {
                    (s.start_line as usize) <= line
                        && line <= (s.end_line as usize)
                        && s.kind != SymbolKind::Namespace
                })
                .min_by_key(|s| s.end_line.saturating_sub(s.start_line));
            scope_tag = if let Some(sym) = enclosing {
                format!(
                    " [in {} {} L{}-L{}, {}L]",
                    sym.kind.as_str(),
                    sym.name,
                    sym.start_line,
                    sym.end_line,
                    entry.line_count
                )
            } else {
                format!(" [{}L]", entry.line_count)
            };
            entry.rel_path.to_string()
        } else {
            scope_tag = String::new();
            display_workspace_path(&path, Some(&workspace))
        };
        rows.push_str(&rel_disp);
        rows.push(':');
        push_usize(&mut rows, line);
        rows.push_str(&scope_tag);
        rows.push_str(": ");
        rows.push_str(&snippet);
        rows.push('\n');
    }
    Ok(format!("Matches ({}):\n{}", matched_count, rows))
}

const IN_RAM_SEARCH_MAX_FILES: usize = 256;
const PER_FILE_SCAN_CANDIDATES: usize = 64;

fn is_plausible_root_spec(left: &str) -> bool {
    let trimmed = left.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut any_part = false;
    for raw_part in trimmed.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            return false;
        }
        any_part = true;
        for ch in part.chars() {
            if matches!(
                ch,
                ':' | ' ' | '\t' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '?' | '^' | '$' | '"'
            ) {
                return false;
            }
        }
    }
    any_part
}

/// Parses `"root1,root2:query"` shorthand while preserving C++ `::` (`Foo::bar` or `Mod:::globalFn`).
pub fn parse_shorthand_search_spec(
    raw: &str,
    require_root: bool,
) -> Result<(String, Vec<String>), SearchError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(SearchError::Failed("query must not be empty".to_string()));
    }
    let bytes = s.as_bytes();
    let mut split_at: Option<usize> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b':' {
            let is_win_drive = i == 1
                && bytes[0].is_ascii_alphabetic()
                && matches!(bytes.get(2), Some(b'/' | b'\\'));
            if is_win_drive {
                i += 1;
                continue;
            }
            if bytes.get(i..i + 3) == Some(b":::") {
                split_at = Some(i);
                break;
            }
            if bytes.get(i..i + 2) == Some(b"::") {
                // C++ `::` cannot appear inside a file/module root; stop scanning for a root prefix.
                break;
            }
            split_at = Some(i);
            break;
        }
        i += 1;
    }

    if let Some(colon_idx) = split_at {
        let left = &s[..colon_idx];
        if is_plausible_root_spec(left) {
            let query = s[colon_idx + 1..].trim();
            if query.is_empty() {
                return Err(SearchError::Failed("query must not be empty".to_string()));
            }
            let roots: Vec<String> = left
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
            return Ok((query.to_string(), roots));
        }
    }

    if require_root {
        return Err(SearchError::Failed(
            "shorthand batch item must be 'root:query'".to_string(),
        ));
    }
    Ok((s.to_string(), Vec::new()))
}

#[inline]
fn is_comment_only_line(snippet: &str) -> bool {
    let t = snippet.trim_start();
    t.starts_with("//")
        || t.starts_with("/*")
        || t.starts_with("*/")
        || t == "*"
        || t.starts_with("* ")
        || t.starts_with("*\t")
}

/// Zero-division round-robin quota across files, prioritizing code lines over comment-only lines
/// when total matches exceed `cap`, while preserving exact file order and ascending line numbers.
fn prioritize_and_balance_file_hits(per_file: Vec<Vec<SearchHit>>, cap: usize) -> Vec<SearchHit> {
    let total: usize = per_file.iter().map(Vec::len).sum();
    if total <= cap {
        let mut flat = Vec::with_capacity(total);
        for mut group in per_file {
            flat.append(&mut group);
        }
        return flat;
    }

    let file_count = per_file.len();
    let mut priority_orders: Vec<Vec<usize>> = Vec::with_capacity(file_count);
    let mut picked_masks: Vec<Vec<bool>> = Vec::with_capacity(file_count);

    for group in &per_file {
        let mut order = Vec::with_capacity(group.len());
        for (idx, hit) in group.iter().enumerate() {
            if !is_comment_only_line(&hit.snippet) {
                order.push(idx);
            }
        }
        for (idx, hit) in group.iter().enumerate() {
            if is_comment_only_line(&hit.snippet) {
                order.push(idx);
            }
        }
        priority_orders.push(order);
        picked_masks.push(vec![false; group.len()]);
    }

    let mut cursors = vec![0usize; file_count];
    let mut picked = 0usize;
    while picked < cap {
        let mut advanced = false;
        for f_idx in 0..file_count {
            let cur = cursors[f_idx];
            if cur < priority_orders[f_idx].len() {
                let hit_idx = priority_orders[f_idx][cur];
                cursors[f_idx] = cur + 1;
                picked_masks[f_idx][hit_idx] = true;
                picked += 1;
                advanced = true;
                if picked >= cap {
                    break;
                }
            }
        }
        if !advanced {
            break;
        }
    }

    let mut out = Vec::with_capacity(picked);
    for (f_idx, group) in per_file.into_iter().enumerate() {
        for (h_idx, hit) in group.into_iter().enumerate() {
            if picked_masks[f_idx][h_idx] {
                out.push(hit);
            }
        }
    }
    out
}

fn parse_literal_alternation(query: &str) -> Option<Vec<&str>> {
    if query.is_empty() {
        return None;
    }
    for ch in query.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$'
        ) {
            return None;
        }
    }
    let parts: Vec<&str> = query.split('|').collect();
    if parts.len() > 8 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    Some(parts)
}

fn try_in_ram_simd_search(
    svc: &BrokerService,
    needles: &[&str],
    search_roots: &[(PathBuf, PathBuf, bool)],
    cap: usize,
    deadline: Instant,
) -> Result<Option<Vec<SearchHit>>, SearchError> {
    let mut targets: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(32);
    for (canon, ws_root, is_dir) in search_roots {
        search_time_left(deadline)?;
        if *is_dir {
            let mut sub = Vec::new();
            walk_source_dir(
                canon,
                &mut sub,
                (IN_RAM_SEARCH_MAX_FILES + 1).saturating_sub(targets.len()),
            );
            for f in sub {
                if !targets.iter().any(|(existing, _)| existing == &f) {
                    targets.push((f, ws_root.clone()));
                }
                if targets.len() > IN_RAM_SEARCH_MAX_FILES {
                    return Ok(None);
                }
            }
        } else {
            if !targets.iter().any(|(existing, _)| existing == canon) {
                targets.push((canon.clone(), ws_root.clone()));
            }
            if targets.len() > IN_RAM_SEARCH_MAX_FILES {
                return Ok(None);
            }
        }
    }

    let case_sensitive = needles.iter().any(|n| n.chars().any(char::is_uppercase));
    let single_file = targets.len() == 1;
    let per_file_scan_cap = if single_file {
        cap.max(PER_FILE_SCAN_CANDIDATES)
    } else {
        PER_FILE_SCAN_CANDIDATES
    };
    let mut per_file: Vec<Vec<SearchHit>> = Vec::with_capacity(targets.len().min(16));

    for (file, ws_root) in targets {
        search_time_left(deadline)?;
        let Ok(entry) = svc.store.get_full_entry(&file, Some(&ws_root)) else {
            continue;
        };
        let Some(text) = entry.content.as_deref() else {
            continue;
        };
        let line_nums = search_lines_literals(
            text,
            &entry.line_offsets,
            needles,
            case_sensitive,
            per_file_scan_cap,
        );
        if line_nums.is_empty() {
            continue;
        }
        let mut file_hits = Vec::with_capacity(line_nums.len());
        for ln in line_nums {
            file_hits.push(SearchHit {
                path: file.clone(),
                workspace: ws_root.clone(),
                line: ln as usize,
                snippet: search_snippet(entry.line_slice(ln)),
            });
        }
        per_file.push(file_hits);
        // When many files match in a broad directory scan, stop once enough distinct files have hits.
        if per_file.len() >= cap {
            break;
        }
    }
    Ok(Some(prioritize_and_balance_file_hits(per_file, cap)))
}

fn collect_search_hits(
    svc: &BrokerService,
    query: &str,
    roots: &[String],
    max_results: usize,
    cwd: Option<&Path>,
    deadline: Instant,
) -> Result<Vec<SearchHit>, SearchError> {
    search_time_left(deadline)?;
    let q = query.trim();
    if q.is_empty() {
        return Err(SearchError::Failed("query must not be empty".to_string()));
    }
    let cap = max_results.clamp(1, 120);

    // (canon_path, ws_root, is_dir)
    let mut admitted_roots: Vec<(PathBuf, PathBuf, bool)> = Vec::with_capacity(roots.len().max(1));
    if roots.is_empty() {
        let base = cwd
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let (canon_dir, ws_root) = svc
            .allowlist
            .admit_dir(&base, Some(&base))
            .map_err(SearchError::Failed)?;
        admitted_roots.push((canon_dir, ws_root, true));
    } else {
        let mut first_non_refusal_err: Option<String> = None;
        for r in roots {
            search_time_left(deadline)?;
            let cleaned = r.trim().trim_end_matches("/**").trim_end_matches("/*");
            let resolved = resolve_input_path(cleaned, cwd);
            if !resolved.exists()
                && is_safe_shorthand_candidate(cleaned)
                && !is_sensitive_path(&resolved)
            {
                let base = cwd.map(Path::to_path_buf).unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                });
                if let Ok((_, ws_root)) = svc.allowlist.admit_dir(&base, Some(&base)) {
                    let alt1 = ws_root.join("src").join("src").join(cleaned);
                    let alt2 = ws_root.join("src").join(cleaned);
                    if alt1.is_dir() {
                        if let Ok((cd, wr)) = svc.allowlist.admit_dir(&alt1, cwd) {
                            admitted_roots.push((cd, wr, true));
                            continue;
                        }
                    } else if alt1.is_file() {
                        if let Ok((cf, wr)) = svc.allowlist.admit_file(&alt1, cwd) {
                            admitted_roots.push((cf, wr, false));
                            continue;
                        }
                    } else if alt2.is_dir() {
                        if let Ok((cd, wr)) = svc.allowlist.admit_dir(&alt2, cwd) {
                            admitted_roots.push((cd, wr, true));
                            continue;
                        }
                    } else if alt2.is_file() {
                        if let Ok((cf, wr)) = svc.allowlist.admit_file(&alt2, cwd) {
                            admitted_roots.push((cf, wr, false));
                            continue;
                        }
                    } else {
                        let matches = svc.store.find_workspace_paths(cleaned, &ws_root, 16);
                        if !matches.is_empty() {
                            let mut any_admitted = false;
                            for m in matches {
                                if let Ok((cf, wr)) = svc.allowlist.admit_file(&m, cwd) {
                                    admitted_roots.push((cf, wr, false));
                                    any_admitted = true;
                                }
                            }
                            if any_admitted {
                                continue;
                            }
                        }
                    }
                }
            }

            if resolved.is_dir() {
                match svc.allowlist.admit_dir(&resolved, cwd) {
                    Ok((canon_dir, ws_root)) => admitted_roots.push((canon_dir, ws_root, true)),
                    Err(e) if e.starts_with("REFUSED") => return Err(SearchError::Failed(e)),
                    Err(e) => {
                        if first_non_refusal_err.is_none() {
                            first_non_refusal_err = Some(e);
                        }
                    }
                }
            } else {
                match svc.allowlist.admit_file(&resolved, cwd) {
                    Ok((canon_f, ws_root)) => {
                        if !canon_f.is_file() {
                            if first_non_refusal_err.is_none() {
                                first_non_refusal_err =
                                    Some(format!("search root is not a regular file: {}", r));
                            }
                        } else {
                            admitted_roots.push((canon_f, ws_root, false));
                        }
                    }
                    Err(e) if e.starts_with("REFUSED") => return Err(SearchError::Failed(e)),
                    Err(e) => {
                        if first_non_refusal_err.is_none() {
                            first_non_refusal_err = Some(e);
                        }
                    }
                }
            }
        }
        if admitted_roots.is_empty() {
            return Err(SearchError::Failed(
                first_non_refusal_err.unwrap_or_else(|| "no readable search roots found".to_string()),
            ));
        }
    }

    if let Some(needles) = parse_literal_alternation(q) {
        if let Some(simd_hits) =
            try_in_ram_simd_search(svc, &needles, &admitted_roots, cap, deadline)?
        {
            return Ok(simd_hits);
        }
    }

    let multi_roots = admitted_roots.len() > 1;
    let search_roots: Vec<PathBuf> = admitted_roots.into_iter().map(|(p, _, _)| p).collect();
    let collect_cap = if multi_roots {
        cap.saturating_mul(2).min(160)
    } else {
        cap
    };
    let mut collection = SearchCollection {
        svc,
        cwd,
        deadline,
        cap: collect_cap,
        hits: Vec::new(),
    };
    run_rg_or_fallback(q, &search_roots, &mut collection)?;
    if collection.hits.len() <= cap {
        return Ok(collection.hits);
    }
    let mut grouped: Vec<Vec<SearchHit>> = Vec::new();
    for hit in collection.hits {
        if let Some(existing) = grouped
            .iter_mut()
            .find(|g| g[0].path == hit.path && g[0].workspace == hit.workspace)
        {
            existing.push(hit);
        } else {
            grouped.push(vec![hit]);
        }
    }
    Ok(prioritize_and_balance_file_hits(grouped, cap))
}

pub fn op_search_batch(
    svc: &BrokerService,
    queries: &[Json],
    cwd: Option<&Path>,
) -> Result<String, SearchError> {
    op_search_batch_with_defaults(svc, queries, 32, 0, cwd)
}

pub fn op_search_batch_with_defaults(
    svc: &BrokerService,
    queries: &[Json],
    default_max_results: usize,
    default_context_lines: usize,
    cwd: Option<&Path>,
) -> Result<String, SearchError> {
    if !(1..=4).contains(&queries.len()) {
        return Err(SearchError::Failed(
            "queries must contain 1–4 searches".to_string(),
        ));
    }
    let permit = svc
        .subproc_sem
        .try_acquire()
        .map_err(SearchError::Failed)?
        .ok_or(SearchError::Busy)?;
    let deadline = Instant::now() + SEARCH_TIMEOUT;

    let results: Vec<(Result<Vec<SearchHit>, SearchError>, usize)> = if queries.len() == 1 {
        vec![run_single_batch_item(
            svc,
            &queries[0],
            default_max_results,
            default_context_lines,
            cwd,
            deadline,
        )]
    } else {
        std::thread::scope(|scope| {
            let handles: Vec<_> = queries
                .iter()
                .map(|item| {
                    scope.spawn(move || {
                        run_single_batch_item(
                            svc,
                            item,
                            default_max_results,
                            default_context_lines,
                            cwd,
                            deadline,
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join().unwrap_or_else(|_| {
                        (
                            Err(SearchError::Failed("batch search worker panicked".to_string())),
                            0,
                        )
                    })
                })
                .collect()
        })
    };
    drop(permit);

    let total_queries = results.len();
    let mut out = String::with_capacity(2048);
    for (index, (result, context)) in results.into_iter().enumerate() {
        let heading = format!("[{}]\n", index + 1);
        let remaining_after = total_queries - 1 - index;
        let reserve_later = remaining_after << 9; // 512B guaranteed floor per later query
        let avail = SEARCH_RESPONSE_BYTES
            .saturating_sub(out.len())
            .saturating_sub(reserve_later);
        let budget = avail.saturating_sub(heading.len()).max(64);
        out.push_str(&heading);
        match result {
            Ok(hits) if hits.is_empty() => out.push_str("0 matches\n"),
            Ok(hits) => out.push_str(&format_compact_search(svc, &hits, context, budget)),
            Err(SearchError::Timeout) => out.push_str("Timeout: shared search budget exhausted\n"),
            Err(SearchError::Failed(error)) => {
                out.push_str("Error: ");
                let mut end = error.len().min(budget - "Error: …\n".len());
                while !error.is_char_boundary(end) {
                    end -= 1;
                }
                out.push_str(&error[..end]);
                if end < error.len() {
                    out.push('…');
                }
                out.push('\n');
            }
            Err(SearchError::Busy) => out.push_str("Error: search busy\n"),
        }
    }
    Ok(out)
}

fn run_single_batch_item(
    svc: &BrokerService,
    item: &Json,
    default_max_results: usize,
    default_context_lines: usize,
    cwd: Option<&Path>,
    deadline: Instant,
) -> (Result<Vec<SearchHit>, SearchError>, usize) {
    if let Some(spec) = item.as_str() {
        let result = parse_shorthand_search_spec(spec, true).and_then(|(query, roots)| {
            collect_search_hits(svc, &query, &roots, default_max_results, cwd, deadline)
        });
        return (result, default_context_lines);
    }
    if let Some(spec) = item.get_str("q") {
        let context = item
            .get_usize("context_lines")
            .unwrap_or(default_context_lines)
            .min(4);
        let max_res = item.get_usize("max_results").unwrap_or(default_max_results);
        let result = parse_shorthand_search_spec(spec, true).and_then(|(query, roots)| {
            collect_search_hits(svc, &query, &roots, max_res, cwd, deadline)
        });
        return (result, context);
    }
    let query = item.get_str("query").unwrap_or("");
    let roots = item.get("roots").and_then(Json::as_arr).and_then(|arr| {
        arr.iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
    });
    let context = item
        .get_usize("context_lines")
        .unwrap_or(default_context_lines)
        .min(4);
    let result = match roots {
        Some(roots) if !roots.is_empty() && roots.iter().all(|root| !root.trim().is_empty()) => {
            collect_search_hits(
                svc,
                query,
                &roots,
                item.get_usize("max_results").unwrap_or(default_max_results),
                cwd,
                deadline,
            )
        }
        _ => Err(SearchError::Failed(
            "roots must be a non-empty array of paths".to_string(),
        )),
    };
    (result, context)
}

#[inline]
fn compact_symbol_tag(name: &str) -> &str {
    name.trim_start_matches("::")
}

fn format_compact_search(
    svc: &BrokerService,
    hits: &[SearchHit],
    context: usize,
    budget: usize,
) -> String {
    let cut = format!("... [response capped at {} bytes]\n", budget);
    let mut out = String::with_capacity(budget.min(2048));
    out.push_str("Matches (");
    push_usize(&mut out, hits.len());
    out.push_str("):\n");
    let mut push_row = |row: &str| {
        if out.len() + row.len() > budget - cut.len() {
            out.push_str(&cut);
            return false;
        }
        out.push_str(row);
        true
    };
    let mut row_buf = String::with_capacity(256);
    'files: for group in hits.chunk_by(|a, b| a.path == b.path && a.workspace == b.workspace) {
        let first = &group[0];
        let path = display_workspace_path(&first.path, Some(&first.workspace));
        if context == 0 {
            if group.len() == 1 {
                row_buf.clear();
                row_buf.push_str(&path);
                row_buf.push(':');
                push_usize(&mut row_buf, first.line);
                row_buf.push_str(": ");
                row_buf.push_str(&first.snippet);
                row_buf.push('\n');
                if !push_row(&row_buf) {
                    break 'files;
                }
                continue;
            }

            row_buf.clear();
            row_buf.push_str(&path);
            row_buf.push('\n');
            if !push_row(&row_buf) {
                break 'files;
            }
            let outline = svc
                .store
                .get_outline_entry(&first.path, Some(&first.workspace))
                .ok();
            let mut last_sym: Option<&str> = None;
            for hit in group {
                let cur_sym = outline.as_deref().and_then(|entry| {
                    entry
                        .symbols
                        .iter()
                        .filter(|s| {
                            (s.start_line as usize) <= hit.line
                                && hit.line <= (s.end_line as usize)
                                && s.kind != SymbolKind::Namespace
                        })
                        .min_by_key(|s| s.end_line.saturating_sub(s.start_line))
                        .map(|s| compact_symbol_tag(&s.name))
                        .filter(|s| !s.is_empty())
                });
                row_buf.clear();
                if cur_sym != last_sym {
                    last_sym = cur_sym;
                    if let Some(sym) = cur_sym {
                        row_buf.push_str("  @");
                        row_buf.push_str(sym);
                        row_buf.push('\n');
                    }
                }
                row_buf.push_str("  ");
                push_usize(&mut row_buf, hit.line);
                row_buf.push_str(": ");
                row_buf.push_str(&hit.snippet);
                row_buf.push('\n');
                if !push_row(&row_buf) {
                    break 'files;
                }
            }
            continue;
        }

        let entry = svc
            .store
            .get_full_entry(&first.path, Some(&first.workspace))
            .ok();
        let total_lines = entry.as_ref().map_or(0usize, |e| e.line_count as usize);
        let entry_ref = entry.as_ref();
        if total_lines == 0
            || group.windows(2).any(|pair| pair[0].line >= pair[1].line)
            || group.iter().any(|hit| {
                hit.line == 0
                    || hit.line > total_lines
                    || entry_ref.is_none_or(|e| {
                        search_snippet(e.line_slice(hit.line as u32)) != hit.snippet
                    })
            })
        {
            for hit in group {
                row_buf.clear();
                row_buf.push_str(&path);
                row_buf.push(':');
                push_usize(&mut row_buf, hit.line);
                row_buf.push_str(": ");
                row_buf.push_str(&hit.snippet);
                row_buf.push('\n');
                if !push_row(&row_buf) {
                    break 'files;
                }
            }
            continue;
        }
        let Some(entry_ok) = entry_ref else {
            continue;
        };
        row_buf.clear();
        row_buf.push_str("-- ");
        row_buf.push_str(&path);
        row_buf.push_str(" --\n");
        if !push_row(&row_buf) {
            break;
        }
        let mut next_line = 1;
        for (i, hit) in group.iter().enumerate() {
            let start = hit.line.saturating_sub(context).max(next_line);
            let end = hit.line.saturating_add(context).min(total_lines);
            let end = group.get(i + 1).map_or(end, |next| end.min(next.line - 1));
            for line in start..=end {
                let snippet = search_snippet(entry_ok.line_slice(line as u32));
                row_buf.clear();
                if line == hit.line {
                    row_buf.push_str(&path);
                    row_buf.push(':');
                    push_usize(&mut row_buf, line);
                    row_buf.push_str(": ");
                    row_buf.push_str(&snippet);
                    row_buf.push('\n');
                } else {
                    row_buf.push_str("  ");
                    push_usize(&mut row_buf, line);
                    row_buf.push_str("- ");
                    row_buf.push_str(&snippet);
                    row_buf.push('\n');
                }
                if !push_row(&row_buf) {
                    break 'files;
                }
            }
            next_line = end + 1;
        }
    }
    out
}

enum RgError {
    Missing,
    Timeout,
    RegexSyntax(String),
    Process(String),
}

struct SearchProcess(Child);

impl Drop for SearchProcess {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn resolve_rg_binary() -> &'static Path {
    static RG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    RG_PATH
        .get_or_init(|| {
            let exe = if cfg!(windows) { "rg.exe" } else { "rg" };
            if let Some(path_var) = std::env::var_os("PATH") {
                for dir in std::env::split_paths(&path_var) {
                    let cand = dir.join(exe);
                    if cand.is_file() {
                        return cand;
                    }
                }
            }
            // Desktop GUI apps (macOS / Linux / Windows) often spawn MCP & hook processes
            // with a minimal system PATH omitting Homebrew, Cargo, WinGet, or ~/.local/bin.
            let mut extra_dirs: Vec<PathBuf> = Vec::new();
            #[cfg(unix)]
            {
                for sys_dir in [
                    "/opt/homebrew/bin",
                    "/usr/local/bin",
                    "/home/linuxbrew/.linuxbrew/bin",
                    "/usr/bin",
                    "/bin",
                ] {
                    extra_dirs.push(PathBuf::from(sys_dir));
                }
            }
            if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
                if !home.trim().is_empty() {
                    let h = PathBuf::from(home);
                    extra_dirs.push(h.join(".cargo").join("bin"));
                    extra_dirs.push(h.join(".local").join("bin"));
                    #[cfg(windows)]
                    {
                        extra_dirs.push(h.join("scoop").join("shims"));
                    }
                }
            }
            #[cfg(windows)]
            {
                if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
                    if !local_app.trim().is_empty() {
                        let la = PathBuf::from(local_app);
                        extra_dirs.push(la.join("Microsoft").join("WinGet").join("Links"));
                        extra_dirs.push(la.join("Programs").join("ripgrep"));
                    }
                }
                if let Ok(pf) = std::env::var("ProgramFiles") {
                    if !pf.trim().is_empty() {
                        extra_dirs.push(PathBuf::from(pf).join("ripgrep"));
                    }
                }
            }
            for dir in extra_dirs {
                let cand = dir.join(exe);
                if cand.is_file() {
                    return cand;
                }
            }
            PathBuf::from(exe)
        })
        .as_path()
}

fn run_rg_once(
    query: &str,
    roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
    fixed_strings: bool,
) -> Result<(), RgError> {
    search_time_left(collection.deadline).map_err(|_| RgError::Timeout)?;
    let mut cmd = Command::new(resolve_rg_binary());
    cmd.arg("--no-config")
        .arg("--with-filename")
        .arg("--null")
        .arg("--line-number")
        .arg("--no-heading")
        .arg("--color=never")
        .arg("--line-buffered")
        .arg("--smart-case")
        .arg("--max-count=25")
        .arg("--glob=!**/.git/**")
        .arg("--glob=!**/build*/**")
        .arg("--glob=!**/node_modules/**")
        .arg("--glob=!**/target/**");
    if fixed_strings {
        cmd.arg("--fixed-strings");
    }
    cmd.arg("--").arg(query);
    for r in roots {
        cmd.arg(r);
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                RgError::Missing
            } else {
                RgError::Process(format!("cannot run rg: {}", error))
            }
        })?;
    collect_rg_output(SearchProcess(child), collection, fixed_strings)
}

enum RgOutput {
    Record(Vec<u8>),
    StdoutDone(io::Result<()>),
    StderrDone(io::Result<Vec<u8>>),
}

fn collect_rg_output(
    mut process: SearchProcess,
    collection: &mut SearchCollection<'_>,
    fixed_strings: bool,
) -> Result<(), RgError> {
    let stdout = process.0.stdout.take().expect("piped rg stdout");
    let stderr = process.0.stderr.take().expect("piped rg stderr");
    let deadline = collection.deadline;
    let (tx, rx) = mpsc::sync_channel(8);
    let stdout_tx = tx.clone();
    // Returning drops the receiver and reaps rg, closing both pipe writers.
    let _stdout_reader = thread::Builder::new()
        .spawn(move || {
            let result = stream_rg_records(BufReader::new(stdout), deadline, &stdout_tx);
            let _ = stdout_tx.send(RgOutput::StdoutDone(result));
        })
        .map_err(|error| RgError::Process(format!("cannot start rg stdout reader: {error}")))?;
    let _stderr_reader = thread::Builder::new()
        .spawn(move || {
            let _ = tx.send(RgOutput::StderrDone(drain_rg_stderr(stderr, deadline)));
        })
        .map_err(|error| RgError::Process(format!("cannot start rg stderr reader: {error}")))?;

    let mut stdout_done = false;
    let mut diagnostic = None;
    while !stdout_done || diagnostic.is_none() {
        let remaining = search_time_left(deadline).map_err(|_| RgError::Timeout)?;
        let output = rx.recv_timeout(remaining).map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => RgError::Timeout,
            mpsc::RecvTimeoutError::Disconnected => {
                RgError::Process("rg readers ended early".to_string())
            }
        })?;
        match output {
            RgOutput::Record(record) => {
                let Some((path, line, snippet)) = parse_grep_line(&record) else {
                    continue;
                };
                let Ok((path, workspace)) = collection.svc.allowlist.admit_file(&path, collection.cwd)
                else {
                    continue;
                };
                search_time_left(deadline).map_err(|_| RgError::Timeout)?;
                collection.hits.push(SearchHit {
                    path,
                    workspace,
                    line,
                    snippet,
                });
                if collection.hits.len() == collection.cap {
                    return Ok(());
                }
            }
            RgOutput::StdoutDone(result) => {
                result.map_err(|error| rg_pipe_error("stdout", error))?;
                stdout_done = true;
            }
            RgOutput::StderrDone(result) => {
                diagnostic = Some(result.map_err(|error| rg_pipe_error("stderr", error))?);
            }
        }
    }

    // EOF can precede process exit. Keep the same deadline while checking status.
    let status = loop {
        let remaining = search_time_left(deadline).map_err(|_| RgError::Timeout)?;
        match process.0.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(remaining.min(Duration::from_millis(5))),
            Err(error) => return Err(RgError::Process(format!("cannot wait for rg: {error}"))),
        }
    };
    check_rg_status(status, &diagnostic.unwrap_or_default(), fixed_strings)
}

fn rg_pipe_error(stream: &str, error: io::Error) -> RgError {
    if error.kind() == ErrorKind::TimedOut {
        RgError::Timeout
    } else {
        RgError::Process(format!("cannot read rg {stream}: {error}"))
    }
}

fn stream_rg_records(
    mut input: impl BufRead,
    deadline: Instant,
    tx: &SyncSender<RgOutput>,
) -> io::Result<()> {
    while let Some(record) = read_rg_record(&mut input, deadline)? {
        if tx.send(RgOutput::Record(record)).is_err() {
            break;
        }
    }
    Ok(())
}

fn read_rg_record(input: &mut impl BufRead, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
    let mut record = Vec::new();
    let mut in_path = true;
    loop {
        search_time_left(deadline).map_err(|_| ErrorKind::TimedOut)?;
        let bytes = input.fill_buf()?;
        if bytes.is_empty() {
            return Ok((!record.is_empty()).then_some(record));
        }
        let delimiter = if in_path { 0 } else { b'\n' };
        let end = bytes.iter().position(|&byte| byte == delimiter);
        let consumed = end.map_or(bytes.len(), |index| index + 1);
        let stored = consumed.min(RG_RECORD_LIMIT - record.len());
        record.extend_from_slice(&bytes[..stored]);
        input.consume(consumed);
        if end.is_some() {
            if !in_path {
                return Ok(Some(record));
            }
            in_path = false;
        }
    }
}

fn drain_rg_stderr(mut input: impl Read, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut prefix = Vec::new();
    let mut buf = [0; RG_DIAGNOSTIC_LIMIT];
    loop {
        search_time_left(deadline).map_err(|_| ErrorKind::TimedOut)?;
        let n = input.read(&mut buf)?;
        if n == 0 {
            return Ok(prefix);
        }
        let stored = n.min(RG_DIAGNOSTIC_LIMIT - prefix.len());
        prefix.extend_from_slice(&buf[..stored]);
    }
}

fn check_rg_status(
    status: std::process::ExitStatus,
    stderr: &[u8],
    fixed_strings: bool,
) -> Result<(), RgError> {
    if matches!(status.code(), Some(0 | 1)) {
        return Ok(());
    }
    let diagnostic = String::from_utf8_lossy(stderr);
    let diagnostic = diagnostic.trim();
    if !fixed_strings
        && matches!(status.code(), Some(2))
        && (diagnostic.starts_with("regex parse error:")
            || diagnostic.starts_with("rg: regex parse error:"))
    {
        return Err(RgError::RegexSyntax(diagnostic.to_string()));
    }
    let diagnostic: String = diagnostic.chars().take(1_000).collect();
    Err(RgError::Process(if diagnostic.is_empty() {
        format!("rg failed ({})", status)
    } else {
        format!("rg failed ({}): {}", status, diagnostic)
    }))
}

fn run_rg_or_fallback(
    query: &str,
    roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
) -> Result<(), SearchError> {
    let has_regex_meta = query.chars().any(|c| {
        matches!(
            c,
            '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\'
        )
    });
    let result = match run_rg_once(query, roots, collection, false) {
        Ok(()) if collection.hits.is_empty() && has_regex_meta => {
            run_rg_once(query, roots, collection, true)
        }
        Err(RgError::RegexSyntax(_)) => {
            collection.hits.clear();
            run_rg_once(query, roots, collection, true)
        }
        result => result,
    };
    match result {
        Ok(()) => Ok(()),
        Err(RgError::Missing) => search_without_rg(query, roots, collection),
        Err(RgError::Timeout) => Err(SearchError::Timeout),
        Err(RgError::Process(error) | RgError::RegexSyntax(error)) => Err(SearchError::Failed(error)),
    }
}

const FALLBACK_SEARCH_FILE_LIMIT: usize = 3_000;

fn is_searchable_source_file(path: &Path, meta: &fs::Metadata) -> bool {
    meta.is_file()
        && meta.len() <= MAX_SINGLE_FILE_CACHE_BYTES as u64
        && !is_sensitive_path(path)
        && !is_multimodal_or_binary_ext(path)
}

fn visit_fallback_files(
    roots: &[PathBuf],
    deadline: Instant,
    mut visit: impl FnMut(&Path) -> Result<bool, SearchError>,
) -> Result<(), SearchError> {
    let mut files_left = FALLBACK_SEARCH_FILE_LIMIT;
    let mut roots = roots.iter().cloned();
    let mut dirs: Vec<fs::ReadDir> = Vec::new();
    loop {
        search_time_left(deadline)?;
        let (path, explicit) = match dirs.last_mut() {
            Some(dir) => match dir.next() {
                Some(Ok(entry)) => (entry.path(), false),
                Some(Err(_)) => continue,
                None => {
                    dirs.pop();
                    continue;
                }
            },
            None => match roots.next() {
                Some(path) => (path, true),
                None => return Ok(()),
            },
        };
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            if explicit || !should_skip_dir(name) {
                if let Ok(entries) = fs::read_dir(&path) {
                    dirs.push(entries);
                }
            }
        } else if is_searchable_source_file(&path, &meta) {
            files_left -= 1;
            if visit(&path)? || files_left == 0 {
                return search_time_left(deadline).map(|_| ());
            }
        }
    }
}

fn search_without_rg(
    query: &str,
    roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
) -> Result<(), SearchError> {
    let needle_low = query.to_ascii_lowercase();
    let deadline = collection.deadline;
    visit_fallback_files(roots, deadline, |path| {
        let Ok((path, workspace)) = collection.svc.allowlist.admit_file(path, collection.cwd) else {
            return Ok(false);
        };
        let Some(text) = read_fallback_file(&path, deadline)? else {
            return Ok(false);
        };
        for (idx, line) in text.lines().enumerate() {
            search_time_left(deadline)?;
            if line.to_ascii_lowercase().contains(&needle_low) {
                collection.hits.push(SearchHit {
                    path: path.clone(),
                    workspace: workspace.clone(),
                    line: idx + 1,
                    snippet: search_snippet(line),
                });
                if collection.hits.len() == collection.cap {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })
}

fn read_fallback_file(path: &Path, deadline: Instant) -> Result<Option<String>, SearchError> {
    search_time_left(deadline)?;
    let Ok(file) = fs::File::open(path) else {
        return Ok(None);
    };
    let mut file = file.take(MAX_SINGLE_FILE_CACHE_BYTES as u64 + 1);
    let mut bytes = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        search_time_left(deadline)?;
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) if n > MAX_SINGLE_FILE_CACHE_BYTES - bytes.len() => return Ok(None),
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Ok(None),
        }
    }
    Ok(String::from_utf8(bytes).ok())
}

fn parse_grep_line(record: &[u8]) -> Option<(PathBuf, usize, String)> {
    let mut fields = record.splitn(2, |&byte| byte == 0);
    let path = fields.next()?;
    let mut fields = fields.next()?.splitn(2, |&byte| byte == b':');
    let number = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
    let text = fields.next()?;
    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(path))
    };
    #[cfg(not(unix))]
    let path = PathBuf::from(std::str::from_utf8(path).ok()?);
    Some((path, number, search_snippet(&String::from_utf8_lossy(text))))
}

#[cfg(test)]
mod search_tests {
    use super::*;
    use std::process::ExitStatus;

    #[test]
    fn collected_search_reuses_the_callers_deadline() {
        let service = BrokerService::new_ephemeral_inproc(PathBuf::new());
        let expired = Instant::now() - SEARCH_TIMEOUT;
        assert!(matches!(
            collect_search_hits(&service, "sample", &[], 1, None, expired),
            Err(SearchError::Timeout)
        ));
    }

    fn exited(code: u8) -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(i32::from(code) << 8)
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(u32::from(code))
        }
    }

    #[test]
    fn rg_distinguishes_no_matches_regex_syntax_and_process_errors() {
        assert!(check_rg_status(exited(1), b"rg: No files were searched", false).is_ok());
        let syntax_error = b"regex parse error:\nerror: unclosed character class";
        assert!(matches!(
            check_rg_status(exited(2), syntax_error, false),
            Err(RgError::RegexSyntax(_))
        ));
        assert!(matches!(
            check_rg_status(exited(2), syntax_error, true),
            Err(RgError::Process(_))
        ));
        assert!(matches!(
            check_rg_status(exited(2), b"rg: Permission denied", false),
            Err(RgError::Process(message)) if message.contains("Permission denied")
        ));
    }

    #[test]
    fn rg_match_has_an_unambiguous_path_separator() {
        let hit = parse_grep_line(b"a:b.rs\x0017:example: value").unwrap();
        assert_eq!(
            hit,
            (PathBuf::from("a:b.rs"), 17, "example: value".to_string())
        );
    }

    #[test]
    fn rg_oversized_record_and_stderr_are_drained_with_bounded_prefixes() {
        let mut data = b"a\nb.rs\0".to_vec();
        data.extend_from_slice(b"17:");
        data.extend(std::iter::repeat(b'x').take(RG_RECORD_LIMIT * 2));
        data.extend_from_slice(b"\nnext.rs\0");
        data.extend_from_slice(b"18:next match\n");
        let mut reader = BufReader::with_capacity(7, io::Cursor::new(&data));
        let deadline = Instant::now() + SEARCH_TIMEOUT;
        let first = read_rg_record(&mut reader, deadline).unwrap().unwrap();
        assert_eq!(first.len(), RG_RECORD_LIMIT);
        assert_eq!(
            parse_grep_line(&first),
            Some((PathBuf::from("a\nb.rs"), 17, "x".repeat(SEARCH_SNIPPET_CHARS)))
        );
        let second = read_rg_record(&mut reader, deadline).unwrap().unwrap();
        assert_eq!(
            parse_grep_line(&second),
            Some((PathBuf::from("next.rs"), 18, "next match".to_string()))
        );
        assert!(read_rg_record(&mut reader, deadline).unwrap().is_none());

        let mut stderr = io::Cursor::new(&data);
        let diagnostic = drain_rg_stderr(&mut stderr, deadline).unwrap();
        assert_eq!(diagnostic, data[..RG_DIAGNOSTIC_LIMIT]);
        assert_eq!(stderr.position(), data.len() as u64);
    }

    #[test]
    fn fallback_uses_one_file_budget_for_directory_and_explicit_roots() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-search-files-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&dir).unwrap();
        let in_directory = dir.join("first.txt");
        fs::write(&in_directory, "needle\n").unwrap();
        let mut roots = vec![dir.clone()];
        roots.extend(std::iter::repeat(in_directory.clone()).take(FALLBACK_SEARCH_FILE_LIMIT));

        let deadline = Instant::now() + SEARCH_TIMEOUT;
        let mut count = 0;
        visit_fallback_files(&roots, deadline, |path| {
            assert_eq!(path, in_directory.as_path());
            count += 1;
            Ok(false)
        })
        .unwrap();

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        let workspace = svc.allowlist.register_hint(&dir, true).unwrap();
        let mut collection = SearchCollection {
            svc: &svc,
            cwd: Some(&dir),
            deadline,
            cap: 1,
            hits: Vec::new(),
        };
        search_without_rg("NEEDLE", &roots, &mut collection).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(count, FALLBACK_SEARCH_FILE_LIMIT);
        let [hit] = collection.hits.as_slice() else {
            panic!("expected one fallback match");
        };
        assert_eq!(hit.path, workspace.join("first.txt"));
        assert_eq!(hit.line, 1);
        assert_eq!(hit.snippet, "needle");
    }

    #[test]
    fn expired_fallback_deadline_stops_before_visiting_files() {
        let result = visit_fallback_files(&[PathBuf::from(".")], Instant::now(), |_| {
            panic!("expired search visited a file");
        });
        assert!(matches!(result, Err(SearchError::Timeout)));
    }

    #[cfg(unix)]
    #[test]
    fn rg_cap_counts_admitted_matches_and_stops_before_eof() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-search-rg-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&dir).unwrap();
        let sensitive = dir.join(".env");
        let source = dir.join("match.rs");
        fs::write(&sensitive, "needle").unwrap();
        fs::write(&source, "needle").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        let workspace = svc.allowlist.register_hint(&dir, true).unwrap();
        let child = Command::new("sh")
            .args([
                "-c",
                r#"printf '%s\000%d:needle\n' "$1" 1 "$2" 1; exec sleep 30"#,
                "rg-test",
            ])
            .arg(&sensitive)
            .arg(&source)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut collection = SearchCollection {
            svc: &svc,
            cwd: Some(&dir),
            deadline: Instant::now() + SEARCH_TIMEOUT,
            cap: 1,
            hits: Vec::new(),
        };
        let result = collect_rg_output(SearchProcess(child), &mut collection, false);
        fs::remove_dir_all(&dir).unwrap();
        assert!(result.is_ok());
        let [hit] = collection.hits.as_slice() else {
            panic!("expected one admitted rg match");
        };
        assert_eq!(hit.path, workspace.join("match.rs"));
    }

    #[cfg(unix)]
    #[test]
    fn rg_timeout_applies_with_silent_open_pipes() {
        let svc = BrokerService::new_ephemeral_inproc(PathBuf::from("unused"));
        let child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut collection = SearchCollection {
            svc: &svc,
            cwd: None,
            deadline: Instant::now() + Duration::from_millis(25),
            cap: 1,
            hits: Vec::new(),
        };
        assert!(matches!(
            collect_rg_output(SearchProcess(child), &mut collection, false),
            Err(RgError::Timeout)
        ));
    }
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
                if crate::broker::contains_known_secret(raw_p) {
                    return Err("REFUSED: memo link contains known secret material".to_string());
                }
                let resolved = resolve_input_path(raw_p, Some(&base));
                let canon = crate::security::admit_file_in_workspace(&resolved, &ws_root)?;
                let rel = canon
                    .strip_prefix(&ws_root)
                    .expect("admitted file must be inside its workspace")
                    .to_str()
                    .ok_or_else(|| "memo linked path must be UTF-8".to_string())?;
                if crate::broker::contains_known_secret(rel) {
                    return Err("REFUSED: memo link contains known secret material".to_string());
                }
                if links.iter().any(|link: &MemoFileLink| link.abs_path == canon) {
                    return Err("memo link paths must be unique".to_string());
                }
                let fnv = svc
                    .store
                    .current_file_fnv64(&canon, Some(&ws_root))
                    .ok_or_else(|| "cannot hash memo linked file".to_string())?;
                links.push(MemoFileLink {
                    rel_path: rel.to_string(),
                    abs_path: canon,
                    fnv64_at_put: fnv,
                });
            }
            let text = svc.broker.put_memo(&ws_norm, topic, summary, kind, trusted_author, links)?;
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
            let text = svc.broker.clear_memos(&ws_norm, (!topic.is_empty()).then_some(topic))?;
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

pub fn op_elf_audit(
    svc: &BrokerService,
    elf_path: &str,
    asm_path: Option<&str>,
    cwd: Option<&Path>,
) -> Result<String, String> {
    let root = cwd
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let resolved_elf = resolve_input_path(elf_path, Some(&root));
    let (canon_elf, _) = svc.allowlist.admit_file(&resolved_elf, Some(&root))?;

    let mut cur: Option<&Path> = Some(root.as_path());
    let mut script_path: Option<PathBuf> = None;
    while let Some(dir) = cur {
        for script_name in ["ElfAudit.py", "CxetElfAudit.py"] {
            let cand = dir.join("tools").join("Checks").join(script_name);
            if cand.is_file() {
                script_path = Some(cand);
                break;
            }
        }
        if script_path.is_some() {
            break;
        }
        cur = dir.parent();
    }
    let Some(script) = script_path else {
        return Err("tools/Checks/ElfAudit.py not found in workspace".to_string());
    };

    let _permit = svc.subproc_sem.acquire(Duration::from_secs(10))?;
    for py in &["python3", "python"] {
        let mut cmd = Command::new(py);
        cmd.arg("-B").arg(&script).arg("--elf").arg(&canon_elf);
        if let Some(a) = asm_path {
            let resolved_asm = resolve_input_path(a, Some(&root));
            let (canon_asm, _) = svc.allowlist.admit_file(&resolved_asm, Some(&root))?;
            cmd.arg("--asm").arg(canon_asm);
        }
        if let Ok(out) = cmd.output() {
            if out.status.success() {
                return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
            } else {
                return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
            }
        }
    }
    Err("python3/python unavailable to run CxetElfAudit.py".to_string())
}
