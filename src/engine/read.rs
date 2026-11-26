use super::DEFAULT_READ_MAX_BYTES;
use crate::base::security::is_sensitive_path;
use crate::base::simd::{decimal_digits, push_u32, push_usize};
use crate::rpc::BrokerService;
use crate::store::{
    display_workspace_path, resolve_input_path, MissingResolution, RamStore,
    MAX_SINGLE_FILE_CACHE_BYTES,
};
use std::fs;
use std::path::{Path, PathBuf};

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

pub fn op_read_for_host(
    svc: &BrokerService,
    specs: &[String],
    max_bytes: usize,
    force: bool,
    session_key: Option<&str>,
    cwd: Option<&Path>,
    inline_dedup_cap: Option<usize>,
) -> Result<String, String> {
    if specs.is_empty() {
        return Err("provide at least one file path".to_string());
    }
    let budget = max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES << 1);
    let mut out = String::new();
    let mut any_ok = false;
    let mut pending_reads: Vec<(PathBuf, PathBuf, usize, usize)> = Vec::new();

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

                let cap_note = if inline_dedup_cap.is_some() {
                    format!(
                        "... [AGY inline cap {budget}B reached; {} later paths unread — prefer parallel native read_file (<=800L/46KB inline) for full files, or ctx_read path:start-end slices for >800L]\n",
                        specs.len() - index - 1
                    )
                } else {
                    format!(
                        "... [output capped at {budget} bytes; {} later paths left unread]\n",
                        specs.len() - index - 1
                    )
                };
                let content_limit = budget.saturating_sub(cap_note.len() + 1);
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
                    if inline_dedup_cap.is_some() {
                        out.push_str(&format!(
                            "... [AGY inline cap {budget}B reached; {} paths unread — prefer parallel native read_file (<=800L/46KB inline) for full files, or ctx_read path:start-end slices for >800L]\n",
                            specs.len() - index
                        ));
                    } else {
                        out.push_str(&format!(
                            "... [output capped at {budget} bytes; {} paths left unread]\n",
                            specs.len() - index
                        ));
                    }
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
                if let Some(actual_end) = actual_end {
                    pending_reads.push((canon.clone(), ws_root.clone(), s, actual_end));
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
    // Never mark files as ALREADY IN CONTEXT when the host client will middle-truncate the payload.
    let safe_to_record = inline_dedup_cap.map_or(true, |cap| out.len() <= cap);
    if safe_to_record {
        if let Some(sk) = session_key {
            for (canon, ws_root, s, actual_end) in pending_reads {
                svc.store
                    .record_read(sk, &canon, Some(&ws_root), s, actual_end);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{AGY_MCP_DEFAULT_MAX_BYTES, AGY_MCP_INLINE_CAP};

    #[test]
    fn agy_inline_cap_skips_session_dedup_when_truncated_and_records_when_inline() {
        let workspace = std::env::temp_dir().join(format!(
            "ctx-agy-dedup-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("small.cpp"), "int small_ok = 1;\n").unwrap();
        let big_body = (1..=320)
            .map(|i| format!("int big_line_{i:03} = {i}; // padding_0123456789_abcdef\n"))
            .collect::<String>();
        fs::write(workspace.join("large.cpp"), &big_body).unwrap();
        let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
        svc.allowlist.register_hint(&workspace, true).unwrap();

        // 1. Oversized AGY read (> AGY_MCP_INLINE_CAP) must NOT poison SessionState with ALREADY IN CONTEXT
        let oversized = op_read_for_host(
            &svc,
            &["small.cpp".into(), "large.cpp".into()],
            16_384,
            false,
            Some("agy-sess-1"),
            Some(&workspace),
            Some(AGY_MCP_INLINE_CAP),
        )
        .unwrap();
        assert!(oversized.len() > AGY_MCP_INLINE_CAP);

        let re_read = op_read_for_host(
            &svc,
            &["small.cpp".into()],
            AGY_MCP_DEFAULT_MAX_BYTES,
            false,
            Some("agy-sess-1"),
            Some(&workspace),
            Some(AGY_MCP_INLINE_CAP),
        )
        .unwrap();
        assert!(re_read.contains("small_ok = 1;"));
        assert!(!re_read.contains("ALREADY IN CONTEXT"));

        // 2. Now that `small.cpp` fit inline (<= AGY_MCP_INLINE_CAP), the next identical read deduplicates cleanly
        let dedup = op_read_for_host(
            &svc,
            &["small.cpp".into()],
            AGY_MCP_DEFAULT_MAX_BYTES,
            false,
            Some("agy-sess-1"),
            Some(&workspace),
            Some(AGY_MCP_INLINE_CAP),
        )
        .unwrap();
        assert!(dedup.contains("ALREADY IN CONTEXT"));

        // 3. Default AGY cap note recommends parallel native read_file
        let capped = op_read_for_host(
            &svc,
            &["large.cpp".into()],
            AGY_MCP_DEFAULT_MAX_BYTES,
            true,
            Some("agy-sess-2"),
            Some(&workspace),
            Some(AGY_MCP_INLINE_CAP),
        )
        .unwrap();
        assert!(capped.len() <= AGY_MCP_INLINE_CAP);
        assert!(capped.contains("read_file"));

        fs::remove_dir_all(&workspace).unwrap();
    }
}
