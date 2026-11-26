use super::DEFAULT_READ_MAX_BYTES;
use crate::base::security::is_sensitive_path;
use crate::base::simd::{decimal_digits, line_hash3, push_u32, push_usize};
use crate::rpc::BrokerService;
use crate::store::{
    display_workspace_path, resolve_input_path, CachedFile, DeltaHit, MissingResolution, RamStore,
    SessionReadStatus, MAX_SINGLE_FILE_CACHE_BYTES,
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
    hashes: bool,
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
            let hint_note = cwd
                .and_then(|c| svc.allowlist.register_hint(c, false))
                .map_or_else(String::new, |ws_root| match svc.store.resolve_missing_path(&resolved, &ws_root) {
                    MissingResolution::Unique(real) => format!(" (moved to `{}`)", display_workspace_path(&real, Some(&ws_root))),
                    MissingResolution::Ambiguous(cands) => {
                        let rels: Vec<String> = cands.iter().take(5).map(|p| display_workspace_path(p, Some(&ws_root))).collect();
                        format!(" (candidates: {})", rels.join(", "))
                    }
                    MissingResolution::NotFound => String::new(),
                });
            out.push_str(&format!("=== {raw_p} [ERROR: file does not exist{hint_note}] ===\n"));
            continue;
        }
        let (canon, ws_root) = match svc.allowlist.admit_file(&resolved, cwd) {
            Ok(pair) => pair,
            Err(msg) => { out.push_str(&format!("=== {raw_p} [{msg}] ===\n")); continue; }
        };
        let meta = match fs::metadata(&canon) {
            Ok(m) if m.is_file() => m,
            Ok(_) => { out.push_str(&format!("=== {raw_p} [ERROR: is a directory; use `ctx outline`] ===\n")); continue; }
            Err(e) => { out.push_str(&format!("=== {raw_p} [ERROR: {e}] ===\n")); continue; }
        };

        let mut delta_hit: Option<DeltaHit> = None;
        if !force {
            if let Some(sk) = session_key {
                let (rs, re) = match slice {
                    Some((s, e)) => (Some(s), Some(e)),
                    None => (None, None),
                };
                match svc.store.check_session_read(sk, &canon, Some(&ws_root), rs, re) {
                    SessionReadStatus::Unchanged(dup) => {
                        any_ok = true;
                        out.push_str(&format!(
                            "=== {} [ALREADY IN CONTEXT: lines {}-{} of {} unchanged; pass --force to reload] ===\nOutline: {}\n\n",
                            dup.rel_path, dup.covered_start, dup.covered_end, dup.total_lines, dup.outline_summary
                        ));
                        continue;
                    }
                    SessionReadStatus::Changed(delta) => delta_hit = Some(delta),
                    SessionReadStatus::Miss => {}
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
                        let body = if hashes { reformat_large_slice_with_hashes(&text, remain) } else { text };
                        out.push_str(&format!("=== {rel} (lines {actual_s}-{actual_e}, large file {}B) ===\n{body}\n", meta.len()));
                    }
                    Err(err) => out.push_str(&format!("=== {rel} [ERROR: {err}] ===\n")),
                }
            } else {
                out.push_str(&format!("=== {rel} [FILE > 1 MiB ({} bytes): pass explicit slice {rel}:1-400] ===\n", meta.len()));
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

                let cap_note = format_cap_note(budget, specs.len() - index - 1, inline_dedup_cap.is_some(), true);
                let content_limit = budget.saturating_sub(cap_note.len() + 1);
                let other_note = format_other_actor_note(svc, session_key, &ws_root, &entry.rel_path);
                if let Some(ref delta) = delta_hit {
                    if let Some((delta_sec, rec_s, rec_e)) = try_format_delta_section(
                        &entry, delta, slice, s, e, hashes, other_note.as_deref(),
                    ) {
                        if out.len() + delta_sec.len() <= content_limit {
                            out.push_str(&delta_sec);
                            pending_reads.push((canon.clone(), ws_root.clone(), rec_s, rec_e));
                            if out.len() >= budget { break; }
                            continue;
                        }
                    }
                }
                let line_overhead = if hashes { 12 } else { 8 };
                let approx_cap = (entry.size_bytes as usize + (e - s + 2) * line_overhead).min(budget);
                let mut section = String::with_capacity(approx_cap.max(128));
                section.push_str("=== "); section.push_str(&entry.rel_path);
                section.push_str(" (lines "); push_usize(&mut section, s);
                section.push('-'); push_usize(&mut section, e);
                section.push_str(" of "); push_usize(&mut section, total);
                section.push_str(", "); push_u32(&mut section, entry.size_bytes);
                section.push_str("B) ===\n");
                if let Some(note) = other_note.as_deref() { section.push_str(note); }

                if out.len() + section.len() > content_limit {
                    out.push_str(&format_cap_note(budget, specs.len() - index, inline_dedup_cap.is_some(), false));
                    break;
                }
                let mut actual_end = None;
                let mut clipped = false;
                let max_present = entry.line_count as usize;
                let prefix_extra = if hashes { 6 } else { 2 };
                for ln in s..=e {
                    if ln == 0 || ln > max_present {
                        break;
                    }
                    let line = entry.line_slice(ln as u32);
                    let row_len = decimal_digits(ln) + prefix_extra + line.len() + 1;
                    if out.len() + section.len() + row_len > content_limit {
                        section.push_str(&cap_note);
                        clipped = true;
                        break;
                    }
                    push_usize(&mut section, ln);
                    if hashes {
                        let h3 = line_hash3(line);
                        section.push(':');
                        section.push(h3[0] as char);
                        section.push(h3[1] as char);
                        section.push(h3[2] as char);
                        section.push_str("| ");
                    } else {
                        section.push_str(": ");
                    }
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

fn format_cap_note(budget: usize, unread: usize, is_agy: bool, later: bool) -> String {
    let qual = if later { "later paths" } else { "paths" };
    if is_agy {
        format!("... [AGY inline cap {budget}B reached; {unread} {qual} unread — prefer parallel native read_file (<=800L/46KB inline) for full files, or ctx_read path:start-end slices for >800L]\n")
    } else {
        format!("... [output capped at {budget} bytes; {unread} {qual} left unread]\n")
    }
}

fn format_other_actor_note(
    svc: &BrokerService, session_key: Option<&str>, ws_root: &Path, rel_path: &str,
) -> Option<String> {
    let sk = session_key?;
    let ws_norm = crate::store::norm_key_from_canon(ws_root);
    let ev = svc.broker.changes.latest_other_actor_change(&ws_norm, rel_path, sk)?;
    let mut note = String::from("[changed by another session: seq #");
    push_usize(&mut note, ev.seq as usize);
    if !ev.changed_symbols.is_empty() {
        note.push_str(", symbols: ");
        note.push_str(&ev.changed_symbols.join(", "));
    }
    note.push_str("]\n");
    Some(note)
}

#[derive(Clone, Copy)]
struct DiffHunk { old_s: usize, old_e: usize, new_s: usize, new_e: usize }

fn myers_diff_hunks(a: &[&str], b: &[&str], prefix: usize, max_d: usize) -> Option<Vec<DiffHunk>> {
    let (n, m) = (a.len(), b.len());
    if n == 0 && m == 0 { return Some(Vec::new()); }
    if n == 0 { return Some(vec![DiffHunk { old_s: prefix, old_e: prefix, new_s: prefix, new_e: prefix + m }]); }
    if m == 0 { return Some(vec![DiffHunk { old_s: prefix, old_e: prefix + n, new_s: prefix, new_e: prefix }]); }
    if n.abs_diff(m) > max_d { return None; }

    let off = max_d as isize;
    let mut v = vec![0u32; (max_d << 1) + 3];
    let mut trace: Vec<Vec<u32>> = Vec::new();
    let mut found_d = None;
    for d in 0..=max_d {
        let di = d as isize;
        let mut k = -di;
        while k <= di {
            let ki = (k + off + 1) as usize;
            let mut x = if k == -di || (k != di && v[ki - 1] < v[ki + 1]) { v[ki + 1] as usize } else { v[ki - 1] as usize + 1 };
            let mut y = (x as isize - k) as usize;
            while x < n && y < m && a[x] == b[y] { x += 1; y += 1; }
            v[ki] = x as u32;
            if x == n && y == m { found_d = Some(d); break; }
            k += 2;
        }
        if found_d.is_some() { break; }
        trace.push(v[(off + 1 - di) as usize..=(off + 1 + di) as usize].to_vec());
    }
    let d_final = found_d?;
    let mut edits = Vec::with_capacity(d_final);
    let (mut x, mut y) = (n, m);
    for d in (1..=d_final).rev() {
        let prev_v = &trace[d - 1];
        let (prev_off, di, k) = ((d - 1) as isize, d as isize, x as isize - y as isize);
        let prev_k = if k == -di || (k != di && prev_v[(k - 1 + prev_off) as usize] < prev_v[(k + 1 + prev_off) as usize]) {
            k + 1
        } else { k - 1 };
        let prev_x = prev_v[(prev_k + prev_off) as usize] as usize;
        let prev_y = (prev_x as isize - prev_k) as usize;
        edits.push((prev_x, prev_y, prev_k == k + 1));
        x = prev_x; y = prev_y;
    }
    edits.reverse();
    let mut hunks: Vec<DiffHunk> = Vec::new();
    for (ex, ey, is_ins) in edits {
        let (os, oe, ns, ne) = if is_ins { (prefix + ex, prefix + ex, prefix + ey, prefix + ey + 1) }
            else { (prefix + ex, prefix + ex + 1, prefix + ey, prefix + ey) };
        if let Some(last) = hunks.last_mut() {
            if last.old_e == os && last.new_e == ns { last.old_e = oe; last.new_e = ne; continue; }
        }
        hunks.push(DiffHunk { old_s: os, old_e: oe, new_s: ns, new_e: ne });
    }
    Some(hunks)
}

#[inline]
fn push_delta_line(out: &mut String, prefix: char, ln: usize, raw: &str, hashes: bool) {
    out.push(prefix);
    push_usize(out, ln);
    if hashes {
        let text = if ln == 1 { raw.strip_prefix('\u{FEFF}').unwrap_or(raw) } else { raw };
        let h3 = line_hash3(text);
        out.extend([':', h3[0] as char, h3[1] as char, h3[2] as char]);
        out.push_str("| ");
        out.push_str(text);
    } else {
        out.push_str(": ");
        out.push_str(raw);
    }
    out.push('\n');
}

fn try_format_delta_section(
    entry: &CachedFile, delta: &DeltaHit, slice: Option<(usize, usize)>,
    s: usize, e: usize, hashes: bool, other_actor: Option<&str>,
) -> Option<(String, usize, usize)> {
    let old_lines: Vec<&str> = delta.prev_content.lines().collect();
    let new_count = entry.line_count as usize;
    let new_lines: Vec<&str> = (1..=new_count).map(|ln| entry.line_slice(ln as u32)).collect();
    let total = new_count.max(1);

    let (mut p, mut q) = (0usize, 0usize);
    while p < old_lines.len() && p < new_count && old_lines[p] == new_lines[p] { p += 1; }
    while p + q < old_lines.len() && p + q < new_count
        && old_lines[old_lines.len() - 1 - q] == new_lines[new_count - 1 - q] { q += 1; }
    let max_d = ((total >> 1) + 2).min(512);
    let hunks = myers_diff_hunks(&old_lines[p..old_lines.len() - q], &new_lines[p..new_count - q], p, max_d)?;
    if hunks.is_empty() { return None; }

    let covered_whole_prev = delta.covered_start <= 1 && delta.covered_end >= old_lines.len().max(1);
    if slice.is_some() && !covered_whole_prev
        && hunks.iter().any(|h| h.old_s + 1 < s || h.new_s + 1 < s || h.old_e > delta.covered_end || h.new_e > e)
    {
        return None;
    }

    let (mut added, mut removed, mut changed_lines) = (0usize, 0usize, 0usize);
    for h in &hunks {
        let (a_n, r_n) = (h.new_e - h.new_s, h.old_e - h.old_s);
        added += a_n; removed += r_n; changed_lines += a_n.max(r_n);
    }
    if changed_lines == 0 || changed_lines.saturating_mul(4) > total { return None; }

    let mut sec = String::with_capacity(256);
    sec.push_str("=== "); sec.push_str(&entry.rel_path);
    sec.push_str(" [DELTA since last read: +"); push_usize(&mut sec, added);
    sec.push_str("/-"); push_usize(&mut sec, removed);
    sec.push_str(" lines, total "); push_usize(&mut sec, new_count);
    sec.push_str(" lines; pass force=true for full] ===\n");
    if let Some(note) = other_actor { sec.push_str(note); }

    let mut hi = 0usize;
    while hi < hunks.len() {
        if hi > 0 { sec.push_str("...\n"); }
        let mut grp_end = hi;
        while grp_end + 1 < hunks.len() && hunks[grp_end + 1].new_s <= hunks[grp_end].new_e.saturating_add(4) {
            grp_end += 1;
        }
        let mut cur_new = hunks[hi].new_s.saturating_sub(2);
        for h in &hunks[hi..=grp_end] {
            while cur_new < h.new_s { push_delta_line(&mut sec, ' ', cur_new + 1, new_lines[cur_new], hashes); cur_new += 1; }
            for oi in h.old_s..h.old_e {
                sec.push('-'); push_usize(&mut sec, oi + 1); sec.push_str(": "); sec.push_str(old_lines[oi]); sec.push('\n');
            }
            for ni in h.new_s..h.new_e { push_delta_line(&mut sec, '+', ni + 1, new_lines[ni], hashes); }
            cur_new = h.new_e;
        }
        let ctx_end = hunks[grp_end].new_e.saturating_add(2).min(new_count);
        while cur_new < ctx_end { push_delta_line(&mut sec, ' ', cur_new + 1, new_lines[cur_new], hashes); cur_new += 1; }
        hi = grp_end + 1;
    }
    sec.push('\n');

    let approx_full_len = if slice.is_none() {
        64usize.saturating_add(entry.size_bytes as usize).saturating_add(new_count.saturating_mul(if hashes { 8 } else { 4 }))
    } else {
        let px = if hashes { 6 } else { 2 };
        (s..=e.min(new_count)).fold(64usize, |acc, ln| acc.saturating_add(decimal_digits(ln) + px + new_lines[ln - 1].len() + 1))
    };
    if sec.len().saturating_mul(2) >= approx_full_len { return None; }
    let (rec_s, rec_e) = if covered_whole_prev { (1, total) } else { (s, e) };
    Some((sec, rec_s, rec_e))
}

fn reformat_large_slice_with_hashes(text: &str, remain: usize) -> String {
    let mut hashed = String::with_capacity(text.len().min(remain));
    for raw_line in text.lines() {
        if let Some((ln_str, body)) = raw_line.split_once(": ") {
            if !ln_str.is_empty() && ln_str.bytes().all(|b| b.is_ascii_digit()) {
                if hashed.len() + ln_str.len() + 6 + body.len() + 33 > remain {
                    hashed.push_str("... [truncated at max_bytes]\n");
                    break;
                }
                let h3 = line_hash3(body);
                hashed.push_str(ln_str);
                hashed.extend([':', h3[0] as char, h3[1] as char, h3[2] as char]);
                hashed.push_str("| "); hashed.push_str(body); hashed.push('\n');
                continue;
            }
        }
        if hashed.len() + raw_line.len() + 1 > remain { break; }
        hashed.push_str(raw_line); hashed.push('\n');
    }
    hashed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{AGY_MCP_DEFAULT_MAX_BYTES, AGY_MCP_INLINE_CAP};

    fn new_ws(tag: &str) -> (PathBuf, BrokerService) {
        let tok = crate::base::security::generate_csprng_token().unwrap();
        let ws = std::env::temp_dir().join(format!("ctx-{tag}-{tok}"));
        fs::create_dir(&ws).unwrap();
        let svc = BrokerService::new_ephemeral_inproc(ws.join("snapshot"));
        svc.allowlist.register_hint(&ws, true).unwrap();
        (ws, svc)
    }

    fn make_lines(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("let value_{i:03} = {i}; // deterministic_line_padding")).collect()
    }

    #[test]
    fn agy_inline_cap_skips_session_dedup_when_truncated_and_records_when_inline() {
        let (workspace, svc) = new_ws("agy-dedup");
        fs::write(workspace.join("small.cpp"), "int small_ok = 1;\n").unwrap();
        let big_body = (1..=320)
            .map(|i| format!("int big_line_{i:03} = {i}; // padding_0123456789_abcdef\n"))
            .collect::<String>();
        fs::write(workspace.join("large.cpp"), &big_body).unwrap();

        // 1. Oversized AGY read (> AGY_MCP_INLINE_CAP) must NOT poison SessionState with ALREADY IN CONTEXT
        let oversized = op_read_for_host(
            &svc, &["small.cpp".into(), "large.cpp".into()], 16_384, false,
            Some("agy-sess-1"), Some(&workspace), Some(AGY_MCP_INLINE_CAP), false,
        ).unwrap();
        assert!(oversized.len() > AGY_MCP_INLINE_CAP);

        let re_read = op_read_for_host(
            &svc, &["small.cpp".into()], AGY_MCP_DEFAULT_MAX_BYTES, false,
            Some("agy-sess-1"), Some(&workspace), Some(AGY_MCP_INLINE_CAP), false,
        ).unwrap();
        assert!(re_read.contains("small_ok = 1;") && !re_read.contains("ALREADY IN CONTEXT"));

        // 2. Now that `small.cpp` fit inline (<= AGY_MCP_INLINE_CAP), the next identical read deduplicates cleanly
        let dedup = op_read_for_host(
            &svc, &["small.cpp".into()], AGY_MCP_DEFAULT_MAX_BYTES, false,
            Some("agy-sess-1"), Some(&workspace), Some(AGY_MCP_INLINE_CAP), false,
        ).unwrap();
        assert!(dedup.contains("ALREADY IN CONTEXT"));

        // 3. Default AGY cap note recommends parallel native read_file
        let capped = op_read_for_host(
            &svc, &["large.cpp".into()], AGY_MCP_DEFAULT_MAX_BYTES, true,
            Some("agy-sess-2"), Some(&workspace), Some(AGY_MCP_INLINE_CAP), false,
        ).unwrap();
        assert!(capped.len() <= AGY_MCP_INLINE_CAP && capped.contains("read_file"));
        fs::remove_dir_all(&workspace).unwrap();
    }

    #[test]
    fn op_read_hashes_formats_line_anchors_and_preserves_plain_output() {
        let (workspace, svc) = new_ws("read-hashes");
        fs::write(workspace.join("sample.rs"), "let alpha = 1;\nlet beta = 2;\n").unwrap();
        let plain = op_read_for_host(&svc, &["sample.rs".into()], 4096, true, None, Some(&workspace), None, false).unwrap();
        assert!(plain.contains("1: let alpha = 1;\n2: let beta = 2;\n"));
        let hashed = op_read_for_host(&svc, &["sample.rs".into()], 4096, true, None, Some(&workspace), None, true).unwrap();
        let (h1, h2) = (line_hash3("let alpha = 1;"), line_hash3("let beta = 2;"));
        assert!(hashed.contains(&format!(
            "1:{}| let alpha = 1;\n2:{}| let beta = 2;\n",
            std::str::from_utf8(&h1).unwrap(), std::str::from_utf8(&h2).unwrap()
        )));
        fs::remove_dir_all(&workspace).unwrap();
    }

    #[test]
    fn delta_read_small_edit_hashes_dedup_and_force_full() {
        let (ws, svc) = new_ws("delta-small");
        let path = ws.join("mod.rs");
        let mut lines = make_lines(40);
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let first = op_read_for_host(&svc, &["mod.rs".into()], 16_384, false, Some("s1"), Some(&ws), None, true).unwrap();
        assert!(first.contains("(lines 1-40 of 40"));

        // Unchanged -> ALREADY IN CONTEXT
        let dup = op_read_for_host(&svc, &["mod.rs".into()], 16_384, false, Some("s1"), Some(&ws), None, true).unwrap();
        assert!(dup.contains("ALREADY IN CONTEXT"));

        // Small multi-hunk edit (+2/-1 lines, file grows 40 -> 41) -> compact DELTA with fresh hashes
        lines[9] = "let value_010 = 9999; // edited_line_ten".into();
        lines.insert(30, "let inserted_31 = 3131; // brand_new_line".into());
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let delta = op_read_for_host(&svc, &["mod.rs".into()], 16_384, false, Some("s1"), Some(&ws), None, true).unwrap();
        assert!(delta.contains("[DELTA since last read: +2/-1 lines, total 41 lines; pass force=true for full]"));
        assert!(delta.contains("-10: let value_010 = 10;"));
        let h10 = line_hash3(&lines[9]);
        let h31 = line_hash3(&lines[30]);
        let h9 = line_hash3(&lines[8]);
        assert!(delta.contains(&format!("+10:{}| {}", std::str::from_utf8(&h10).unwrap(), lines[9])));
        assert!(delta.contains(&format!("+31:{}| {}", std::str::from_utf8(&h31).unwrap(), lines[30])));
        assert!(delta.contains(&format!(" 9:{}| {}", std::str::from_utf8(&h9).unwrap(), lines[8])));
        assert!(delta.contains("...\n"));

        // Re-reading right after delta -> ALREADY IN CONTEXT (session updated to new hash)
        let after = op_read_for_host(&svc, &["mod.rs".into()], 16_384, false, Some("s1"), Some(&ws), None, true).unwrap();
        assert!(after.contains("ALREADY IN CONTEXT"));

        // force=true always yields full read
        let forced = op_read_for_host(&svc, &["mod.rs".into()], 16_384, true, Some("s1"), Some(&ws), None, false).unwrap();
        assert!(forced.contains("(lines 1-41 of 41") && !forced.contains("[DELTA"));
        fs::remove_dir_all(&ws).unwrap();
    }

    #[test]
    fn delta_read_large_rewrite_falls_back_and_respects_agy_inline_cap() {
        let (ws, svc) = new_ws("delta-gates");
        let path = ws.join("wide.rs");
        let mut lines = make_lines(40);
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let big = (1..=300).map(|i| format!("let pad_{i:03} = {i}; // padding_0123456789_abcdef\n")).collect::<String>();
        fs::write(ws.join("pad.rs"), &big).unwrap();

        let _ = op_read_for_host(&svc, &["wide.rs".into()], 16_384, false, Some("s2"), Some(&ws), Some(AGY_MCP_INLINE_CAP), false).unwrap();

        // Small edit combined in oversized AGY batch (> AGY_MCP_INLINE_CAP): emits DELTA but must NOT advance SessionState
        lines[19] = "let value_020 = 2020; // agy_cap_edit".into();
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let oversized = op_read_for_host(
            &svc, &["wide.rs".into(), "pad.rs".into()], 16_384, false,
            Some("s2"), Some(&ws), Some(AGY_MCP_INLINE_CAP), false,
        ).unwrap();
        assert!(oversized.len() > AGY_MCP_INLINE_CAP && oversized.contains("[DELTA since last read: +1/-1"));

        // Subsequent inline read must STILL get DELTA (not ALREADY IN CONTEXT!) and now record it
        let inline_delta = op_read_for_host(
            &svc, &["wide.rs".into()], AGY_MCP_DEFAULT_MAX_BYTES, false,
            Some("s2"), Some(&ws), Some(AGY_MCP_INLINE_CAP), false,
        ).unwrap();
        assert!(
            inline_delta.contains("[DELTA since last read: +1/-1")
                && inline_delta.contains("+20: let value_020 = 2020; // agy_cap_edit\n")
                && inline_delta.contains(" 19: let value_019 = 19;")
                && !inline_delta.contains("ALREADY IN CONTEXT")
        );

        // >25% rewrite (12/40 = 30%) falls back to normal full read
        for row in lines.iter_mut().take(12) { *row = format!("{row}_rewritten"); }
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let full = op_read_for_host(&svc, &["wide.rs".into()], 16_384, false, Some("s2"), Some(&ws), None, false).unwrap();
        assert!(full.contains("(lines 1-40 of 40") && !full.contains("[DELTA"));
        fs::remove_dir_all(&ws).unwrap();
    }
}
