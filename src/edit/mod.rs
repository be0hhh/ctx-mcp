//! Universal hashline edit & scoped symbol-rename engine, caller/impact graph, and read-only
//! git inspection (`ctx_impact`, `ctx_edit`, `ctx_git`). Zero external crates,
//! zero `div`/`idiv`, and zero project hardcodes (all project hooks go through
//! `crate::base::ext::policy()`).

pub mod apply;
pub mod git;
pub mod hashline;
pub mod impact;
pub mod refactor;

#[allow(unused_imports)]
pub use apply::{op_edit, op_edit_with_session};
pub use git::op_git;
pub use hashline::{format_conflict_window, parse_line_anchor};
#[allow(unused_imports)]
pub use impact::{op_impact, op_impact_with_git};
#[allow(unused_imports)]
pub use refactor::{op_refactor, op_refactor_with_session};

use crate::parser::{build_cleaned_code_buffer_for_ext, SymbolKind, SymbolSpan};
use crate::store::CachedFile;
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static SHARED_TMP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Returns the innermost non-namespace symbol covering 1-based `line`.
pub(super) fn enclosing_scope(entry: &CachedFile, line: usize) -> Option<&SymbolSpan> {
    entry
        .symbols
        .iter()
        .filter(|sym| {
            sym.kind != SymbolKind::Namespace
                && (sym.start_line as usize..=sym.end_line as usize).contains(&line)
        })
        .min_by_key(|sym| sym.end_line.saturating_sub(sym.start_line))
}

/// Collects deduplicated `@symbol` labels overlapping any inclusive 1-based `(start, end)` range.
pub(super) fn collect_overlapping_symbols(
    entry: &CachedFile,
    ranges: &[(usize, usize)],
) -> Vec<String> {
    collect_overlapping_symbol_spans(&entry.symbols, ranges)
}

/// Collects deduplicated `@symbol` labels from an explicit symbol span slice (used for dry-run preview).
pub(super) fn collect_overlapping_symbol_spans(
    symbols: &[SymbolSpan],
    ranges: &[(usize, usize)],
) -> Vec<String> {
    let mut out = Vec::new();
    for &(s, e) in ranges {
        for sym in symbols {
            if sym.kind == SymbolKind::Namespace {
                continue;
            }
            if (sym.start_line as usize) <= e && (sym.end_line as usize) >= s {
                let name = sym.name.trim_start_matches("::");
                if !name.is_empty() {
                    let tag = format!("@{name}");
                    if !out.contains(&tag) {
                        out.push(tag);
                    }
                }
            }
        }
    }
    out
}

/// Computes 0-based byte start offsets for each 1-based line (matching `scan_source_bytes`).
pub(super) fn line_offsets_for_text(text: &str) -> Vec<u32> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut offsets = Vec::with_capacity((bytes.len() >> 5).max(16));
    offsets.push(0);
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' && i + 1 < bytes.len() {
            offsets.push((i + 1) as u32);
        }
    }
    offsets
}

pub(super) const MAX_DIFF_LINES_PER_FILE: usize = 24;
pub(super) const MAX_DIFF_BYTES_PER_FILE: usize = 2_048;
const MAX_DIFF_LINE_BYTES: usize = 240;

pub(super) fn detect_line_ending(body: &str) -> &'static str {
    let b = body.as_bytes();
    if let Some(nl) = b.iter().position(|&c| c == b'\n') {
        if nl > 0 && b[nl - 1] == b'\r' {
            return "\r\n";
        }
    }
    "\n"
}

pub(super) fn join_body_lines(
    lines: &[String],
    ending: &str,
    had_trailing_nl: bool,
    was_empty: bool,
) -> String {
    let mut out = String::new();
    if !lines.is_empty() {
        for (idx, line) in lines.iter().enumerate() {
            if idx > 0 {
                out.push_str(ending);
            }
            out.push_str(line);
        }
        if had_trailing_nl || was_empty {
            out.push_str(ending);
        }
    }
    out
}

pub(super) fn push_merged_range(ranges: &mut Vec<(usize, usize)>, s: usize, e: usize) {
    if let Some(last) = ranges.last_mut() {
        if s <= last.1.saturating_add(1) {
            last.1 = last.1.max(e);
            return;
        }
    }
    ranges.push((s, e));
}

pub(super) fn push_diff_line(
    buf: &mut String,
    emitted: &mut usize,
    omitted: &mut usize,
    sign: char,
    ln: usize,
    line: &str,
) {
    if *omitted > 0 || *emitted >= MAX_DIFF_LINES_PER_FILE {
        *omitted += 1;
        return;
    }
    let mut entry = String::with_capacity(line.len().min(MAX_DIFF_LINE_BYTES) + 16);
    entry.push(sign);
    entry.push('L');
    crate::base::simd::push_usize(&mut entry, ln);
    entry.push(' ');
    if line.len() > MAX_DIFF_LINE_BYTES {
        let mut cut = MAX_DIFF_LINE_BYTES;
        while !line.is_char_boundary(cut) {
            cut -= 1;
        }
        entry.push_str(&line[..cut]);
        entry.push_str("...");
    } else {
        entry.push_str(line);
    }
    entry.push('\n');
    if buf.len().saturating_add(entry.len()) > MAX_DIFF_BYTES_PER_FILE {
        *omitted += 1;
        return;
    }
    buf.push_str(&entry);
    *emitted += 1;
}

/// Non-blocking delimiter balance check over a comment/string-cleaned buffer.
/// Skips C/C++ files containing `#if`/`#ifdef`/`#ifndef` so conditional compilation never false-positives.
pub(super) fn check_delimiter_balance(text: &str, ext: &str) -> Option<String> {
    let is_cpp = matches!(
        ext,
        "c" | "h" | "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" | "inl" | "tpp" | "cu" | "cuh"
    );
    let is_code = is_cpp
        || matches!(
            ext,
            "rs" | "js"
                | "jsx"
                | "ts"
                | "tsx"
                | "mjs"
                | "cjs"
                | "go"
                | "java"
                | "cs"
                | "kt"
                | "kts"
                | "swift"
                | "zig"
                | "py"
                | "pyi"
                | "json"
                | "jsonc"
                | "proto"
        );
    if !is_code {
        return None;
    }
    if is_cpp
        && text.lines().any(|l| {
            l.trim_start()
                .strip_prefix('#')
                .is_some_and(|r| r.trim_start().starts_with("if"))
        })
    {
        return None;
    }
    let cleaned = build_cleaned_code_buffer_for_ext(text, ext);
    let mut stack: Vec<(u8, usize)> = Vec::new();
    let mut ln = 1usize;
    for &b in cleaned.as_bytes() {
        match b {
            b'\n' => ln += 1,
            b'{' | b'(' | b'[' => stack.push((b, ln)),
            b'}' | b')' | b']' => {
                let want = match b {
                    b'}' => b'{',
                    b')' => b'(',
                    _ => b'[',
                };
                if !matches!(stack.pop(), Some((open, _)) if open == want) {
                    return Some(format!("[syntax] L{ln}: unexpected `{}`", b as char));
                }
            }
            _ => {}
        }
    }
    stack
        .pop()
        .map(|(open, open_ln)| format!("[syntax] L{open_ln}: unclosed `{}`", open as char))
}

/// Returns the non-recursive regular-file count in `path`'s parent directory.
pub(super) fn count_dir_files(path: &Path) -> usize {
    let Some(parent) = path.parent() else {
        return 0;
    };
    let Ok(rd) = fs::read_dir(parent) else {
        return 0;
    };
    let mut count = 0usize;
    for item in rd.flatten() {
        let name = item.file_name();
        if name
            .to_str()
            .is_some_and(|s| s.starts_with(".ctx-edit.") && s.ends_with(".tmp"))
        {
            continue;
        }
        if item.file_type().is_ok_and(|ft| ft.is_file()) {
            count += 1;
        }
    }
    count
}

#[inline]
pub(super) fn line_count_flag(line_count: usize) -> &'static str {
    if line_count > 800 {
        " [OVER 800L]"
    } else if line_count >= 600 {
        " [>=600L]"
    } else {
        ""
    }
}

pub(super) fn ext_lower_buf<'a>(path: &Path, buf: &'a mut [u8; 16]) -> &'a str {
    let Some(raw) = path.extension().and_then(|s| s.to_str()) else {
        return "";
    };
    if raw.len() > buf.len() || !raw.is_ascii() {
        return "";
    }
    for (i, b) in raw.bytes().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    std::str::from_utf8(&buf[..raw.len()]).unwrap_or("")
}

pub(super) fn cap_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let note = "... [truncated at max_bytes]\n";
    if max_bytes <= note.len() {
        return note[..max_bytes].to_string();
    }
    let mut end = max_bytes - note.len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + note.len());
    out.push_str(&text[..end]);
    out.push_str(note);
    out
}

/// Atomic same-directory temp write with `0o600` creation + permission preservation on Unix
/// and readonly-safe `.bak` fallback replace on Windows.
pub(super) fn atomic_write_file(
    target: &Path,
    data: &[u8],
    orig_perms: &Permissions,
) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("target has no parent: {}", target.display()))?;
    let seq = SHARED_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".ctx-edit.{}.r{seq}.tmp", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("create temp {}: {e}", tmp.display()))?;
    if let Err(e) = f.write_all(data).and_then(|_| f.flush()) {
        drop(f);
        let _ = fs::remove_file(&tmp);
        return Err(format!("write temp {}: {e}", tmp.display()));
    }
    drop(f);
    #[cfg(unix)]
    if let Err(e) =
        fs::set_permissions(&tmp, orig_perms.clone()).and_then(|_| fs::rename(&tmp, target))
    {
        let _ = fs::remove_file(&tmp);
        return Err(format!("commit {}: {e}", target.display()));
    }
    #[cfg(not(unix))]
    {
        if orig_perms.readonly() {
            let mut w = orig_perms.clone();
            w.set_readonly(false);
            let _ = fs::set_permissions(target, w);
        }
        if let Err(e) = fs::rename(&tmp, target) {
            let bak = parent.join(format!(".ctx-edit.{}.r{seq}.bak", std::process::id()));
            if fs::rename(target, &bak)
                .and_then(|_| fs::rename(&tmp, target))
                .is_ok()
            {
                let _ = fs::remove_file(&bak);
            } else {
                if bak.exists() && !target.exists() {
                    let _ = fs::rename(&bak, target);
                }
                let _ = fs::remove_file(&tmp);
                return Err(format!("replace {}: {e}", target.display()));
            }
        }
        let _ = fs::set_permissions(target, orig_perms.clone());
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) struct AtomicWriteEntry<'a> {
    pub canon: &'a Path,
    pub rel_path: &'a str,
    pub orig_perms: &'a Permissions,
    pub orig_bytes: &'a [u8],
    pub new_bytes: &'a [u8],
}

/// Writes all entries sequentially with full reverse-order rollback on any commit failure.
#[allow(dead_code)]
pub(super) fn commit_atomic_batch<F>(entries: &[AtomicWriteEntry<'_>], mut writer: F) -> Result<(), String>
where
    F: FnMut(&Path, &[u8], &Permissions) -> Result<(), String>,
{
    for (idx, entry) in entries.iter().enumerate() {
        if let Err(commit_err) = writer(entry.canon, entry.new_bytes, entry.orig_perms) {
            let committed: Vec<&str> = entries[..idx].iter().map(|e| e.rel_path).collect();
            let (mut rolled_back, mut rollback_failed) = (Vec::new(), Vec::new());
            for prev in entries[..idx].iter().rev() {
                match writer(prev.canon, prev.orig_bytes, prev.orig_perms) {
                    Ok(()) => rolled_back.push(prev.rel_path),
                    Err(rb_err) => rollback_failed.push(format!("{} ({rb_err})", prev.rel_path)),
                }
            }
            if !rollback_failed.is_empty() {
                return Err(format!(
                    "partial_commit: failed on `{}` ({commit_err}); committed=[{}]; rolled_back=[{}]; rollback_failed=[{}]",
                    entry.rel_path, committed.join(", "), rolled_back.join(", "), rollback_failed.join(", ")
                ));
            }
            return Err(format!(
                "commit failed on `{}` ({commit_err}); rolled back {} file(s)",
                entry.rel_path,
                rolled_back.len()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_atomic_batch_rolls_back_and_reports_partial_commit() {
        let ws = std::env::temp_dir().join(format!("ctx-rb-{}-{}", std::process::id(), crate::store::now_ms_u64()));
        fs::create_dir_all(&ws).unwrap();
        let (a, b) = (ws.join("a.rs"), ws.join("b.rs"));
        fs::write(&a, "a0\n").unwrap();
        fs::write(&b, "b0\n").unwrap();
        let perms = fs::metadata(&a).unwrap().permissions();
        let entries = [
            AtomicWriteEntry { canon: &a, rel_path: "a.rs", orig_perms: &perms, orig_bytes: b"a0\n", new_bytes: b"a1\n" },
            AtomicWriteEntry { canon: &b, rel_path: "b.rs", orig_perms: &perms, orig_bytes: b"b0\n", new_bytes: b"b1\n" },
        ];
        let mut writes = Vec::new();
        let err = commit_atomic_batch(&entries, |p, data, _| {
            if p == b.as_path() { return Err("disk full".into()); }
            writes.push(data.to_vec());
            Ok(())
        }).unwrap_err();
        assert!(err.contains("rolled back 1 file(s)") && writes == vec![b"a1\n".to_vec(), b"a0\n".to_vec()]);
        let mut calls = 0usize;
        let partial = commit_atomic_batch(&entries, |_, _, _| { calls += 1; if calls == 1 { Ok(()) } else { Err("io".into()) } }).unwrap_err();
        assert!(partial.starts_with("partial_commit:") && partial.contains("committed=[a.rs]") && partial.contains("rollback_failed=[a.rs"));
        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn diff_line_cap_enforces_24_lines_and_monotonic_omission() {
        let (mut buf, mut emitted, mut omitted) = (String::new(), 0usize, 0usize);
        for ln in 1..=30 {
            push_diff_line(&mut buf, &mut emitted, &mut omitted, '+', ln, "let v = 1;");
        }
        assert_eq!(emitted, MAX_DIFF_LINES_PER_FILE);
        assert_eq!(omitted, 6);
        assert!(buf.len() <= MAX_DIFF_BYTES_PER_FILE);
    }
}
