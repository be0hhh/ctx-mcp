//! Hash-anchored line addressing (`<line>:<3-hex>`) and conflict/post-edit window rendering.

use crate::base::simd::{line_hash3, push_usize};
use crate::store::CachedFile;

/// Parses `"223:a4f"` (or `"0:000"` for BOF insert) into `(line_1based, lowercase_hex3)`.
pub fn parse_line_anchor(raw: &str) -> Result<(usize, [u8; 3]), String> {
    let trimmed = raw.trim();
    let Some((line_part, hash_part)) = trimmed.split_once(':') else {
        return Err(format!(
            "invalid line anchor `{raw}`: expected `<line>:<3-hex>`"
        ));
    };
    let line_str = line_part.trim();
    if line_str.is_empty() || !line_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid line number in anchor `{raw}`"));
    }
    let line = line_str
        .parse::<usize>()
        .map_err(|_| format!("line number overflow in anchor `{raw}`"))?;
    let hb = hash_part.trim().as_bytes();
    if hb.len() != 3 || !hb.iter().all(u8::is_ascii_hexdigit) {
        return Err(format!(
            "invalid 3-hex hash in anchor `{raw}`: expected 3 ASCII hex digits"
        ));
    }
    let norm = [
        hb[0].to_ascii_lowercase(),
        hb[1].to_ascii_lowercase(),
        hb[2].to_ascii_lowercase(),
    ];
    if line == 0 && norm != *b"000" {
        return Err(format!(
            "invalid BOF anchor `{raw}`: line 0 requires `0:000`"
        ));
    }
    Ok((line, norm))
}

/// Returns the 3-character hex anchor string view.
#[inline]
pub fn hash3_str(h: &[u8; 3]) -> &str {
    std::str::from_utf8(h).unwrap_or("???")
}

/// Normalizes a line before hashing (strips UTF-8 BOM on line 1 so disk and cache match).
#[inline]
pub(super) fn canonical_line_text(line_1based: usize, raw_line: &str) -> &str {
    if line_1based == 1 {
        raw_line.strip_prefix('\u{FEFF}').unwrap_or(raw_line)
    } else {
        raw_line
    }
}

/// Computes the 3-hex anchor for a logical 1-based line.
#[inline]
pub(super) fn line_anchor_hash(line_1based: usize, raw_line: &str) -> [u8; 3] {
    line_hash3(canonical_line_text(line_1based, raw_line))
}

/// Appends `<ln>:<h3>| <line>\n` to `out`.
#[inline]
pub(super) fn push_hashed_line(out: &mut String, line_1based: usize, raw_line: &str) {
    let line = canonical_line_text(line_1based, raw_line);
    let h = line_hash3(line);
    push_usize(out, line_1based);
    out.push(':');
    out.push_str(hash3_str(&h));
    out.push_str("| ");
    out.push_str(line);
    out.push('\n');
}

/// Formats `[focus-radius ..= focus+radius]` with `<ln>:<h3>| <line>\n` for immediate retry.
pub fn format_conflict_window(entry: &CachedFile, focus_line: usize, radius: usize) -> String {
    let total = entry.line_count as usize;
    if total == 0 {
        return "(empty file; use anchor `0:000` with `insert_after`)\n".to_string();
    }
    let focus = focus_line.clamp(1, total);
    let start = focus.saturating_sub(radius).max(1);
    let end = focus.saturating_add(radius).min(total);
    let mut out = String::with_capacity((end - start + 1) * 48);
    for ln in start..=end {
        push_hashed_line(&mut out, ln, entry.line_slice(ln as u32));
    }
    out
}

/// Formats a conflict window directly from an in-RAM line slice when disk state differs from cache.
pub(super) fn format_conflict_window_lines(
    lines: &[String],
    focus_line: usize,
    radius: usize,
) -> String {
    let total = lines.len();
    if total == 0 {
        return "(empty file; use anchor `0:000` with `insert_after`)\n".to_string();
    }
    let focus = focus_line.clamp(1, total);
    let start = focus.saturating_sub(radius).max(1);
    let end = focus.saturating_add(radius).min(total);
    let mut out = String::with_capacity((end - start + 1) * 48);
    for ln in start..=end {
        push_hashed_line(&mut out, ln, &lines[ln - 1]);
    }
    out
}

/// Emits updated `<ln>:<h3>| <line>` anchor windows around each edited `(start, end)` range.
pub(super) fn append_anchor_windows(
    out: &mut String,
    lines: &[String],
    ranges: &[(usize, usize)],
) {
    let total = lines.len();
    if total == 0 {
        out.push_str("(file now empty; use `0:000` to insert)\n");
        return;
    }
    let mut last = 0usize;
    for &(s, e) in ranges {
        let ws = s.saturating_sub(1).max(1).max(last + 1);
        let we = e.saturating_add(1).min(total);
        if ws > we {
            continue;
        }
        let cap = we.min(ws.saturating_add(23));
        for ln in ws..=cap {
            push_hashed_line(out, ln, &lines[ln - 1]);
            last = ln;
        }
        if cap < we {
            out.push_str("... (+");
            push_usize(out, we - cap);
            out.push_str(" more edited lines)\n");
            last = we;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::simd::scan_source_bytes;
    use crate::store::{ParsedBody, PathId};
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    fn mock_entry(text: &str) -> CachedFile {
        let scanned = scan_source_bytes(text.as_bytes().to_vec()).unwrap();
        let line_count = scanned.line_count;
        let body = ParsedBody::for_test(scanned.text, scanned.line_offsets, line_count);
        CachedFile {
            norm_path: Arc::from("sample.rs"),
            rel_path: Box::from("sample.rs"),
            mtime_ns: 0,
            ctime_ns: 0,
            ino: 0,
            content_hash64: 0,
            path_id: PathId(0),
            size_bytes: text.len() as u32,
            line_count,
            symbols: Arc::from([]),
            body: Some(body),
            last_access: AtomicU64::new(0),
        }
    }

    #[test]
    fn parse_line_anchor_validates_hex_case_and_bof() {
        assert_eq!(parse_line_anchor("223:a4f").unwrap(), (223, *b"a4f"));
        assert_eq!(parse_line_anchor(" 42:A0F ").unwrap(), (42, *b"a0f"));
        assert_eq!(parse_line_anchor("0:000").unwrap(), (0, *b"000"));
        assert_eq!(hash3_str(b"a4f"), "a4f");

        assert!(parse_line_anchor("0:001").is_err());
        assert!(parse_line_anchor("12:ab").is_err());
        assert!(parse_line_anchor("12:abcd").is_err());
        assert!(parse_line_anchor("12:xyz").is_err());
        assert!(parse_line_anchor("abc:123").is_err());
        assert!(parse_line_anchor("42").is_err());
        assert!(parse_line_anchor("").is_err());
    }

    #[test]
    fn conflict_window_clamps_bounds_and_handles_empty_and_bom() {
        let empty = mock_entry("");
        assert!(format_conflict_window(&empty, 1, 2).contains("0:000"));

        let entry = mock_entry("\u{FEFF}alpha\nbeta\ngamma\ndelta\nepsilon\n");
        let win = format_conflict_window(&entry, 1, 1);
        let h1 = line_hash3("alpha");
        let h2 = line_hash3("beta");
        assert!(win.contains(&format!("1:{}| alpha\n", hash3_str(&h1))));
        assert!(win.contains(&format!("2:{}| beta\n", hash3_str(&h2))));
        assert!(!win.contains("gamma"));

        let tail = format_conflict_window(&entry, 99, 1);
        assert!(tail.contains("delta") && tail.contains("epsilon") && !tail.contains("beta"));
    }
}
