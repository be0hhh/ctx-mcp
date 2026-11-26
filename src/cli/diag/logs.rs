//! ANSI/CR stripping and generic log template deduplication (`ctx diag`).
//! Strictly bounded memory (`MAX_UNIQUE_TEMPLATES = 1024`), O(1) hashing via
//! `fast_hash64`, 0 external crates, and 0 runtime `div`/`idiv`.

use crate::base::simd::{fast_hash64, find_ansi_or_cr, push_usize, FastHashMap};
use std::borrow::Cow;
use std::collections::VecDeque;

pub const MAX_UNIQUE_TEMPLATES: usize = 1024;
const MAX_OSC_BYTES: usize = 256;
const MAX_LINE_DISPLAY: usize = 240;

#[inline]
pub(super) fn find_esc_or_cr(bytes: &[u8]) -> Option<usize> {
    let pos = find_ansi_or_cr(bytes, 0);
    (pos < bytes.len()).then_some(pos)
}

#[inline]
fn floor_utf8(s: &str, max_bytes: usize) -> usize {
    let mut end = max_bytes.min(s.len());
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    end
}

pub(super) fn truncate_utf8_bytes(s: &mut String, max_bytes: usize) {
    if s.len() > max_bytes { let end = floor_utf8(s, max_bytes); s.truncate(end); }
}

#[inline]
pub(super) fn clip_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes { s } else { &s[..floor_utf8(s, max_bytes)] }
}

/// Strips ANSI CSI (`\x1b[...final`) and bounded OSC (`\x1b]...(\x07|\x1b\\)`, <=256B),
/// handles CRLF cleanly, and collapses `\r` progress overwrites to the last non-empty segment.
pub fn strip_ansi_and_cr(raw_line: &str) -> Cow<'_, str> {
    if find_esc_or_cr(raw_line.as_bytes()).is_none() { return Cow::Borrowed(raw_line); }
    let base = raw_line.strip_suffix("\r\n").or_else(|| raw_line.strip_suffix('\r')).unwrap_or(raw_line);
    if !base.as_bytes().contains(&b'\r') { return strip_ansi_only(base); }
    let mut fallback: Option<Cow<'_, str>> = None;
    for seg in base.trim_end_matches('\r').rsplit('\r') {
        if seg.is_empty() { continue; }
        let cleaned = strip_ansi_only(seg);
        if !cleaned.trim().is_empty() { return cleaned; }
        if fallback.is_none() && !cleaned.is_empty() { fallback = Some(cleaned); }
    }
    fallback.unwrap_or(Cow::Borrowed(""))
}

fn strip_ansi_only(s: &str) -> Cow<'_, str> {
    if !s.as_bytes().contains(&0x1b) { return Cow::Borrowed(s); }
    let (b, mut out, mut i) = (s.as_bytes(), Vec::with_capacity(s.len()), 0usize);
    while i < b.len() {
        if b[i] != 0x1b { out.push(b[i]); i += 1; continue; }
        match b.get(i + 1).copied() {
            Some(b'[') => {
                i += 2;
                while i < b.len() && !(0x40..=0x7e).contains(&b[i]) { i += 1; }
                if i < b.len() { i += 1; }
            }
            Some(b']') => {
                let (mut j, limit) = (i + 2, (i + 2).saturating_add(MAX_OSC_BYTES).min(b.len()));
                let mut next = limit;
                while j < limit {
                    if b[j] == 0x07 { next = j + 1; break; }
                    if b[j] == 0x1b && b.get(j + 1) == Some(&b'\\') { next = j + 2; break; }
                    j += 1;
                }
                i = next;
            }
            Some(b'(' | b')') if i + 2 < b.len() => i += 3,
            Some(c) if (0x40..=0x5f).contains(&c) => i += 2,
            _ => i += 1,
        }
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

struct LogTemplate { sample: String, count: usize, severity: u8, first_order: usize }

pub fn compress_generic_logs(raw: &str, max_bytes: usize) -> String {
    let mut map: FastHashMap<u64, usize> = FastHashMap::default();
    let mut templates: Vec<LogTemplate> = Vec::new();
    let mut tpl_buf: Vec<u8> = Vec::with_capacity(256);
    let mut tail: VecDeque<String> = VecDeque::with_capacity(6);
    let (mut total_lines, mut capped) = (0usize, 0usize);

    for raw_line in raw.lines() {
        let clean = strip_ansi_and_cr(raw_line);
        let trimmed = clean.trim();
        if trimmed.is_empty() { continue; }
        total_lines += 1;
        let disp = clip_str(trimmed, MAX_LINE_DISPLAY);
        if let Some(pos) = tail.iter().position(|s| s == disp) { tail.remove(pos); }
        else if tail.len() == 5 { tail.pop_front(); }
        tail.push_back(disp.to_string());

        normalize_log_template(trimmed.as_bytes(), &mut tpl_buf);
        let h = fast_hash64(&tpl_buf);
        if let Some(&slot) = map.get(&h) {
            templates[slot].count += 1;
        } else if templates.len() < MAX_UNIQUE_TEMPLATES {
            let idx = templates.len();
            map.insert(h, idx);
            templates.push(LogTemplate {
                sample: disp.to_string(), count: 1,
                severity: score_severity(trimmed.as_bytes()), first_order: idx,
            });
        } else { capped += 1; }
    }
    if total_lines == 0 { return "[ctx diag: logs, 0 lines -> 0 unique templates]\n".to_string(); }

    let mut order: Vec<usize> = (0..templates.len()).collect();
    order.sort_unstable_by(|&a, &b| {
        let (ta, tb) = (&templates[a], &templates[b]);
        tb.severity.cmp(&ta.severity)
            .then_with(|| tb.count.cmp(&ta.count))
            .then_with(|| ta.first_order.cmp(&tb.first_order))
    });

    let mut tail_block = String::with_capacity(256);
    tail_block.push_str("--- tail (last "); push_usize(&mut tail_block, tail.len());
    tail_block.push_str(" distinct) ---\n");
    for line in &tail { tail_block.push_str(line); tail_block.push('\n'); }
    let body_limit = max_bytes.saturating_sub(tail_block.len().min(max_bytes >> 1));

    let mut out = String::with_capacity(max_bytes.min(4096));
    out.push_str("[ctx diag: logs, "); push_usize(&mut out, total_lines);
    out.push_str(" lines -> "); push_usize(&mut out, templates.len());
    out.push_str(" unique templates]\n");

    let mut emitted = 0usize;
    for &idx in &order {
        let t = &templates[idx];
        let extra = t.sample.len() + if t.count > 1 { 20 } else { 2 };
        if emitted > 0 && out.len().saturating_add(extra) > body_limit { break; }
        out.push_str(&t.sample);
        if t.count > 1 { out.push_str(" (\u{00d7}"); push_usize(&mut out, t.count); out.push(')'); }
        out.push('\n');
        emitted += 1;
    }
    let omitted = templates.len().saturating_sub(emitted).saturating_add(capped);
    if omitted > 0 && out.len().saturating_add(40) <= body_limit {
        out.push_str("... (+"); push_usize(&mut out, omitted); out.push_str(" more templates omitted)\n");
    }
    if out.len().saturating_add(24) < max_bytes {
        for line in tail_block.lines() {
            if out.len().saturating_add(line.len() + 1) > max_bytes { break; }
            out.push_str(line); out.push('\n');
        }
    }
    truncate_utf8_bytes(&mut out, max_bytes);
    out
}

fn normalize_log_template(b: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let mut i = if let Some(skip) = match_syslog_prefix(b) { out.push(b'#'); skip } else { 0 };
    while i < b.len() {
        if let Some(skip) = match_iso_timestamp(b, i) { push_hash(out); i = skip; }
        else if is_uuid_at(b, i) { push_hash(out); i += 36; }
        else if b[i] == b'0' && matches!(b.get(i + 1), Some(b'x' | b'X'))
            && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            out.extend_from_slice(b"0x#");
            i += 2;
            while i < b.len() && b[i].is_ascii_hexdigit() { i += 1; }
        } else if let Some(skip) = match_ipv4_opt_port(b, i) { push_hash(out); i = skip; }
        else if b[i].is_ascii_digit() {
            push_hash(out);
            while i < b.len() && b[i].is_ascii_digit() { i += 1; }
        } else { out.push(b[i]); i += 1; }
    }
}

#[inline]
fn push_hash(out: &mut Vec<u8>) { if out.last() != Some(&b'#') { out.push(b'#'); } }

fn match_syslog_prefix(b: &[u8]) -> Option<usize> {
    const MONTHS: [&[u8; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
    ];
    if b.len() < 14 || b[3] != b' ' || !MONTHS.iter().any(|m| &b[0..3] == m.as_slice()) { return None; }
    let mut i = if b.get(4) == Some(&b' ') { 5 } else { 4 };
    let d0 = i;
    while i < b.len() && b[i].is_ascii_digit() { i += 1; }
    if i == d0 || b.get(i) != Some(&b' ') { return None; }
    i += 1;
    (i + 8 <= b.len() && b[i + 2] == b':' && b[i + 5] == b':').then_some(i + 8)
}

fn match_iso_timestamp(b: &[u8], i: usize) -> Option<usize> {
    if i + 10 > b.len() || b[i + 4] != b'-' || b[i + 7] != b'-'
        || !b[i..i + 4].iter().all(u8::is_ascii_digit)
        || !b[i + 5..i + 7].iter().all(u8::is_ascii_digit)
        || !b[i + 8..i + 10].iter().all(u8::is_ascii_digit) { return None; }
    let mut j = i + 10;
    if matches!(b.get(j), Some(b'T' | b' ')) && j + 9 <= b.len() && b[j + 3] == b':' && b[j + 6] == b':' {
        j += 9;
        if matches!(b.get(j), Some(b'.' | b',')) {
            j += 1;
            while j < b.len() && b[j].is_ascii_digit() { j += 1; }
        }
        if b.get(j) == Some(&b'Z') { j += 1; }
        else if matches!(b.get(j), Some(b'+' | b'-')) && j + 6 <= b.len() && b[j + 3] == b':' { j += 6; }
    }
    Some(j)
}

fn is_uuid_at(b: &[u8], i: usize) -> bool {
    if i + 36 > b.len() || (i > 0 && b[i - 1].is_ascii_alphanumeric())
        || b.get(i + 36).is_some_and(u8::is_ascii_alphanumeric) { return false; }
    let s = &b[i..i + 36];
    s[8] == b'-' && s[13] == b'-' && s[18] == b'-' && s[23] == b'-'
        && s.iter().enumerate().all(|(k, &c)| matches!(k, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
}

fn match_ipv4_opt_port(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    for oct in 0..4 {
        let start = j;
        while j < b.len() && b[j].is_ascii_digit() && j - start < 3 { j += 1; }
        if j == start || (oct < 3 && b.get(j) != Some(&b'.')) { return None; }
        if oct < 3 { j += 1; }
    }
    if b.get(j).is_some_and(u8::is_ascii_digit) { return None; }
    if b.get(j) == Some(&b':') && b.get(j + 1).is_some_and(u8::is_ascii_digit) {
        j += 1;
        while j < b.len() && b[j].is_ascii_digit() { j += 1; }
    }
    Some(j)
}

fn score_severity(b: &[u8]) -> u8 {
    const T4: &[&[u8]] = &[b"fatal", b"panic", b"critical", b"segfault"];
    const T3: &[&[u8]] = &[b"error", b"fail", b"exception"];
    const T2: &[&[u8]] = &[b"denied", b"refused", b"timeout", b"timed out", b"killed"];
    if T4.iter().any(|k| has_ci(b, k)) || has_word_ci(b, b"crit") { 4 }
    else if T3.iter().any(|k| has_ci(b, k)) || has_word_ci(b, b"err") { 3 }
    else if T2.iter().any(|k| has_ci(b, k)) || has_word_ci(b, b"oom") { 2 }
    else if has_ci(b, b"warn") { 1 } else { 0 }
}

fn has_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

fn has_word_ci(hay: &[u8], needle: &[u8]) -> bool {
    let n = needle.len();
    hay.len() >= n && (0..=hay.len() - n).any(|i| {
        (i == 0 || !hay[i - 1].is_ascii_alphanumeric())
            && (i + n == hay.len() || !hay[i + n].is_ascii_alphanumeric())
            && hay[i..i + n].eq_ignore_ascii_case(needle)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_csi_osc_and_cr_progress_bars() {
        assert_eq!(strip_ansi_and_cr("plain line"), Cow::Borrowed("plain line"));
        assert_eq!(strip_ansi_and_cr("crlf line\r"), Cow::Borrowed("crlf line"));
        assert_eq!(strip_ansi_and_cr("crlf full\r\n"), Cow::Borrowed("crlf full"));
        assert_eq!(strip_ansi_and_cr("\x1b[1;31mERR\x1b[0m \x1b]0;t\x07ok \x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\"), "ERR ok link");
        assert_eq!(strip_ansi_and_cr("[12/300] Building...\r[13/300] Building...\r"), "[13/300] Building...");
        let malformed = format!("\x1b]0;{}TAIL", "x".repeat(320));
        let cleaned = strip_ansi_and_cr(&malformed);
        assert!(cleaned.ends_with("TAIL") && cleaned.len() < malformed.len());
    }

    #[test]
    fn generic_logs_dedup_templates_rank_severity_and_cap_bytes() {
        let mut raw = String::new();
        for i in 1..=30 {
            raw.push_str(&format!("Nov 26 21:15:{i:02} host app[{}]: INFO ping 10.0.0.{i}:443 req=550e8400-e29b-41d4-a716-44665544{i:04}\n", 1000 + i));
        }
        for i in 1..=5 {
            raw.push_str(&format!("2026-11-26T21:16:0{i}.123Z ERROR refused addr=0x7fffa{i:03} peer=192.168.1.{i}:5432\n"));
        }
        raw.push_str("2026-11-26T21:17:00Z FATAL kernel panic at 0xdeadbeef\n");
        let out = compress_generic_logs(&raw, 1024);
        assert!(out.starts_with("[ctx diag: logs, 36 lines -> 3 unique templates]\n"));
        assert!(out.contains("(\u{00d7}30)") && out.contains("(\u{00d7}5)"));
        assert!(out.find("FATAL").unwrap() < out.find("ERROR").unwrap() && out.find("ERROR").unwrap() < out.find("INFO").unwrap());
        assert!(out.len() <= 1024);
    }
}
