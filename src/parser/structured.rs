//! Structural outline parsers for CMake, Markdown/MDX, TOML, JSON/JSONC, YAML, and SQL.

use super::{compact_ws, SymbolKind, SymbolSpan};
use crate::base::simd::line_slice_at;

const MAX_STRUCTURED_SYMBOLS: usize = 512;
const MAX_NESTED_DEPTH: usize = 3;

#[inline]
fn starts_with_ascii_ci(hay: &str, prefix_lower: &str) -> bool {
    hay.len() >= prefix_lower.len()
        && hay.as_bytes()[..prefix_lower.len()].eq_ignore_ascii_case(prefix_lower.as_bytes())
}

#[inline]
fn push_span(syms: &mut Vec<SymbolSpan>, kind: SymbolKind, name: &str, sig: &str, line: u32, end: u32, sig_cap: usize) -> usize {
    let idx = syms.len();
    syms.push(SymbolSpan { kind, name: name.into(), signature: compact_ws(sig, sig_cap), start_line: line, end_line: end });
    idx
}

pub(super) fn parse_cmake(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    const KW: &[(&str, SymbolKind, bool)] = &[
        ("function(", SymbolKind::Function, true),
        ("macro(", SymbolKind::Macro, true),
        ("add_library(", SymbolKind::AddLibrary, false),
        ("add_executable(", SymbolKind::AddExecutable, false),
        ("add_custom_target(", SymbolKind::AddCustomTarget, false),
    ];
    let (mut symbols, mut open_fn) = (Vec::new(), None::<u32>);
    for line_no in 1..=(line_offsets.len() as u32) {
        let trimmed = line_slice_at(text, line_offsets, line_no).trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        for &(kw, kind, has_body) in KW {
            if starts_with_ascii_ci(trimmed, kw) {
                let inside = trimmed[kw.len()..].trim_start();
                let nlen = inside.bytes().take_while(|&b| !b.is_ascii_whitespace() && b != b')').count();
                if nlen > 0 {
                    let s_idx = push_span(&mut symbols, kind, &inside[..nlen], trimmed, line_no, line_no, 110) as u32;
                    if has_body { open_fn = Some(s_idx); }
                }
            }
        }
        if starts_with_ascii_ci(trimmed, "endfunction(") || starts_with_ascii_ci(trimmed, "endmacro(") {
            if let Some(s_idx) = open_fn.take() { symbols[s_idx as usize].end_line = line_no; }
        }
    }
    symbols
}

pub(super) fn parse_markdown(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let total_lines = line_offsets.len() as u32;
    let (mut symbols, mut stack, mut fence) = (Vec::<SymbolSpan>::new(), Vec::<(u8, usize)>::new(), None::<(u8, usize)>);
    for line_no in 1..=total_lines {
        let trimmed = line_slice_at(text, line_offsets, line_no).trim_start();
        let bytes = trimmed.as_bytes();
        if let Some(&first @ (b'`' | b'~')) = bytes.first() {
            let run = bytes.iter().take_while(|&&b| b == first).count();
            if let Some((fc, flen)) = fence {
                if first == fc && run >= flen && trimmed[run..].trim().is_empty() { fence = None; }
                continue;
            } else if run >= 3 && (first == b'~' || !bytes[run..].contains(&b'`')) {
                fence = Some((first, run));
                continue;
            }
        }
        if fence.is_some() || !trimmed.starts_with('#') { continue; }
        let hashes = bytes.iter().take_while(|&&b| b == b'#').count();
        if (1..=4).contains(&hashes) && matches!(bytes.get(hashes), Some(b' ' | b'\t')) {
            let level = hashes as u8;
            while stack.last().is_some_and(|&(top_lvl, _)| top_lvl >= level) {
                if let Some((_, idx)) = stack.pop() {
                    symbols[idx].end_line = line_no.saturating_sub(1).max(symbols[idx].start_line);
                }
            }
            let kind = match hashes { 1 => SymbolKind::H1, 2 => SymbolKind::H2, 3 => SymbolKind::H3, _ => SymbolKind::H4 };
            let name = compact_ws(trimmed[hashes + 1..].trim(), 80);
            let idx = symbols.len();
            symbols.push(SymbolSpan { kind, name, signature: compact_ws(trimmed, 100), start_line: line_no, end_line: total_lines });
            stack.push((level, idx));
        }
    }
    while let Some((_, idx)) = stack.pop() {
        symbols[idx].end_line = total_lines.max(symbols[idx].start_line);
    }
    symbols
}

pub(super) fn parse_toml(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    for line_no in 1..=total_lines {
        let trimmed = line_slice_at(text, line_offsets, line_no).trim();
        if trimmed.starts_with('[') && trimmed.contains(']') {
            if let Some(last) = symbols.last_mut() {
                last.end_line = line_no.saturating_sub(1).max(last.start_line);
            }
            let end = trimmed.rfind(']').unwrap_or(trimmed.len());
            let name = trimmed[1..end].trim_matches('[').trim();
            symbols.push(SymbolSpan { kind: SymbolKind::Table, name: name.into(), signature: trimmed.into(), start_line: line_no, end_line: total_lines });
        }
    }
    symbols
}

struct JsonFrame {
    is_array: bool,
    prefix: String,
    depth: u8,
    active_key: Option<(String, Option<usize>)>,
    elem_sym: Option<usize>,
    expecting_key: bool,
    last_token_line: u32,
}

impl JsonFrame {
    fn new(is_array: bool, prefix: String, depth: u8, elem_sym: Option<usize>, line: u32) -> Self {
        Self { is_array, prefix, depth, active_key: None, elem_sym, expecting_key: !is_array, last_token_line: line }
    }
}

fn skip_json_ws_comments(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        match b[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'/' if b.get(i + 1) == Some(&b'/') => { i += 2; while i < b.len() && b[i] != b'\n' { i += 1; } }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') { i += 1; }
                i = (i + 2).min(b.len());
            }
            _ => break,
        }
    }
    i
}

fn scan_json_str(b: &[u8], q: usize) -> (&[u8], usize) {
    let mut i = q + 1;
    while i < b.len() {
        if b[i] == b'\\' { i = (i + 2).min(b.len()); continue; }
        if b[i] == b'"' { return (&b[q + 1..i], i + 1); }
        i += 1;
    }
    (&b[q + 1..i], i)
}

fn peek_json_object_id(b: &[u8], open_brace: usize) -> Option<String> {
    let limit = (open_brace + 2048).min(b.len());
    let (mut i, mut nested, mut expect_key) = (open_brace + 1, 0usize, true);
    while i < limit {
        i = skip_json_ws_comments(b, i);
        if i >= limit { break; }
        match b[i] {
            b'"' => {
                let (raw, next_i) = scan_json_str(b, i);
                i = next_i;
                if nested == 0 && expect_key {
                    let colon = skip_json_ws_comments(b, i);
                    if b.get(colon) == Some(&b':') {
                        expect_key = false;
                        i = skip_json_ws_comments(b, colon + 1);
                        if matches!(raw, b"name" | b"id" | b"tool" | b"title") && b.get(i) == Some(&b'"') {
                            if let Ok(v) = std::str::from_utf8(scan_json_str(b, i).0) {
                                if !v.is_empty() && v.len() <= 96 { return Some(v.to_string()); }
                            }
                        }
                    }
                }
            }
            b'{' | b'[' => { nested += 1; i += 1; }
            b'}' | b']' => { if nested == 0 { break; } nested -= 1; i += 1; }
            b',' if nested == 0 => { expect_key = true; i += 1; }
            _ => i += 1,
        }
    }
    None
}

/// Nested JSON/JSONC key-path extractor (depth `<= 3`, cap `512`), emitting dotted paths
/// and `<parent>[<id>]` (or `<id>` at root array) for object arrays with `name`/`id`/`tool`.
pub(super) fn parse_json(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let b = text.as_bytes();
    let (mut symbols, mut frames) = (Vec::<SymbolSpan>::new(), Vec::<JsonFrame>::new());
    let (mut i, mut line_no) = (0usize, 1u32);

    while i < b.len() {
        match b[i] {
            b'\n' => { line_no += 1; i += 1; }
            b' ' | b'\t' | b'\r' => i += 1,
            b'/' if b.get(i + 1) == Some(&b'/') => { i += 2; while i < b.len() && b[i] != b'\n' { i += 1; } }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    if b[i] == b'\n' { line_no += 1; }
                    i += 1;
                }
                i = (i + 2).min(b.len());
            }
            b'"' => {
                let (key_start, key_line) = (i + 1, line_no);
                i += 1;
                while i < b.len() {
                    if b[i] == b'\\' { i = (i + 2).min(b.len()); continue; }
                    if b[i] == b'\n' { line_no += 1; }
                    if b[i] == b'"' { break; }
                    i += 1;
                }
                let key_end = i;
                if i < b.len() { i += 1; }
                if let Some(top) = frames.last_mut() {
                    top.last_token_line = line_no;
                    if !top.is_array && top.expecting_key && b.get(skip_json_ws_comments(b, i)) == Some(&b':') {
                        top.expecting_key = false;
                        if let Ok(k) = std::str::from_utf8(&b[key_start..key_end]) {
                            if !k.is_empty() && k.len() <= 96 {
                                let full = if top.prefix.is_empty() { k.to_string() } else { format!("{}.{k}", top.prefix) };
                                let sym_idx = ((top.depth as usize) < MAX_NESTED_DEPTH && symbols.len() < MAX_STRUCTURED_SYMBOLS)
                                    .then(|| push_span(&mut symbols, SymbolKind::Key, &full, line_slice_at(text, line_offsets, key_line), key_line, key_line, 100));
                                top.active_key = Some((full, sym_idx));
                            }
                        }
                    }
                }
            }
            b'{' => {
                if let Some(p) = frames.last_mut() { p.last_token_line = line_no; }
                let frame = match frames.last() {
                    None => JsonFrame::new(false, String::new(), 0, None, line_no),
                    Some(p) if p.is_array => {
                        let elem = ((p.depth as usize) < MAX_NESTED_DEPTH && symbols.len() < MAX_STRUCTURED_SYMBOLS)
                            .then(|| peek_json_object_id(b, i))
                            .flatten()
                            .map(|id| {
                                let name = if p.prefix.is_empty() { id } else { format!("{}[{}]", p.prefix, id) };
                                let idx = push_span(&mut symbols, SymbolKind::Key, &name, line_slice_at(text, line_offsets, line_no), line_no, line_no, 100);
                                (name, idx)
                            });
                        let (pfx, es) = elem.map_or_else(|| (p.prefix.clone(), None), |(n, idx)| (n, Some(idx)));
                        JsonFrame::new(false, pfx, MAX_NESTED_DEPTH as u8, es, line_no)
                    }
                    Some(p) => {
                        let pfx = p.active_key.as_ref().map(|(s, _)| s.clone()).unwrap_or_default();
                        JsonFrame::new(false, pfx, p.depth.saturating_add(1), None, line_no)
                    }
                };
                frames.push(frame);
                i += 1;
            }
            b'[' => {
                if let Some(p) = frames.last_mut() { p.last_token_line = line_no; }
                let frame = match frames.last() {
                    None => JsonFrame::new(true, String::new(), 0, None, line_no),
                    Some(p) => {
                        let pfx = if p.is_array { p.prefix.clone() }
                            else { p.active_key.as_ref().map(|(s, _)| s.clone()).unwrap_or_default() };
                        JsonFrame::new(true, pfx, p.depth.saturating_add(1), None, line_no)
                    }
                };
                frames.push(frame);
                i += 1;
            }
            b'}' | b']' => {
                if let Some(mut closed) = frames.pop() {
                    if let Some((_, Some(idx))) = closed.active_key.take() {
                        symbols[idx].end_line = closed.last_token_line.max(symbols[idx].start_line);
                    }
                    if let Some(idx) = closed.elem_sym { symbols[idx].end_line = line_no.max(symbols[idx].start_line); }
                    if let Some(p) = frames.last_mut() {
                        p.last_token_line = line_no;
                        if let Some((_, Some(idx))) = p.active_key { symbols[idx].end_line = line_no.max(symbols[idx].start_line); }
                    }
                }
                i += 1;
            }
            b',' => {
                if let Some(top) = frames.last_mut() {
                    if let Some((_, Some(idx))) = top.active_key.take() {
                        symbols[idx].end_line = top.last_token_line.max(symbols[idx].start_line);
                    }
                    if !top.is_array { top.expecting_key = true; }
                }
                i += 1;
            }
            b':' => { if let Some(top) = frames.last_mut() { top.expecting_key = false; } i += 1; }
            _ => { if let Some(top) = frames.last_mut() { top.last_token_line = line_no; } i += 1; }
        }
    }
    let eof = line_offsets.len() as u32;
    while let Some(c) = frames.pop() {
        if let Some((_, Some(idx))) = c.active_key { symbols[idx].end_line = eof.max(symbols[idx].start_line); }
        if let Some(idx) = c.elem_sym { symbols[idx].end_line = eof.max(symbols[idx].start_line); }
    }
    symbols
}

fn find_yaml_colon(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if let Some(&q @ (b'"' | b'\'')) = b.first() {
        let mut i = 1;
        while i < b.len() {
            if q == b'"' && b[i] == b'\\' { i = (i + 2).min(b.len()); continue; }
            if b[i] == q {
                return (b.get(i + 1) == Some(&b':') && matches!(b.get(i + 2), None | Some(b' ' | b'\t'))).then_some(i + 1);
            }
            i += 1;
        }
        return None;
    }
    b.iter().enumerate()
        .find(|&(i, &c)| c == b':' && matches!(b.get(i + 1), None | Some(b' ' | b'\t')))
        .map(|(i, _)| i)
}

fn is_yaml_block_scalar(tail: &str) -> bool {
    let t = tail.trim();
    let b = t.find(" #").or_else(|| t.find("\t#")).map_or(t, |p| t[..p].trim()).as_bytes();
    matches!(b.first(), Some(b'|' | b'>'))
        && b[1..].len() <= 2
        && b[1..].iter().all(|&c| matches!(c, b'-' | b'+' | b'1'..=b'9'))
}

/// Nested YAML key-path extractor (depth `<= 3`, cap `512`), skipping `|`/`>` block scalar bodies.
pub(super) fn parse_yaml(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let (mut symbols, mut stack) = (Vec::<SymbolSpan>::new(), Vec::<(usize, String, Option<usize>)>::new());
    let (mut block_indent, mut last_nonempty) = (None::<usize>, 0u32);

    for line_no in 1..=(line_offsets.len() as u32) {
        let raw = line_slice_at(text, line_offsets, line_no);
        let trimmed = raw.trim();
        let indent = raw.bytes().take_while(|&b| b == b' ' || b == b'\t')
            .fold(0usize, |acc, b| acc + if b == b'\t' { 2 } else { 1 });

        if let Some(bi) = block_indent {
            if trimmed.is_empty() { continue; }
            if indent > bi { last_nonempty = line_no; continue; }
            block_indent = None;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        if trimmed == "---" || trimmed == "..." {
            while let Some((_, _, opt)) = stack.pop() {
                if let Some(idx) = opt { symbols[idx].end_line = last_nonempty.max(symbols[idx].start_line); }
            }
            continue;
        }
        if trimmed == "-" || trimmed.starts_with("- ") || trimmed.starts_with("-\t") {
            while stack.last().is_some_and(|&(ti, _, _)| ti > indent) {
                if let Some((_, _, Some(idx))) = stack.pop() { symbols[idx].end_line = last_nonempty.max(symbols[idx].start_line); }
            }
            let tail = trimmed[1..].trim();
            if is_yaml_block_scalar(tail) || find_yaml_colon(tail).is_some_and(|c| is_yaml_block_scalar(&tail[c + 1..])) {
                block_indent = Some(indent);
            }
            last_nonempty = line_no;
            continue;
        }
        while stack.last().is_some_and(|&(ti, _, _)| ti >= indent) {
            if let Some((_, _, Some(idx))) = stack.pop() { symbols[idx].end_line = last_nonempty.max(symbols[idx].start_line); }
        }
        if let Some(colon) = find_yaml_colon(trimmed) {
            let key = trimmed[..colon].trim().trim_matches('"').trim_matches('\'');
            if !key.is_empty() && key.len() <= 96 && stack.len() < MAX_NESTED_DEPTH {
                let full = match stack.last() { Some((_, p, _)) => format!("{p}.{key}"), None => key.to_string() };
                let sym_idx = (symbols.len() < MAX_STRUCTURED_SYMBOLS)
                    .then(|| push_span(&mut symbols, SymbolKind::Key, &full, trimmed, line_no, line_no, 100));
                stack.push((indent, full, sym_idx));
            }
            if is_yaml_block_scalar(&trimmed[colon + 1..]) { block_indent = Some(indent); }
        }
        last_nonempty = line_no;
    }
    while let Some((_, _, opt)) = stack.pop() {
        if let Some(idx) = opt { symbols[idx].end_line = last_nonempty.max(symbols[idx].start_line); }
    }
    symbols
}

pub(super) fn parse_sql(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    const KW: &[(&str, SymbolKind)] = &[
        ("create or replace table ", SymbolKind::Table),
        ("create table if not exists ", SymbolKind::Table),
        ("create table ", SymbolKind::Table),
        ("create or replace view ", SymbolKind::Table),
        ("create view ", SymbolKind::Table),
        ("create or replace function ", SymbolKind::Function),
        ("create function ", SymbolKind::Function),
        ("create or replace procedure ", SymbolKind::Function),
        ("create procedure ", SymbolKind::Function),
    ];
    let (mut symbols, mut open_idx) = (Vec::new(), None::<usize>);
    for line_no in 1..=(line_offsets.len() as u32) {
        let trimmed = line_slice_at(text, line_offsets, line_no).trim();
        if trimmed.is_empty() || trimmed.starts_with("--") { continue; }
        for &(kw, kind) in KW {
            if starts_with_ascii_ci(trimmed, kw) {
                let rest = trimmed[kw.len()..].trim_start();
                let nlen = rest.bytes().take_while(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'"' | b'`')).count();
                if nlen > 0 {
                    let name = rest[..nlen].trim_matches('"').trim_matches('`');
                    open_idx = Some(push_span(&mut symbols, kind, name, trimmed, line_no, line_no, 110));
                }
                break;
            }
        }
        if trimmed.ends_with(';') {
            if let Some(idx) = open_idx.take() { symbols[idx].end_line = line_no; }
        }
    }
    symbols
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::simd::scan_source_bytes;

    #[test]
    fn markdown_tracks_h1_to_h4_nested_spans_and_four_backtick_fences() {
        let md = "# Top\n## Sec A\n### Sub A1\n#### Detail\n````md\n```rs\n## Fake Inside\n```\n````\n~~~\n# Fake Tilde\n~~~\n## Sec B\nbody\n";
        let s = scan_source_bytes(md.as_bytes().to_vec()).unwrap();
        let syms = parse_markdown(&s.text, &s.line_offsets);
        assert_eq!(syms.len(), 5);
        assert!(syms.iter().any(|x| x.kind == SymbolKind::H1 && &*x.name == "Top" && x.start_line == 1 && x.end_line == 14));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::H2 && &*x.name == "Sec A" && x.start_line == 2 && x.end_line == 12));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::H3 && &*x.name == "Sub A1" && x.start_line == 3 && x.end_line == 12));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::H4 && &*x.name == "Detail" && x.start_line == 4 && x.end_line == 12));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::H2 && &*x.name == "Sec B" && x.start_line == 13 && x.end_line == 14));
    }

    #[test]
    fn json_extracts_nested_dotted_keys_array_objects_and_jsonc() {
        let doc = "{\n  // comment\n  \"routes\": {\n    /* block */\n    \"context_scout\": {\n      \"model\": \"gpt-6.1-terra\"\n    }\n  },\n  \"tools\": [\n    {\n      \"name\": \"ctx_impact\",\n      \"readOnly\": true\n    }\n  ]\n}\n";
        let s = scan_source_bytes(doc.as_bytes().to_vec()).unwrap();
        let syms = parse_json(&s.text, &s.line_offsets);
        assert!(syms.iter().any(|x| &*x.name == "routes" && x.start_line == 3 && x.end_line == 8));
        assert!(syms.iter().any(|x| &*x.name == "routes.context_scout" && x.start_line == 5 && x.end_line == 7));
        assert!(syms.iter().any(|x| &*x.name == "routes.context_scout.model" && x.start_line == 6 && x.end_line == 6));
        assert!(syms.iter().any(|x| &*x.name == "tools[ctx_impact]" && x.start_line == 10 && x.end_line == 13));

        let root_arr = "[\n  {\"id\": \"ctx_impact\", \"v\": 1}\n]\n";
        let rs = scan_source_bytes(root_arr.as_bytes().to_vec()).unwrap();
        let rsyms = parse_json(&rs.text, &rs.line_offsets);
        assert!(rsyms.iter().any(|x| &*x.name == "ctx_impact" && x.start_line == 2 && x.end_line == 2));
    }

    #[test]
    fn yaml_extracts_nested_paths_and_skips_block_scalars() {
        let doc = "on:\n  push:\n    branches: [main]\njobs:\n  test:\n    run: |\n      fake_key: 1\n      echo ok\n  lint:\n    runs-on: ubuntu\n";
        let s = scan_source_bytes(doc.as_bytes().to_vec()).unwrap();
        let syms = parse_yaml(&s.text, &s.line_offsets);
        assert!(syms.iter().any(|x| &*x.name == "on.push" && x.start_line == 2 && x.end_line == 3));
        assert!(syms.iter().any(|x| &*x.name == "jobs" && x.start_line == 4 && x.end_line == 10));
        assert!(syms.iter().any(|x| &*x.name == "jobs.test" && x.start_line == 5 && x.end_line == 8));
        assert!(syms.iter().any(|x| &*x.name == "jobs.lint" && x.start_line == 9 && x.end_line == 10));
        assert!(!syms.iter().any(|x| x.name.contains("fake_key")));
    }
}
