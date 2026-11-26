//! Structural outline parsers for structured text/config/query formats:
//! CMake, Markdown/MDX, TOML, JSON/JSONC, YAML, and SQL.

use super::{compact_ws, SymbolKind, SymbolSpan};
use crate::base::simd::line_slice_at;

fn starts_with_ascii_ci(hay: &str, prefix_lower: &str) -> bool {
    hay.len() >= prefix_lower.len()
        && hay.as_bytes()[..prefix_lower.len()].eq_ignore_ascii_case(prefix_lower.as_bytes())
}

pub(super) fn parse_cmake(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    const KW: &[(&str, SymbolKind, bool)] = &[
        ("function(", SymbolKind::Function, true),
        ("macro(", SymbolKind::Macro, true),
        ("add_library(", SymbolKind::AddLibrary, false),
        ("add_executable(", SymbolKind::AddExecutable, false),
        ("add_custom_target(", SymbolKind::AddCustomTarget, false),
    ];
    let total_lines = line_offsets.len() as u32;
    let mut symbols = Vec::new();
    let mut open_fn: Option<u32> = None;

    for line_no in 1..=total_lines {
        let line = line_slice_at(text, line_offsets, line_no);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for &(kw, kind, has_body) in KW {
            if starts_with_ascii_ci(trimmed, kw) {
                let inside = trimmed[kw.len()..].trim_start();
                let name_len = inside
                    .bytes()
                    .take_while(|&b| !b.is_ascii_whitespace() && b != b')')
                    .count();
                if name_len > 0 {
                    let s_idx = symbols.len() as u32;
                    symbols.push(SymbolSpan {
                        kind,
                        name: inside[..name_len].into(),
                        signature: compact_ws(trimmed, 110),
                        start_line: line_no,
                        end_line: line_no,
                    });
                    if has_body {
                        open_fn = Some(s_idx);
                    }
                }
            }
        }
        if starts_with_ascii_ci(trimmed, "endfunction(")
            || starts_with_ascii_ci(trimmed, "endmacro(")
        {
            if let Some(s_idx) = open_fn.take() {
                symbols[s_idx as usize].end_line = line_no;
            }
        }
    }
    symbols
}

pub(super) fn parse_markdown(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut in_fence = false;

    for line_no in 1..=total_lines {
        let line = line_slice_at(text, line_offsets, line_no);
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence || !trimmed.starts_with('#') {
            continue;
        }
        let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
        if (1..=3).contains(&hashes) && trimmed.as_bytes().get(hashes) == Some(&b' ') {
            if let Some(last) = symbols.last_mut() {
                last.end_line = line_no.saturating_sub(1).max(last.start_line);
            }
            let kind = match hashes {
                1 => SymbolKind::H1,
                2 => SymbolKind::H2,
                _ => SymbolKind::H3,
            };
            let title = trimmed[hashes + 1..].trim();
            symbols.push(SymbolSpan {
                kind,
                name: compact_ws(title, 80),
                signature: compact_ws(trimmed, 100),
                start_line: line_no,
                end_line: total_lines,
            });
        }
    }
    symbols
}

pub(super) fn parse_toml(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    for line_no in 1..=total_lines {
        let line = line_slice_at(text, line_offsets, line_no);
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.contains(']') {
            if let Some(last) = symbols.last_mut() {
                last.end_line = line_no.saturating_sub(1).max(last.start_line);
            }
            let end = trimmed.rfind(']').unwrap_or(trimmed.len());
            let name = trimmed[1..end].trim_matches('[').trim();
            symbols.push(SymbolSpan {
                kind: SymbolKind::Table,
                name: name.into(),
                signature: trimmed.into(),
                start_line: line_no,
                end_line: total_lines,
            });
        }
    }
    symbols
}

/// Fast single-pass JSON/JSONC top-level key outline extractor (depth == 1 inside root `{...}`).
pub(super) fn parse_json(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let bytes = text.as_bytes();
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut i = 0usize;
    let mut line_no: u32 = 1;
    let mut depth: i32 = 0;
    let mut active_key: Option<usize> = None;

    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\n' => {
                line_no += 1;
                i += 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    if bytes[i] == b'\n' {
                        line_no += 1;
                    }
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            b'"' => {
                let key_start = i + 1;
                let key_line = line_no;
                i += 1;
                while i < bytes.len() {
                    let c = bytes[i];
                    if c == b'\\' {
                        i = (i + 2).min(bytes.len());
                        continue;
                    }
                    if c == b'\n' {
                        line_no += 1;
                    }
                    if c == b'"' {
                        break;
                    }
                    i += 1;
                }
                let key_end = i;
                if i < bytes.len() {
                    i += 1;
                }
                if depth == 1 && active_key.is_none() && symbols.len() < 256 {
                    let mut look = i;
                    while look < bytes.len()
                        && matches!(bytes[look], b' ' | b'\t' | b'\r' | b'\n')
                    {
                        look += 1;
                    }
                    if bytes.get(look) == Some(&b':') {
                        if let Ok(key_name) = std::str::from_utf8(&bytes[key_start..key_end]) {
                            if !key_name.is_empty() && key_name.len() <= 96 {
                                let raw_line = line_slice_at(text, line_offsets, key_line);
                                let idx = symbols.len();
                                symbols.push(SymbolSpan {
                                    kind: SymbolKind::Key,
                                    name: key_name.into(),
                                    signature: compact_ws(raw_line, 100),
                                    start_line: key_line,
                                    end_line: key_line,
                                });
                                active_key = Some(idx);
                            }
                        }
                    }
                }
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                if depth == 1 {
                    if let Some(idx) = active_key.take() {
                        symbols[idx].end_line = line_no.saturating_sub(1).max(symbols[idx].start_line);
                    }
                }
                depth = (depth - 1).max(0);
                if depth == 1 {
                    if let Some(idx) = active_key {
                        symbols[idx].end_line = line_no;
                    }
                }
                i += 1;
            }
            b',' if depth == 1 => {
                if let Some(idx) = active_key.take() {
                    symbols[idx].end_line = line_no.max(symbols[idx].start_line);
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    if let Some(idx) = active_key {
        symbols[idx].end_line = (line_offsets.len() as u32).max(symbols[idx].start_line);
    }
    symbols
}

/// Fast top-level YAML key outline extractor (`indent == 0`, `key:`).
pub(super) fn parse_yaml(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut last_nonempty: u32 = 0;

    for line_no in 1..=total_lines {
        let raw = line_slice_at(text, line_offsets, line_no);
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" || trimmed == "..." {
            continue;
        }
        let first = raw.as_bytes()[0];
        if first != b' ' && first != b'\t' && first != b'-' {
            if let Some(colon) = raw.find(':') {
                let after = raw.as_bytes().get(colon + 1);
                if after.is_none() || matches!(after, Some(b' ' | b'\t')) {
                    let key = raw[..colon].trim().trim_matches('"').trim_matches('\'');
                    if !key.is_empty() && key.len() <= 96 {
                        if let Some(last) = symbols.last_mut() {
                            last.end_line = last_nonempty.max(last.start_line);
                        }
                        symbols.push(SymbolSpan {
                            kind: SymbolKind::Key,
                            name: key.into(),
                            signature: compact_ws(trimmed, 100),
                            start_line: line_no,
                            end_line: line_no,
                        });
                    }
                }
            }
        }
        last_nonempty = line_no;
    }
    if let Some(last) = symbols.last_mut() {
        last.end_line = last_nonempty.max(last.start_line);
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
    let total_lines = line_offsets.len() as u32;
    let mut symbols = Vec::new();
    let mut open_idx: Option<usize> = None;

    for line_no in 1..=total_lines {
        let trimmed = line_slice_at(text, line_offsets, line_no).trim();
        if trimmed.is_empty() || trimmed.starts_with("--") {
            continue;
        }
        for &(kw, kind) in KW {
            if starts_with_ascii_ci(trimmed, kw) {
                let rest = trimmed[kw.len()..].trim_start();
                let name_len = rest
                    .bytes()
                    .take_while(|&b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'"' | b'`')
                    })
                    .count();
                if name_len > 0 {
                    let name = rest[..name_len].trim_matches('"').trim_matches('`');
                    let idx = symbols.len();
                    symbols.push(SymbolSpan {
                        kind,
                        name: name.into(),
                        signature: compact_ws(trimmed, 110),
                        start_line: line_no,
                        end_line: line_no,
                    });
                    open_idx = Some(idx);
                }
                break;
            }
        }
        if trimmed.ends_with(';') {
            if let Some(idx) = open_idx.take() {
                symbols[idx].end_line = line_no;
            }
        }
    }
    symbols
}
