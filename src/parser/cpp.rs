//! C/C++26 structural symbol outline parser with O(1) incremental non-namespace scope tracking.

use super::clean::build_cleaned_code_buffer;
use super::{compact_ws, is_ident_char, SymbolKind, SymbolSpan};
use crate::base::simd::line_slice_at;

#[derive(Clone, Copy)]
struct OpenBlock {
    symbol_idx: Option<u32>,
    is_namespace: bool,
}

fn extract_cpp_type_decl(trimmed: &str) -> Option<(SymbolKind, Box<str>)> {
    const KW_MAP: &[(&str, SymbolKind)] = &[
        ("namespace ", SymbolKind::Namespace),
        ("struct ", SymbolKind::Struct),
        ("class ", SymbolKind::Class),
        ("enum class ", SymbolKind::Enum),
        ("enum struct ", SymbolKind::Enum),
        ("enum ", SymbolKind::Enum),
        ("concept ", SymbolKind::Concept),
    ];
    for &(prefix, kind) in KW_MAP {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let rest = rest.trim_start();
            let rest = if let Some(after_open) = rest.strip_prefix("[[") {
                if let Some(end_attr) = after_open.find("]]") {
                    after_open[end_attr + 2..].trim_start()
                } else {
                    rest
                }
            } else {
                rest
            };
            let bytes = rest.as_bytes();
            let mut end = 0;
            while end < bytes.len() && (is_ident_char(bytes[end]) || bytes[end] == b':') {
                end += 1;
            }
            if end > 0 {
                let name = rest[..end].trim_matches(':');
                if !name.is_empty() && !trimmed.ends_with(';') {
                    return Some((kind, name.into()));
                }
            }
        }
    }
    None
}

fn extract_cpp_fn_name(stmt: &str) -> Option<Box<str>> {
    let paren_pos = stmt.find('(')?;
    let before = stmt[..paren_pos].trim_end();
    if before.is_empty() {
        return None;
    }
    let bytes = before.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0
        && (is_ident_char(bytes[start - 1])
            || bytes[start - 1] == b':'
            || bytes[start - 1] == b'~')
    {
        start -= 1;
    }
    if start == end {
        return None;
    }
    let name = &before[start..end];
    const FORBIDDEN: &[&str] = &[
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "sizeof",
        "alignof",
        "decltype",
        "static_assert",
        "requires",
        "noexcept",
        "new",
        "delete",
    ];
    if FORBIDDEN.contains(&name) {
        return None;
    }
    let prefix = before[..start].trim();
    if prefix.is_empty() && !name.contains("::") && !name.starts_with('~') {
        return None;
    }
    if prefix.ends_with('=') || prefix.ends_with('.') || prefix.ends_with("->") {
        return None;
    }
    Some(name.into())
}

pub(super) fn parse_cpp(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let cleaned = build_cleaned_code_buffer(text);
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut brace_stack: Vec<OpenBlock> = Vec::with_capacity(16);
    let mut non_ns_depth: u32 = 0;
    let mut pending_decl_start: Option<u32> = None;
    let mut pending_buf = String::new();

    for line_no in 1..=total_lines {
        let clean_line = line_slice_at(&cleaned, line_offsets, line_no);
        let trimmed = clean_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let scope_allows_decl = non_ns_depth <= 1;

        if scope_allows_decl {
            if pending_buf.is_empty() && trimmed.starts_with("using ") && trimmed.contains('=') {
                let rest = trimmed["using ".len()..].trim_start();
                let end = rest.bytes().take_while(|&b| is_ident_char(b)).count();
                if end > 0 {
                    let raw_line = line_slice_at(text, line_offsets, line_no);
                    symbols.push(SymbolSpan {
                        kind: SymbolKind::Using,
                        name: rest[..end].into(),
                        signature: compact_ws(raw_line, 110),
                        start_line: line_no,
                        end_line: line_no,
                    });
                }
            }

            if trimmed.starts_with("concept ") && trimmed.contains('=') && trimmed.ends_with(';') {
                let rest = trimmed["concept ".len()..].trim_start();
                let end = rest.bytes().take_while(|&b| is_ident_char(b)).count();
                if end > 0 {
                    let raw_line = line_slice_at(text, line_offsets, line_no);
                    symbols.push(SymbolSpan {
                        kind: SymbolKind::Concept,
                        name: rest[..end].into(),
                        signature: compact_ws(raw_line, 110),
                        start_line: pending_decl_start.unwrap_or(line_no),
                        end_line: line_no,
                    });
                    pending_decl_start = None;
                    pending_buf.clear();
                }
            }
        }

        let mut opened_symbol_this_line = false;
        if scope_allows_decl && !trimmed.contains('{') && !trimmed.ends_with(';') {
            if pending_decl_start.is_none() {
                pending_decl_start = Some(line_no);
            }
            if pending_buf.len() < 512 {
                if !pending_buf.is_empty() {
                    pending_buf.push(' ');
                }
                pending_buf.push_str(trimmed);
            }
        }

        for b in clean_line.bytes() {
            if b == b'{' {
                let mut created: Option<(u32, bool)> = None;
                if scope_allows_decl && !opened_symbol_this_line {
                    let combined_owned: String;
                    let combined: &str = if pending_buf.is_empty() {
                        trimmed
                    } else {
                        combined_owned = {
                            let mut s = String::with_capacity(pending_buf.len() + 1 + trimmed.len());
                            s.push_str(&pending_buf);
                            s.push(' ');
                            s.push_str(trimmed);
                            s
                        };
                        &combined_owned
                    };
                    let start_ln = pending_decl_start.unwrap_or(line_no);
                    let after_tpl = strip_leading_template(combined);
                    let head = combined.split('{').next().unwrap_or(combined);
                    if let Some((kind, name)) = extract_cpp_type_decl(after_tpl) {
                        let is_ns = kind == SymbolKind::Namespace;
                        let sym_idx = symbols.len() as u32;
                        symbols.push(SymbolSpan {
                            kind,
                            name,
                            signature: compact_ws(head, 110),
                            start_line: start_ln,
                            end_line: line_no,
                        });
                        created = Some((sym_idx, is_ns));
                        opened_symbol_this_line = true;
                    } else if let Some(fn_name) = extract_cpp_fn_name(after_tpl) {
                        let sym_idx = symbols.len() as u32;
                        symbols.push(SymbolSpan {
                            kind: SymbolKind::Fn,
                            name: fn_name,
                            signature: compact_ws(head, 110),
                            start_line: start_ln,
                            end_line: line_no,
                        });
                        created = Some((sym_idx, false));
                        opened_symbol_this_line = true;
                    }
                }
                pending_decl_start = None;
                pending_buf.clear();
                let is_namespace = created.map(|(_, ns)| ns).unwrap_or(false);
                if !is_namespace {
                    non_ns_depth += 1;
                }
                brace_stack.push(OpenBlock {
                    symbol_idx: created.map(|(i, _)| i),
                    is_namespace,
                });
            } else if b == b'}' {
                if let Some(popped) = brace_stack.pop() {
                    if !popped.is_namespace {
                        non_ns_depth = non_ns_depth.saturating_sub(1);
                    }
                    if let Some(sym_idx) = popped.symbol_idx {
                        symbols[sym_idx as usize].end_line = line_no;
                    }
                }
                pending_decl_start = None;
                pending_buf.clear();
            } else if b == b';' && non_ns_depth <= 1 {
                pending_decl_start = None;
                pending_buf.clear();
            }
        }
    }
    symbols
}

fn strip_leading_template(s: &str) -> &str {
    let mut cur = s.trim_start();
    while cur.starts_with("template") {
        let rest = cur["template".len()..].trim_start();
        if !rest.starts_with('<') {
            break;
        }
        let bytes = rest.as_bytes();
        let mut depth = 0i32;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'<' => depth += 1,
                b'>' => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if depth != 0 {
            break;
        }
        cur = rest[i..].trim_start();
    }
    cur
}
