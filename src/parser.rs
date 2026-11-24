//! Fast zero-dependency structural outline extractor for C/C++26, Python, Rust,
//! TypeScript/JS, Go, CMake, TOML, and Markdown using compact `SymbolKind` tokens
//! and precomputed `line_offsets` (`0` per-line `String` allocations).

use crate::simd::line_slice_at;
use std::path::Path;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolKind {
    Namespace = 1,
    Struct = 2,
    Class = 3,
    Enum = 4,
    Concept = 5,
    Using = 6,
    Fn = 7,
    Def = 8,
    AsyncDef = 9,
    Trait = 10,
    Impl = 11,
    Func = 12,
    Type = 13,
    Interface = 14,
    Function = 15,
    Macro = 16,
    AddLibrary = 17,
    AddExecutable = 18,
    AddCustomTarget = 19,
    H1 = 20,
    H2 = 21,
    H3 = 22,
    Table = 23,
    Sym = 24,
}

impl SymbolKind {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Struct => "struct",
            Self::Class => "class",
            Self::Enum => "enum",
            Self::Concept => "concept",
            Self::Using => "using",
            Self::Fn => "fn",
            Self::Def => "def",
            Self::AsyncDef => "async def",
            Self::Trait => "trait",
            Self::Impl => "impl",
            Self::Func => "func",
            Self::Type => "type",
            Self::Interface => "interface",
            Self::Function => "function",
            Self::Macro => "macro",
            Self::AddLibrary => "add_library",
            Self::AddExecutable => "add_executable",
            Self::AddCustomTarget => "add_custom_target",
            Self::H1 => "h1",
            Self::H2 => "h2",
            Self::H3 => "h3",
            Self::Table => "table",
            Self::Sym => "sym",
        }
    }

    #[inline]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Namespace),
            2 => Some(Self::Struct),
            3 => Some(Self::Class),
            4 => Some(Self::Enum),
            5 => Some(Self::Concept),
            6 => Some(Self::Using),
            7 => Some(Self::Fn),
            8 => Some(Self::Def),
            9 => Some(Self::AsyncDef),
            10 => Some(Self::Trait),
            11 => Some(Self::Impl),
            12 => Some(Self::Func),
            13 => Some(Self::Type),
            14 => Some(Self::Interface),
            15 => Some(Self::Function),
            16 => Some(Self::Macro),
            17 => Some(Self::AddLibrary),
            18 => Some(Self::AddExecutable),
            19 => Some(Self::AddCustomTarget),
            20 => Some(Self::H1),
            21 => Some(Self::H2),
            22 => Some(Self::H3),
            23 => Some(Self::Table),
            24 => Some(Self::Sym),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolSpan {
    pub name: Box<str>,
    pub signature: Box<str>,
    pub start_line: u32,
    pub end_line: u32,
    pub kind: SymbolKind,
}

const _: [(); 48] = [(); std::mem::size_of::<SymbolSpan>()];

pub fn extract_symbols(path: &Path, text: &str, line_offsets: &[u32]) -> Box<[SymbolSpan]> {
    if text.is_empty() || line_offsets.is_empty() {
        return Box::new([]);
    }
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let mut ext_buf = [0u8; 16];
    let ext = lower_ext(path, &mut ext_buf);

    let vec = if fname == "CMakeLists.txt" || ext == "cmake" {
        parse_cmake(text, line_offsets)
    } else {
        match ext {
            "h" | "hpp" | "ipp" | "hh" | "hxx" | "c" | "cc" | "cpp" | "cxx" | "inl" | "tpp" => {
                parse_cpp(text, line_offsets)
            }
            "py" | "pyi" => parse_python(text, line_offsets),
            "rs" | "ts" | "tsx" | "js" | "mjs" | "go" | "java" | "cs" => {
                parse_brace_lang(text, line_offsets, ext)
            }
            "md" | "markdown" => parse_markdown(text, line_offsets),
            "toml" => parse_toml(text, line_offsets),
            _ => Vec::new(),
        }
    };
    vec.into_boxed_slice()
}

fn lower_ext<'a>(path: &Path, buf: &'a mut [u8; 16]) -> &'a str {
    let Some(raw) = path.extension().and_then(|s| s.to_str()) else {
        return "";
    };
    if raw.len() > buf.len() || !raw.is_ascii() {
        return "";
    }
    for (i, b) in raw.bytes().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    // SAFETY: `raw` was checked ASCII.
    unsafe { std::str::from_utf8_unchecked(&buf[..raw.len()]) }
}

fn compact_ws(s: &str, max_len: usize) -> Box<str> {
    let trimmed = s.trim();
    let mut out = String::with_capacity(trimmed.len().min(max_len + 3));
    let mut prev_ws = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
        if out.len() >= max_len {
            out.push_str("...");
            break;
        }
    }
    out.into_boxed_str()
}

#[inline]
fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Produces a single contiguous byte buffer matching `text.len()` byte-for-byte on line breaks,
/// blanking comments and string literal interiors with spaces so `line_offsets` indexes both!
fn build_cleaned_code_buffer(text: &str) -> String {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = vec![b' '; len];
    let mut i = 0usize;
    let mut in_block_comment = false;
    let mut raw_delim: Option<&[u8]> = None;

    while i < len {
        let b = bytes[i];
        if b == b'\n' || b == b'\r' {
            out[i] = b;
            i += 1;
            continue;
        }

        if let Some(delim) = raw_delim {
            // Match `)<delim>"`
            if b == b')'
                && i + 1 + delim.len() < len
                && &bytes[i + 1..i + 1 + delim.len()] == delim
                && bytes[i + 1 + delim.len()] == b'"'
            {
                i += 2 + delim.len();
                raw_delim = None;
            } else {
                i += 1;
            }
            continue;
        }

        if in_block_comment {
            if b == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                i += 2;
                in_block_comment = false;
            } else {
                i += 1;
            }
            continue;
        }

        if b == b'/' && i + 1 < len {
            if bytes[i + 1] == b'/' {
                while i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                    i += 1;
                }
                continue;
            }
            if bytes[i + 1] == b'*' {
                i += 2;
                in_block_comment = true;
                continue;
            }
        }

        // C++ raw string `R"delim(...)delim"`
        if b == b'R' && i + 1 < len && bytes[i + 1] == b'"' {
            let max_scan = (i + 2 + 17).min(len);
            if let Some(rel_paren) = bytes[i + 2..max_scan]
                .iter()
                .position(|&c| c == b'(' || c == b'\n' || c == b'\r' || c == b' ' || c == b'\\')
            {
                if bytes[i + 2 + rel_paren] == b'(' {
                    raw_delim = Some(&bytes[i + 2..i + 2 + rel_paren]);
                    i = i + 2 + rel_paren + 1;
                    continue;
                }
            }
        }

        if b == b'"' || b == b'\'' {
            let quote = b;
            out[i] = quote;
            i += 1;
            while i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                if bytes[i] == b'\\' {
                    i += 1;
                    if i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                        i += 1;
                    }
                    continue;
                }
                if bytes[i] == quote {
                    out[i] = quote;
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        out[i] = b;
        i += 1;
    }

    // Valid UTF-8 outside comments/strings is copied verbatim; interiors are replaced with ASCII ' '.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned())
}

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

fn parse_cpp(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let cleaned = build_cleaned_code_buffer(text);
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut brace_stack: Vec<OpenBlock> = Vec::with_capacity(16);
    let mut pending_decl_start: Option<u32> = None;
    let mut pending_buf = String::new();

    for line_no in 1..=total_lines {
        let clean_line = line_slice_at(&cleaned, line_offsets, line_no);
        let trimmed = clean_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let scope_allows_decl = brace_stack.iter().filter(|b| !b.is_namespace).count() <= 1;

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
                brace_stack.push(OpenBlock {
                    symbol_idx: created.map(|(i, _)| i),
                    is_namespace: created.map(|(_, ns)| ns).unwrap_or(false),
                });
            } else if b == b'}' {
                if let Some(popped) = brace_stack.pop() {
                    if let Some(sym_idx) = popped.symbol_idx {
                        symbols[sym_idx as usize].end_line = line_no;
                    }
                }
                pending_decl_start = None;
                pending_buf.clear();
            } else if b == b';' && brace_stack.iter().filter(|blk| !blk.is_namespace).count() <= 1 {
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

fn parse_python(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut stack: Vec<(u32, u32)> = Vec::new();
    let mut last_nonempty_line = 0u32;
    let mut in_triple: Option<&str> = None;

    for line_no in 1..=total_lines {
        let raw = line_slice_at(text, line_offsets, line_no);
        let trimmed = raw.trim();

        if let Some(delim) = in_triple {
            if trimmed.contains(delim) {
                in_triple = None;
            }
            last_nonempty_line = line_no;
            continue;
        }
        for delim in &["\"\"\"", "'''"] {
            if let Some(pos) = raw.find(delim) {
                if raw[pos + 3..].find(delim).is_none() {
                    in_triple = Some(delim);
                    break;
                }
            }
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw.bytes().take_while(|&b| b == b' ' || b == b'\t').count() as u32;

        while let Some(&(top_indent, sym_idx)) = stack.last() {
            if indent <= top_indent {
                let sym = &mut symbols[sym_idx as usize];
                sym.end_line = last_nonempty_line.max(sym.start_line);
                stack.pop();
            } else {
                break;
            }
        }

        let (kind, rest) = if let Some(r) = trimmed.strip_prefix("class ") {
            (Some(SymbolKind::Class), r)
        } else if let Some(r) = trimmed.strip_prefix("def ") {
            (Some(SymbolKind::Def), r)
        } else if let Some(r) = trimmed.strip_prefix("async def ") {
            (Some(SymbolKind::AsyncDef), r)
        } else {
            (None, "")
        };

        if let Some(k) = kind {
            let name_len = rest.bytes().take_while(|&b| is_ident_char(b)).count();
            if name_len > 0 {
                let sym_idx = symbols.len() as u32;
                symbols.push(SymbolSpan {
                    kind: k,
                    name: rest[..name_len].into(),
                    signature: compact_ws(trimmed, 110),
                    start_line: line_no,
                    end_line: line_no,
                });
                stack.push((indent, sym_idx));
            }
        }
        last_nonempty_line = line_no;
    }

    for (_, sym_idx) in stack {
        let sym = &mut symbols[sym_idx as usize];
        sym.end_line = last_nonempty_line.max(sym.start_line);
    }
    symbols
}

fn parse_brace_lang(text: &str, line_offsets: &[u32], ext: &str) -> Vec<SymbolSpan> {
    let cleaned = build_cleaned_code_buffer(text);
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut stack: Vec<Option<u32>> = Vec::with_capacity(16);
    let mut pending_sym: Option<u32> = None;

    const RS_KW: &[(&str, SymbolKind)] = &[
        ("pub fn ", SymbolKind::Fn),
        ("pub(crate) fn ", SymbolKind::Fn),
        ("fn ", SymbolKind::Fn),
        ("pub struct ", SymbolKind::Struct),
        ("struct ", SymbolKind::Struct),
        ("pub enum ", SymbolKind::Enum),
        ("enum ", SymbolKind::Enum),
        ("pub trait ", SymbolKind::Trait),
        ("trait ", SymbolKind::Trait),
        ("impl ", SymbolKind::Impl),
    ];
    const GO_KW: &[(&str, SymbolKind)] = &[("func ", SymbolKind::Func), ("type ", SymbolKind::Type)];
    const TS_KW: &[(&str, SymbolKind)] = &[
        ("export async function ", SymbolKind::Function),
        ("export function ", SymbolKind::Function),
        ("async function ", SymbolKind::Function),
        ("function ", SymbolKind::Function),
        ("export class ", SymbolKind::Class),
        ("class ", SymbolKind::Class),
        ("export interface ", SymbolKind::Interface),
        ("interface ", SymbolKind::Interface),
        ("export type ", SymbolKind::Type),
    ];

    let keywords = match ext {
        "rs" => RS_KW,
        "go" => GO_KW,
        _ => TS_KW,
    };

    for line_no in 1..=total_lines {
        let clean = line_slice_at(&cleaned, line_offsets, line_no);
        let trimmed = clean.trim();

        if stack.len() <= 1 && pending_sym.is_none() {
            for &(kw, kind) in keywords {
                if let Some(rest) = trimmed.strip_prefix(kw) {
                    let rest = rest.trim_start();
                    let name_len = rest
                        .bytes()
                        .take_while(|&b| is_ident_char(b))
                        .count();
                    if name_len > 0 {
                        let s_idx = symbols.len() as u32;
                        let raw_line = line_slice_at(text, line_offsets, line_no);
                        symbols.push(SymbolSpan {
                            kind,
                            name: rest[..name_len].into(),
                            signature: compact_ws(raw_line, 110),
                            start_line: line_no,
                            end_line: line_no,
                        });
                        pending_sym = Some(s_idx);
                        break;
                    }
                }
            }
        }

        for b in clean.bytes() {
            if b == b'{' {
                stack.push(pending_sym.take());
            } else if b == b'}' {
                if let Some(Some(s_idx)) = stack.pop() {
                    symbols[s_idx as usize].end_line = line_no;
                }
                pending_sym = None;
            } else if b == b';' && stack.len() <= 1 {
                pending_sym = None;
            }
        }
    }
    symbols
}

fn starts_with_ascii_ci(hay: &str, prefix_lower: &str) -> bool {
    hay.len() >= prefix_lower.len()
        && hay.as_bytes()[..prefix_lower.len()].eq_ignore_ascii_case(prefix_lower.as_bytes())
}

fn parse_cmake(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
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

fn parse_markdown(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
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

fn parse_toml(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
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
