//! Structural outline parsers for Python, Rust, Go, TypeScript/JS, Java, C#,
//! Kotlin, Swift, Zig, Proto, and Shell.

use super::clean::{build_cleaned_code_buffer, build_cleaned_code_buffer_for_ext};
use super::{compact_ws, is_ident_char, SymbolKind, SymbolSpan};
use crate::base::simd::line_slice_at;

pub(super) fn parse_python(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let cleaned = build_cleaned_code_buffer_for_ext(text, "py");
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut stack: Vec<(u32, u32)> = Vec::new();
    let mut last_nonempty_line = 0u32;
    let mut paren_depth: i32 = 0;

    for line_no in 1..=total_lines {
        let raw = line_slice_at(text, line_offsets, line_no);
        let raw_trim = raw.trim();
        let clean = line_slice_at(&cleaned, line_offsets, line_no);
        let clean_trim = clean.trim();

        if clean_trim.is_empty() {
            if !raw_trim.is_empty() && !raw_trim.starts_with('#') {
                last_nonempty_line = line_no;
            }
            continue;
        }
        let indent = raw.bytes().take_while(|&b| b == b' ' || b == b'\t').count() as u32;

        if paren_depth == 0 {
            while let Some(&(top_indent, sym_idx)) = stack.last() {
                if indent <= top_indent {
                    let sym = &mut symbols[sym_idx as usize];
                    sym.end_line = last_nonempty_line.max(sym.start_line);
                    stack.pop();
                } else {
                    break;
                }
            }

            let (kind, rest) = if let Some(r) = clean_trim.strip_prefix("class ") {
                (Some(SymbolKind::Class), r)
            } else if let Some(r) = clean_trim.strip_prefix("def ") {
                (Some(SymbolKind::Def), r)
            } else if let Some(r) = clean_trim.strip_prefix("async def ") {
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
                        signature: compact_ws(raw_trim, 110),
                        start_line: line_no,
                        end_line: line_no,
                    });
                    stack.push((indent, sym_idx));
                }
            }
        }

        for b in clean.bytes() {
            match b {
                b'(' | b'[' | b'{' => paren_depth += 1,
                b')' | b']' | b'}' => paren_depth = (paren_depth - 1).max(0),
                _ => {}
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

fn leading_ident(s: &str) -> &str {
    let n = s.bytes().take_while(|&b| is_ident_char(b)).count();
    &s[..n]
}

fn parse_rust_impl_target(rest: &str) -> &str {
    let mut s = rest.trim_start();
    if s.starts_with('<') {
        let mut depth = 0i32;
        let mut end = 0usize;
        for (idx, b) in s.bytes().enumerate() {
            if b == b'<' {
                depth += 1;
            } else if b == b'>' {
                depth -= 1;
                if depth == 0 {
                    end = idx + 1;
                    break;
                }
            }
        }
        if end > 0 {
            s = s[end..].trim_start();
        }
    }
    if let Some(pos) = s.find(" for ") {
        s = s[pos + 5..].trim_start();
    }
    let name_len = s
        .bytes()
        .take_while(|&b| is_ident_char(b) || b == b':')
        .count();
    let raw = &s[..name_len];
    raw.rsplit("::").next().unwrap_or(raw)
}

fn parse_go_func_name(rest: &str) -> &str {
    let mut s = rest.trim_start();
    if s.starts_with('(') {
        if let Some(close) = s.find(')') {
            s = s[close + 1..].trim_start();
        }
    }
    leading_ident(s)
}

fn parse_ts_const_fn(trimmed: &str) -> Option<&str> {
    let rest = trimmed
        .strip_prefix("export const ")
        .or_else(|| trimmed.strip_prefix("const "))?;
    let name = leading_ident(rest.trim_start());
    if name.is_empty() {
        return None;
    }
    if rest.contains("=>") || rest.contains("function(") || rest.contains("function (") {
        Some(name)
    } else {
        None
    }
}

pub(super) fn parse_brace_lang(text: &str, line_offsets: &[u32], ext: &str) -> Vec<SymbolSpan> {
    let cleaned = build_cleaned_code_buffer_for_ext(text, ext);
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut stack: Vec<Option<u32>> = Vec::with_capacity(16);
    let mut pending_sym: Option<u32> = None;

    const RS_KW: &[(&str, SymbolKind)] = &[
        ("pub async unsafe fn ", SymbolKind::Fn),
        ("pub async fn ", SymbolKind::Fn),
        ("pub unsafe fn ", SymbolKind::Fn),
        ("pub const unsafe fn ", SymbolKind::Fn),
        ("pub const fn ", SymbolKind::Fn),
        ("pub(crate) async fn ", SymbolKind::Fn),
        ("pub(crate) unsafe fn ", SymbolKind::Fn),
        ("pub(crate) const fn ", SymbolKind::Fn),
        ("pub(crate) fn ", SymbolKind::Fn),
        ("pub(super) async fn ", SymbolKind::Fn),
        ("pub(super) unsafe fn ", SymbolKind::Fn),
        ("pub(super) const fn ", SymbolKind::Fn),
        ("pub(super) fn ", SymbolKind::Fn),
        ("pub fn ", SymbolKind::Fn),
        ("async unsafe fn ", SymbolKind::Fn),
        ("async fn ", SymbolKind::Fn),
        ("unsafe fn ", SymbolKind::Fn),
        ("const unsafe fn ", SymbolKind::Fn),
        ("const fn ", SymbolKind::Fn),
        ("fn ", SymbolKind::Fn),
        ("pub(crate) struct ", SymbolKind::Struct),
        ("pub(super) struct ", SymbolKind::Struct),
        ("pub struct ", SymbolKind::Struct),
        ("struct ", SymbolKind::Struct),
        ("pub(crate) enum ", SymbolKind::Enum),
        ("pub(super) enum ", SymbolKind::Enum),
        ("pub enum ", SymbolKind::Enum),
        ("enum ", SymbolKind::Enum),
        ("pub(crate) trait ", SymbolKind::Trait),
        ("pub(super) trait ", SymbolKind::Trait),
        ("pub unsafe trait ", SymbolKind::Trait),
        ("pub trait ", SymbolKind::Trait),
        ("unsafe trait ", SymbolKind::Trait),
        ("trait ", SymbolKind::Trait),
        ("pub(crate) type ", SymbolKind::Type),
        ("pub type ", SymbolKind::Type),
        ("type ", SymbolKind::Type),
        ("pub(crate) mod ", SymbolKind::Mod),
        ("pub mod ", SymbolKind::Mod),
        ("mod ", SymbolKind::Mod),
        ("macro_rules! ", SymbolKind::Macro),
    ];
    const TS_KW: &[(&str, SymbolKind)] = &[
        ("export default async function ", SymbolKind::Function),
        ("export default function ", SymbolKind::Function),
        ("export async function ", SymbolKind::Function),
        ("export function ", SymbolKind::Function),
        ("async function ", SymbolKind::Function),
        ("function ", SymbolKind::Function),
        ("export default abstract class ", SymbolKind::Class),
        ("export default class ", SymbolKind::Class),
        ("export abstract class ", SymbolKind::Class),
        ("export class ", SymbolKind::Class),
        ("abstract class ", SymbolKind::Class),
        ("class ", SymbolKind::Class),
        ("export interface ", SymbolKind::Interface),
        ("interface ", SymbolKind::Interface),
        ("export const enum ", SymbolKind::Enum),
        ("export enum ", SymbolKind::Enum),
        ("enum ", SymbolKind::Enum),
        ("export type ", SymbolKind::Type),
        ("type ", SymbolKind::Type),
    ];
    const KT_KW: &[(&str, SymbolKind)] = &[
        ("public data class ", SymbolKind::Class),
        ("data class ", SymbolKind::Class),
        ("sealed class ", SymbolKind::Class),
        ("sealed interface ", SymbolKind::Interface),
        ("abstract class ", SymbolKind::Class),
        ("open class ", SymbolKind::Class),
        ("internal class ", SymbolKind::Class),
        ("private class ", SymbolKind::Class),
        ("public class ", SymbolKind::Class),
        ("class ", SymbolKind::Class),
        ("interface ", SymbolKind::Interface),
        ("enum class ", SymbolKind::Enum),
        ("object ", SymbolKind::Struct),
        ("suspend fun ", SymbolKind::Fn),
        ("override fun ", SymbolKind::Fn),
        ("private suspend fun ", SymbolKind::Fn),
        ("private fun ", SymbolKind::Fn),
        ("internal fun ", SymbolKind::Fn),
        ("public fun ", SymbolKind::Fn),
        ("fun ", SymbolKind::Fn),
    ];
    const SWIFT_KW: &[(&str, SymbolKind)] = &[
        ("public final class ", SymbolKind::Class),
        ("final class ", SymbolKind::Class),
        ("public class ", SymbolKind::Class),
        ("class ", SymbolKind::Class),
        ("public struct ", SymbolKind::Struct),
        ("struct ", SymbolKind::Struct),
        ("public enum ", SymbolKind::Enum),
        ("enum ", SymbolKind::Enum),
        ("public protocol ", SymbolKind::Interface),
        ("protocol ", SymbolKind::Interface),
        ("actor ", SymbolKind::Class),
        ("extension ", SymbolKind::Impl),
        ("public func ", SymbolKind::Func),
        ("private func ", SymbolKind::Func),
        ("internal func ", SymbolKind::Func),
        ("static func ", SymbolKind::Func),
        ("func ", SymbolKind::Func),
    ];
    const ZIG_KW: &[(&str, SymbolKind)] = &[
        ("pub inline fn ", SymbolKind::Fn),
        ("pub export fn ", SymbolKind::Fn),
        ("pub fn ", SymbolKind::Fn),
        ("inline fn ", SymbolKind::Fn),
        ("export fn ", SymbolKind::Fn),
        ("fn ", SymbolKind::Fn),
    ];
    const PROTO_KW: &[(&str, SymbolKind)] = &[
        ("message ", SymbolKind::Struct),
        ("service ", SymbolKind::Interface),
        ("enum ", SymbolKind::Enum),
        ("rpc ", SymbolKind::Fn),
    ];

    for line_no in 1..=total_lines {
        let clean = line_slice_at(&cleaned, line_offsets, line_no);
        let trimmed = clean.trim();

        if stack.len() <= 1 && pending_sym.is_none() && !trimmed.is_empty() {
            let mut matched: Option<(SymbolKind, &str)> = None;
            if ext == "rs" {
                if let Some(rest) = trimmed
                    .strip_prefix("unsafe impl")
                    .or_else(|| trimmed.strip_prefix("impl"))
                {
                    if rest.is_empty()
                        || rest.starts_with(' ')
                        || rest.starts_with('<')
                    {
                        let name = parse_rust_impl_target(rest);
                        if !name.is_empty() {
                            matched = Some((SymbolKind::Impl, name));
                        }
                    }
                }
                if matched.is_none() {
                    for &(kw, kind) in RS_KW {
                        if let Some(rest) = trimmed.strip_prefix(kw) {
                            let name = leading_ident(rest.trim_start());
                            if !name.is_empty() {
                                matched = Some((kind, name));
                                break;
                            }
                        }
                    }
                }
            } else if ext == "go" {
                if let Some(rest) = trimmed.strip_prefix("func ") {
                    let name = parse_go_func_name(rest);
                    if !name.is_empty() {
                        matched = Some((SymbolKind::Func, name));
                    }
                } else if let Some(rest) = trimmed.strip_prefix("type ") {
                    let name = leading_ident(rest.trim_start());
                    if !name.is_empty() {
                        matched = Some((SymbolKind::Type, name));
                    }
                }
            } else {
                let keywords = match ext {
                    "kt" | "kts" => KT_KW,
                    "swift" => SWIFT_KW,
                    "zig" => ZIG_KW,
                    "proto" => PROTO_KW,
                    _ => TS_KW,
                };
                for &(kw, kind) in keywords {
                    if let Some(rest) = trimmed.strip_prefix(kw) {
                        let name = leading_ident(rest.trim_start());
                        if !name.is_empty() {
                            matched = Some((kind, name));
                            break;
                        }
                    }
                }
                if matched.is_none()
                    && matches!(ext, "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs")
                {
                    if let Some(name) = parse_ts_const_fn(trimmed) {
                        matched = Some((SymbolKind::Function, name));
                    }
                }
            }

            if let Some((kind, name)) = matched {
                let s_idx = symbols.len() as u32;
                let raw_line = line_slice_at(text, line_offsets, line_no);
                symbols.push(SymbolSpan {
                    kind,
                    name: name.into(),
                    signature: compact_ws(raw_line, 110),
                    start_line: line_no,
                    end_line: line_no,
                });
                pending_sym = Some(s_idx);
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

fn strip_java_cs_modifiers(mut s: &str) -> &str {
    const MODS: &[&str] = &[
        "public", "private", "protected", "internal", "static", "final", "abstract", "sealed",
        "readonly", "partial", "async", "virtual", "override", "extern", "unsafe", "synchronized",
        "native", "default", "strictfp", "new", "ref", "file", "non-sealed",
    ];
    loop {
        s = s.trim_start();
        let mut stripped = false;
        for &m in MODS {
            if let Some(rest) = s.strip_prefix(m) {
                if rest.starts_with(char::is_whitespace) {
                    s = rest;
                    stripped = true;
                    break;
                }
            }
        }
        if !stripped {
            return s;
        }
    }
}

fn is_control_kw(ident: &str) -> bool {
    matches!(
        ident,
        "if" | "for"
            | "foreach"
            | "while"
            | "switch"
            | "catch"
            | "using"
            | "lock"
            | "fixed"
            | "synchronized"
            | "return"
            | "throw"
            | "new"
            | "else"
            | "try"
            | "finally"
            | "when"
            | "where"
    )
}

fn extract_method_name_before_paren(s: &str) -> Option<&str> {
    let paren = s.find('(')?;
    let before = s[..paren].trim_end();
    if before.is_empty() || before.contains('=') || before.contains("->") {
        return None;
    }
    // Strip trailing generic parameters like `Foo<T>`
    let before = if before.ends_with('>') {
        let mut depth = 0i32;
        let mut cut = None;
        for (idx, b) in before.bytes().enumerate().rev() {
            if b == b'>' {
                depth += 1;
            } else if b == b'<' {
                depth -= 1;
                if depth == 0 {
                    cut = Some(idx);
                    break;
                }
            }
        }
        cut.map_or(before, |i| before[..i].trim_end())
    } else {
        before
    };
    let end = before.len();
    let start = before
        .bytes()
        .rposition(|b| !is_ident_char(b))
        .map_or(0, |i| i + 1);
    let name = &before[start..end];
    if name.is_empty() || !name.as_bytes()[0].is_ascii_alphabetic() || is_control_kw(name) {
        return None;
    }
    Some(name)
}

pub(super) fn parse_java_cs(text: &str, line_offsets: &[u32], is_cs: bool) -> Vec<SymbolSpan> {
    let cleaned = build_cleaned_code_buffer(text);
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    // (symbol_idx, is_namespace)
    let mut stack: Vec<(Option<u32>, bool)> = Vec::with_capacity(16);
    let mut non_ns_depth: u32 = 0;
    let mut pending_sym: Option<(u32, bool)> = None;

    for line_no in 1..=total_lines {
        let clean = line_slice_at(&cleaned, line_offsets, line_no);
        let trimmed = clean.trim();

        if non_ns_depth <= 1
            && pending_sym.is_none()
            && !trimmed.is_empty()
            && (!trimmed.starts_with('@') || trimmed.starts_with("@interface "))
            && !trimmed.starts_with('[')
            && !trimmed.starts_with("import ")
            && !trimmed.starts_with("package ")
            && !trimmed.starts_with("using ")
        {
            let body = strip_java_cs_modifiers(trimmed);
            let mut found: Option<(SymbolKind, &str, bool)> = None;
            if is_cs {
                if let Some(rest) = body.strip_prefix("namespace ") {
                    let nlen = rest
                        .bytes()
                        .take_while(|&b| is_ident_char(b) || b == b'.')
                        .count();
                    if nlen > 0 {
                        found = Some((SymbolKind::Namespace, &rest[..nlen], true));
                    }
                }
            }
            if found.is_none() {
                const TYPE_KWS: &[(&str, SymbolKind)] = &[
                    ("class ", SymbolKind::Class),
                    ("interface ", SymbolKind::Interface),
                    ("enum ", SymbolKind::Enum),
                    ("record struct ", SymbolKind::Record),
                    ("record class ", SymbolKind::Record),
                    ("record ", SymbolKind::Record),
                    ("struct ", SymbolKind::Struct),
                    ("@interface ", SymbolKind::Interface),
                ];
                for &(kw, kind) in TYPE_KWS {
                    if let Some(rest) = body.strip_prefix(kw) {
                        let name = leading_ident(rest.trim_start());
                        if !name.is_empty() {
                            found = Some((kind, name, false));
                            break;
                        }
                    }
                }
            }
            if found.is_none() && non_ns_depth == 1 {
                if let Some(name) = extract_method_name_before_paren(body) {
                    if clean.contains('{') || !clean.contains(';') {
                        found = Some((SymbolKind::Fn, name, false));
                    }
                }
            }

            if let Some((kind, name, is_ns)) = found {
                let s_idx = symbols.len() as u32;
                let raw_line = line_slice_at(text, line_offsets, line_no);
                symbols.push(SymbolSpan {
                    kind,
                    name: name.into(),
                    signature: compact_ws(raw_line, 110),
                    start_line: line_no,
                    end_line: line_no,
                });
                // File-scoped C# `namespace Foo.Bar;` or record `record Foo(int X);` has no `{`
                if !trimmed.ends_with(';') {
                    pending_sym = Some((s_idx, is_ns));
                }
            }
        }

        for b in clean.bytes() {
            if b == b'{' {
                let (sym_idx, is_ns) = match pending_sym.take() {
                    Some((idx, ns)) => (Some(idx), ns),
                    None => (None, false),
                };
                if !is_ns {
                    non_ns_depth += 1;
                }
                stack.push((sym_idx, is_ns));
            } else if b == b'}' {
                if let Some((sym_opt, is_ns)) = stack.pop() {
                    if !is_ns {
                        non_ns_depth = non_ns_depth.saturating_sub(1);
                    }
                    if let Some(s_idx) = sym_opt {
                        symbols[s_idx as usize].end_line = line_no;
                    }
                }
                pending_sym = None;
            } else if b == b';' && non_ns_depth <= 1 {
                pending_sym = None;
            }
        }
    }
    symbols
}

pub(super) fn parse_shell(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut depth: i32 = 0;
    let mut open_fn: Option<u32> = None;

    for line_no in 1..=total_lines {
        let line = line_slice_at(text, line_offsets, line_no);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if depth == 0 && open_fn.is_none() {
            let name_opt = if let Some(rest) = trimmed.strip_prefix("function ") {
                let n = leading_ident(rest.trim_start());
                (!n.is_empty()).then_some(n)
            } else if let Some(pos) = trimmed.find("()") {
                let n = trimmed[..pos].trim();
                (!n.is_empty() && n.bytes().all(is_ident_char)).then_some(n)
            } else {
                None
            };
            if let Some(name) = name_opt {
                let s_idx = symbols.len() as u32;
                symbols.push(SymbolSpan {
                    kind: SymbolKind::Function,
                    name: name.into(),
                    signature: compact_ws(trimmed, 100),
                    start_line: line_no,
                    end_line: line_no,
                });
                open_fn = Some(s_idx);
            }
        }
        for b in trimmed.bytes() {
            if b == b'#' {
                break;
            }
            if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                depth = (depth - 1).max(0);
                if depth == 0 {
                    if let Some(s_idx) = open_fn.take() {
                        symbols[s_idx as usize].end_line = line_no;
                    }
                }
            }
        }
    }
    symbols
}
