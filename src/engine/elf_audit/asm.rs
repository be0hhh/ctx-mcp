//! Streaming static disassembly / assembly text scanner with per-function instruction counts.

use super::elf::MAX_AUDIT_FILE_BYTES;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Default)]
pub(super) struct AsmCounts {
    pub total_insns: usize,
    pub vzeroupper: usize,
    pub zmm: usize,
    pub divq_idivq: usize,
    pub tls_get_addr: usize,
    pub rep_stos: usize,
    pub indirect_callq: usize,
    pub per_fn_insns: BTreeMap<String, usize>,
}

#[inline]
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[inline]
fn is_zmm_token(tok: &[u8]) -> bool {
    if tok.len() < 4 || tok.len() > 5 || !tok.starts_with(b"zmm") {
        return false;
    }
    let rest = &tok[3..];
    match rest.len() {
        1 => rest[0].is_ascii_digit(),
        2 => {
            ((rest[0] == b'1' || rest[0] == b'2') && rest[1].is_ascii_digit())
                || (rest[0] == b'3' && (rest[1] == b'0' || rest[1] == b'1'))
        }
        _ => false,
    }
}

#[inline]
fn trim_ascii_bytes(mut s: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = s.split_first() {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = s.split_last() {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

/// Parses `objdump` / `llvm-objdump` function headers such as `0000000000401000 <sym>:` or `<sym>:`.
fn parse_objdump_fn_header(trimmed: &[u8]) -> Option<&str> {
    if !trimmed.ends_with(b">:") {
        return None;
    }
    let open = if trimmed.first() == Some(&b'<') {
        0
    } else {
        let mut i = 0usize;
        while i < trimmed.len() && trimmed[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i == 0 {
            return None;
        }
        let ws_start = i;
        while i < trimmed.len() && (trimmed[i] == b' ' || trimmed[i] == b'\t') {
            i += 1;
        }
        if i == ws_start || trimmed.get(i) != Some(&b'<') {
            return None;
        }
        i
    };
    let name_bytes = &trimmed[open + 1..trimmed.len() - 2];
    if name_bytes.is_empty() {
        return None;
    }
    std::str::from_utf8(name_bytes).ok()
}

/// Returns `true` when `rest` after `<hex>:` is empty or consists solely of 2-hex-digit raw bytes
/// (e.g. GNU `objdump` continuation lines for long x86-64 instructions).
fn is_empty_or_hex_continuation(rest: &[u8]) -> bool {
    for part in rest.split(|b| b.is_ascii_whitespace()) {
        if part.is_empty() {
            continue;
        }
        if part.len() != 2 || !part[0].is_ascii_hexdigit() || !part[1].is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn contains_colon_ws(s: &[u8]) -> bool {
    s.windows(2)
        .any(|w| w[0] == b':' && (w[1] == b' ' || w[1] == b'\t'))
}

fn scan_asm_tokens(slice: &[u8], counts: &mut AsmCounts) {
    let len = slice.len();
    let mut i = 0usize;
    while i < len {
        if !is_word_byte(slice[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < len && is_word_byte(slice[i]) {
            i += 1;
        }
        let tok = &slice[start..i];
        if is_zmm_token(tok) {
            counts.zmm += 1;
        } else if tok == b"vzeroupper" {
            counts.vzeroupper += 1;
        } else if tok == b"divq" || tok == b"idivq" {
            counts.divq_idivq += 1;
        } else if tok == b"__tls_get_addr" {
            counts.tls_get_addr += 1;
        } else if tok == b"rep" {
            let mut j = i;
            while j < len && slice[j].is_ascii_whitespace() {
                j += 1;
            }
            if j > i && j < len && is_word_byte(slice[j]) {
                let next_start = j;
                while j < len && is_word_byte(slice[j]) {
                    j += 1;
                }
                let next_tok = &slice[next_start..j];
                if matches!(
                    next_tok,
                    b"stos" | b"stosb" | b"stosw" | b"stosd" | b"stosq"
                ) {
                    counts.rep_stos += 1;
                }
            }
        } else if tok == b"call" || tok == b"callq" {
            let mut j = i;
            while j < len && slice[j].is_ascii_whitespace() {
                j += 1;
            }
            if j > i && j < len && slice[j] == b'*' {
                counts.indirect_callq += 1;
            }
        }
    }
}

fn record_insn(counts: &mut AsmCounts, current_fn: Option<&str>) {
    counts.total_insns += 1;
    if let Some(name) = current_fn {
        if let Some(slot) = counts.per_fn_insns.get_mut(name) {
            *slot += 1;
        } else {
            counts.per_fn_insns.insert(name.to_owned(), 1);
        }
    }
}

fn scan_asm_line(line: &[u8], counts: &mut AsmCounts, current_fn: &mut Option<String>) {
    let trimmed = trim_ascii_bytes(line);
    if trimmed.is_empty() {
        return;
    }
    if let Some(fn_name) = parse_objdump_fn_header(trimmed) {
        *current_fn = Some(fn_name.to_owned());
        return;
    }
    if matches!(trimmed[0], b'#' | b';' | b'/' | b'.') {
        return;
    }

    let mut hex_end = 0usize;
    while hex_end < trimmed.len() && trimmed[hex_end].is_ascii_hexdigit() {
        hex_end += 1;
    }
    if hex_end > 0 && trimmed.get(hex_end) == Some(&b':') {
        let rest = &trimmed[hex_end + 1..];
        let rest_trimmed = trim_ascii_bytes(rest);
        if rest_trimmed.starts_with(b"...") || is_empty_or_hex_continuation(rest_trimmed) {
            return;
        }
        record_insn(counts, current_fn.as_deref());
        scan_asm_tokens(rest_trimmed, counts);
        return;
    }

    if trimmed.ends_with(b":") || contains_colon_ws(trimmed) {
        return;
    }
    if trimmed[0].is_ascii_alphabetic() {
        record_insn(counts, current_fn.as_deref());
        scan_asm_tokens(trimmed, counts);
    }
}

pub(super) fn scan_asm_file(path: &Path) -> Result<AsmCounts, String> {
    let meta = fs::metadata(path)
        .map_err(|e| format!("cannot stat ASM file {}: {}", path.display(), e))?;
    if !meta.is_file() {
        return Err(format!("ASM path is not a regular file: {}", path.display()));
    }
    if meta.len() > MAX_AUDIT_FILE_BYTES {
        return Err(format!(
            "ASM file exceeds {} bytes: {}",
            MAX_AUDIT_FILE_BYTES,
            path.display()
        ));
    }
    let file = File::open(path)
        .map_err(|e| format!("cannot open ASM file {}: {}", path.display(), e))?;
    let mut reader = BufReader::new(file);
    let mut counts = AsmCounts::default();
    let mut current_fn: Option<String> = None;
    let mut buf = Vec::with_capacity(512);
    loop {
        buf.clear();
        let read = reader
            .read_until(b'\n', &mut buf)
            .map_err(|e| format!("cannot read ASM file {}: {}", path.display(), e))?;
        if read == 0 {
            break;
        }
        scan_asm_line(&buf, &mut counts, &mut current_fn);
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objdump_headers_continuations_and_vzeroupper_are_tracked_per_function() {
        let dump = "\
sample.elf:     file format elf64-x86-64\n\
\n\
Disassembly of section .text:\n\
\n\
0000000000401000 <demo::Book<32>::apply(int const&)>:\n\
  401000:\tc5 f8 77             \tvzeroupper\n\
  401003:\t66 66 2e 0f 1f 84 00 \tnopw   %cs:0x0(%rax,%rax,1)\n\
  40100a:\t00 00 00 00\n\
  40100e:\tc3                   \tret\n\
<bare_fn>:\n\
  401010:\t48 f7 f1             \tdivq   %rcx\n\
  401013:\t...\n\
  401014:\tc3                   \tret\n";

        let mut counts = AsmCounts::default();
        let mut cur = None;
        for line in dump.as_bytes().split(|&b| b == b'\n') {
            scan_asm_line(line, &mut counts, &mut cur);
        }
        assert_eq!(counts.total_insns, 5);
        assert_eq!(counts.vzeroupper, 1);
        assert_eq!(counts.divq_idivq, 1);
        assert_eq!(
            counts.per_fn_insns.get("demo::Book<32>::apply(int const&)"),
            Some(&3)
        );
        assert_eq!(counts.per_fn_insns.get("bare_fn"), Some(&2));
    }
}
