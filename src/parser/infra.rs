//! Structural outline parsers for Makefile (`Makefile`, `GNUmakefile`, `makefile`, `*.mk`)
//! and Dockerfile/Containerfile (`Dockerfile`, `Containerfile`, `Dockerfile.*`, `*.dockerfile`).

use super::{compact_ws, SymbolKind, SymbolSpan};
use crate::base::simd::line_slice_at;

const MAX_MAKE_SYMBOLS: usize = 512;
const MAX_DOCKER_SYMBOLS: usize = 256;

/// Parses top-level Makefile targets (`name:`) skipping comments/assignments (`:=`, `?=`, `+=`, `=`),
/// extending spans across tab-indented recipe lines (`SymbolKind::Sym`, capped at 512).
pub(super) fn parse_makefile(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut active_target: Option<usize> = None;
    let mut in_cont = false;

    for line_no in 1..=total_lines {
        let raw = line_slice_at(text, line_offsets, line_no);
        let bytes = raw.as_bytes();
        let trimmed = raw.trim();
        if in_cont || bytes.first() == Some(&b'\t') {
            if let Some(idx) = active_target {
                symbols[idx].end_line = line_no;
            }
            in_cont = trimmed.ends_with('\\');
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        active_target = None;
        if bytes[0] == b' ' {
            continue;
        }
        let Some(colon) = raw.find(':') else {
            continue;
        };
        let lhs = raw[..colon].trim();
        if lhs.is_empty() || lhs.len() > 96 || lhs.contains('=') || lhs.contains('#') {
            continue;
        }
        let after = bytes.get(colon + 1).copied();
        if after == Some(b'=')
            || (matches!(after, Some(b':' | b'!')) && bytes.get(colon + 2) == Some(&b'='))
        {
            continue;
        }
        if matches!(
            lhs.split_ascii_whitespace().next(),
            Some("ifeq" | "ifneq" | "ifdef" | "ifndef" | "include" | "-include" | "sinclude"
                | "export" | "unexport" | "override" | "define" | "vpath")
        ) {
            continue;
        }
        if symbols.len() < MAX_MAKE_SYMBOLS {
            let idx = symbols.len();
            symbols.push(SymbolSpan {
                kind: SymbolKind::Sym,
                name: compact_ws(lhs, 96),
                signature: compact_ws(trimmed, 110),
                start_line: line_no,
                end_line: line_no,
            });
            active_target = Some(idx);
            in_cont = trimmed.ends_with('\\');
        }
    }
    symbols
}

/// Parses `FROM <img...> [AS <stage>]` multi-stage spans (`SymbolKind::Mod`) and top-level
/// `ARG`/`ENTRYPOINT`/`CMD` (`SymbolKind::Key`, capped at 256).
pub(super) fn parse_dockerfile(text: &str, line_offsets: &[u32]) -> Vec<SymbolSpan> {
    let total_lines = line_offsets.len() as u32;
    let mut symbols: Vec<SymbolSpan> = Vec::new();
    let mut active_stage: Option<usize> = None;
    let mut active_key_cont: Option<usize> = None;
    let mut last_nonempty: u32 = 0;

    for line_no in 1..=total_lines {
        let trimmed = line_slice_at(text, line_offsets, line_no).trim();
        if let Some(kidx) = active_key_cont {
            symbols[kidx].end_line = line_no;
            if !trimmed.is_empty() {
                last_nonempty = line_no;
            }
            if !trimmed.ends_with('\\') {
                active_key_cont = None;
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (instr, rest) = match trimmed.find(|c: char| c.is_ascii_whitespace()) {
            Some(pos) => (&trimmed[..pos], trimmed[pos..].trim_start()),
            None => (trimmed, ""),
        };
        if instr.eq_ignore_ascii_case("FROM") {
            if let Some(sidx) = active_stage.take() {
                symbols[sidx].end_line = last_nonempty.max(symbols[sidx].start_line);
            }
            let stage = extract_from_stage_name(rest);
            if !stage.is_empty() && symbols.len() < MAX_DOCKER_SYMBOLS {
                let idx = symbols.len();
                symbols.push(SymbolSpan {
                    kind: SymbolKind::Mod,
                    name: compact_ws(stage, 96),
                    signature: compact_ws(trimmed, 110),
                    start_line: line_no,
                    end_line: line_no,
                });
                active_stage = Some(idx);
            }
        } else if instr.eq_ignore_ascii_case("ARG")
            || instr.eq_ignore_ascii_case("ENTRYPOINT")
            || instr.eq_ignore_ascii_case("CMD")
        {
            let name = if instr.eq_ignore_ascii_case("ARG") {
                rest.split(|c: char| c.is_ascii_whitespace() || c == '=')
                    .next()
                    .unwrap_or("")
            } else if instr.eq_ignore_ascii_case("ENTRYPOINT") {
                "ENTRYPOINT"
            } else {
                "CMD"
            };
            if !name.is_empty() && name.len() <= 96 && symbols.len() < MAX_DOCKER_SYMBOLS {
                let idx = symbols.len();
                symbols.push(SymbolSpan {
                    kind: SymbolKind::Key,
                    name: name.into(),
                    signature: compact_ws(trimmed, 110),
                    start_line: line_no,
                    end_line: line_no,
                });
                if trimmed.ends_with('\\') {
                    active_key_cont = Some(idx);
                }
            }
        }
        last_nonempty = line_no;
    }
    if let Some(sidx) = active_stage.take() {
        symbols[sidx].end_line = last_nonempty.max(symbols[sidx].start_line);
    }
    symbols
}

fn extract_from_stage_name(rest: &str) -> &str {
    let mut iter = rest.split_ascii_whitespace();
    let mut image = "";
    while let Some(tok) = iter.next() {
        if tok.starts_with("--") {
            continue;
        }
        if image.is_empty() {
            image = tok;
        } else if tok.eq_ignore_ascii_case("AS") {
            if let Some(stage) = iter.next() {
                return stage;
            }
        }
    }
    image
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::simd::scan_source_bytes;

    #[test]
    fn makefile_extracts_targets_and_skips_assignments() {
        let mk = "# Build\nCC := clang\nCFLAGS ?= -O3\nLDFLAGS += -lm\nOUT = a:b\nall: build\nbuild: main.c\n\t$(CC) -o app main.c\n\t@echo ok\n\nclean:\n\trm -f app\n";
        let s = scan_source_bytes(mk.as_bytes().to_vec()).unwrap();
        let syms = parse_makefile(&s.text, &s.line_offsets);
        assert_eq!(syms.len(), 3);
        assert!(syms.iter().any(|x| x.kind == SymbolKind::Sym && &*x.name == "all" && x.start_line == 6 && x.end_line == 6));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::Sym && &*x.name == "build" && x.start_line == 7 && x.end_line == 9));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::Sym && &*x.name == "clean" && x.start_line == 11 && x.end_line == 12));
    }

    #[test]
    fn dockerfile_extracts_multistage_spans_and_top_keys() {
        let df = "ARG BASE_IMG=ubuntu:24.04\nFROM --platform=$BUILDPLATFORM rust:1.80 AS builder\nWORKDIR /app\nRUN cargo build\n\nFROM ${BASE_IMG} AS runtime\nCOPY --from=builder /app/bin /bin/app\nENTRYPOINT [\"/bin/app\"]\nCMD [\"--serve\"]\n";
        let s = scan_source_bytes(df.as_bytes().to_vec()).unwrap();
        let syms = parse_dockerfile(&s.text, &s.line_offsets);
        assert!(syms.iter().any(|x| x.kind == SymbolKind::Key && &*x.name == "BASE_IMG" && x.start_line == 1 && x.end_line == 1));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::Mod && &*x.name == "builder" && x.start_line == 2 && x.end_line == 4));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::Mod && &*x.name == "runtime" && x.start_line == 6 && x.end_line == 9));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::Key && &*x.name == "ENTRYPOINT" && x.start_line == 8));
        assert!(syms.iter().any(|x| x.kind == SymbolKind::Key && &*x.name == "CMD" && x.start_line == 9));
    }
}
