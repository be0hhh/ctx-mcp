//! Single-pass language-aware comment and string-interior blanking buffer preserving exact
//! byte offsets and UTF-8 soundness.
//!
//! Handles C/C++26 (`//`, `/* */`, `R"delim(...)delim"`, digit separators `1'000`), Rust
//! (`r#"..."#`, lifetimes `'a`/`'_`/`'static`, char literals `'x'`/`'\n'`), JS/TS/Go
//! (backtick template/raw strings), and Python (`#` comments, `"""..."""` / `'''...'''`).

use crate::base::simd::{
    find_next_clean_delim, CLEAN_LANG_BACKTICK, CLEAN_LANG_CLIKE, CLEAN_LANG_PYTHON,
    CLEAN_LANG_RUST,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum CleanLang {
    CLike,
    Rust,
    Backtick,
    Python,
}

impl CleanLang {
    #[inline(always)]
    const fn simd_code(self) -> u8 {
        match self {
            Self::CLike => CLEAN_LANG_CLIKE,
            Self::Rust => CLEAN_LANG_RUST,
            Self::Backtick => CLEAN_LANG_BACKTICK,
            Self::Python => CLEAN_LANG_PYTHON,
        }
    }
}

#[inline]
fn classify_ext(ext: &str) -> CleanLang {
    if ext.eq_ignore_ascii_case("rs") {
        CleanLang::Rust
    } else if ext.eq_ignore_ascii_case("py") || ext.eq_ignore_ascii_case("pyi") {
        CleanLang::Python
    } else if ext.eq_ignore_ascii_case("js")
        || ext.eq_ignore_ascii_case("jsx")
        || ext.eq_ignore_ascii_case("mjs")
        || ext.eq_ignore_ascii_case("cjs")
        || ext.eq_ignore_ascii_case("ts")
        || ext.eq_ignore_ascii_case("tsx")
        || ext.eq_ignore_ascii_case("go")
    {
        CleanLang::Backtick
    } else {
        CleanLang::CLike
    }
}

/// Default C/C++/brace cleaner (safe on C++26 digit separators and Rust lifetimes).
pub fn build_cleaned_code_buffer(text: &str) -> String {
    build_cleaned_code_buffer_for_ext(text, "cpp")
}

/// Produces a single contiguous UTF-8 buffer matching `text.len()` byte-for-byte on line breaks,
/// blanking comments and string literal interiors with ASCII spaces so `line_offsets` indexes
/// both buffers identically.
pub fn build_cleaned_code_buffer_for_ext(text: &str, ext: &str) -> String {
    let lang = classify_ext(ext);
    let lang_code = lang.simd_code();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = vec![b' '; len];
    let mut i = 0usize;
    let mut in_block_comment = false;
    let mut block_comment_depth = 0usize;
    let mut cpp_raw_delim: Option<&[u8]> = None;
    let mut rust_raw_hashes: Option<usize> = None;
    let mut py_triple_quote: Option<u8> = None;
    let mut in_backtick = false;

    while i < len {
        let b = bytes[i];
        if b == b'\n' || b == b'\r' {
            out[i] = b;
            i += 1;
            continue;
        }

        if let Some(delim) = cpp_raw_delim {
            if b == b')'
                && i + 1 + delim.len() < len
                && &bytes[i + 1..i + 1 + delim.len()] == delim
                && bytes[i + 1 + delim.len()] == b'"'
            {
                i += 2 + delim.len();
                cpp_raw_delim = None;
            } else {
                i += 1;
            }
            continue;
        }

        if let Some(hashes) = rust_raw_hashes {
            if b == b'"'
                && i + hashes < len
                && bytes[i + 1..=i + hashes].iter().all(|&c| c == b'#')
            {
                i += 1 + hashes;
                rust_raw_hashes = None;
            } else {
                i += 1;
            }
            continue;
        }

        if let Some(q) = py_triple_quote {
            if b == b'\\' && i + 1 < len && bytes[i + 1] != b'\n' && bytes[i + 1] != b'\r' {
                i += 2;
            } else if b == q && i + 2 < len && bytes[i + 1] == q && bytes[i + 2] == q {
                i += 3;
                py_triple_quote = None;
            } else {
                i += 1;
            }
            continue;
        }

        if in_backtick {
            if b == b'\\'
                && !ext.eq_ignore_ascii_case("go")
                && i + 1 < len
                && bytes[i + 1] != b'\n'
                && bytes[i + 1] != b'\r'
            {
                i += 2;
            } else if b == b'`' {
                out[i] = b'`';
                i += 1;
                in_backtick = false;
            } else {
                i += 1;
            }
            continue;
        }

        if in_block_comment {
            if lang == CleanLang::Rust && b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
                block_comment_depth += 1;
                i += 2;
            } else if b == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                i += 2;
                if block_comment_depth > 1 {
                    block_comment_depth -= 1;
                } else {
                    block_comment_depth = 0;
                    in_block_comment = false;
                }
            } else {
                i += 1;
            }
            continue;
        }

        let next = find_next_clean_delim(bytes, i, lang_code);
        if next > i {
            out[i..next].copy_from_slice(&bytes[i..next]);
            i = next;
            if i >= len {
                break;
            }
            if bytes[i] == b'\n' || bytes[i] == b'\r' {
                out[i] = bytes[i];
                i += 1;
                continue;
            }
        }
        let b = bytes[i];

        if lang == CleanLang::Python {
            if b == b'#' {
                while i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                    i += 1;
                }
                continue;
            }
            if (b == b'"' || b == b'\'')
                && i + 2 < len
                && bytes[i + 1] == b
                && bytes[i + 2] == b
            {
                py_triple_quote = Some(b);
                i += 3;
                continue;
            }
        } else if b == b'/' && i + 1 < len {
            if bytes[i + 1] == b'/' {
                while i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                    i += 1;
                }
                continue;
            }
            if bytes[i + 1] == b'*' {
                i += 2;
                in_block_comment = true;
                block_comment_depth = 1;
                continue;
            }
        }

        // C++ raw string `R"delim(...)delim"`
        if lang == CleanLang::CLike && b == b'R' && i + 1 < len && bytes[i + 1] == b'"' {
            let max_scan = (i + 2 + 17).min(len);
            if let Some(rel_paren) = bytes[i + 2..max_scan]
                .iter()
                .position(|&c| c == b'(' || c == b'\n' || c == b'\r' || c == b' ' || c == b'\\')
            {
                if bytes[i + 2 + rel_paren] == b'(' {
                    cpp_raw_delim = Some(&bytes[i + 2..i + 2 + rel_paren]);
                    i = i + 2 + rel_paren + 1;
                    continue;
                }
            }
        }

        // Rust raw string `r"..."`, `r#"..."#`, `br#"..."#`, `cr#"..."#`
        if lang == CleanLang::Rust
            && b == b'r'
            && (i == 0
                || !crate::parser::is_ident_char(bytes[i - 1])
                || ((bytes[i - 1] == b'b' || bytes[i - 1] == b'c')
                    && (i == 1 || !crate::parser::is_ident_char(bytes[i - 2]))))
        {
            let mut j = i + 1;
            while j < len && bytes[j] == b'#' {
                j += 1;
            }
            if j < len && bytes[j] == b'"' {
                rust_raw_hashes = Some(j - (i + 1));
                i = j + 1;
                continue;
            }
        }

        // JS/TS/Go backtick string
        if lang == CleanLang::Backtick && b == b'`' {
            out[i] = b'`';
            i += 1;
            in_backtick = true;
            continue;
        }

        if b == b'"' {
            out[i] = b'"';
            i += 1;
            while i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                if bytes[i] == b'\\' {
                    i += 1;
                    if i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                        i += 1;
                    }
                    continue;
                }
                if bytes[i] == b'"' {
                    out[i] = b'"';
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        if b == b'\'' {
            if lang == CleanLang::Python || lang == CleanLang::Backtick {
                out[i] = b'\'';
                i += 1;
                while i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                    if bytes[i] == b'\\' {
                        i += 1;
                        if i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                            i += 1;
                        }
                        continue;
                    }
                    if bytes[i] == b'\'' {
                        out[i] = b'\'';
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            // C/C++26 digit separator: `1'000`, `0xFF'AA`
            if i > 0
                && i + 1 < len
                && bytes[i - 1].is_ascii_hexdigit()
                && bytes[i + 1].is_ascii_hexdigit()
            {
                out[i] = b'\'';
                i += 1;
                continue;
            }
            // Match a real char literal (`'x'`, `'\n'`, `'\x7f'`, `'\u{1234}'`) without consuming
            // Rust lifetimes (`'a`, `'_`, `'static`) or unmatched apostrophes.
            if let Some(close_idx) = match_short_char_literal(bytes, i) {
                out[i] = b'\'';
                out[close_idx] = b'\'';
                i = close_idx + 1;
                continue;
            }
            // Lifetime / non-char apostrophe: copy verbatim.
            out[i] = b'\'';
            i += 1;
            continue;
        }

        out[i] = b;
        i += 1;
    }

    // SAFETY: `text` is valid UTF-8 and `out` is initialized to ASCII `b' '`. Every delimiter
    // checked above is strictly ASCII `< 0x80`, so multibyte UTF-8 sequences are either copied
    // verbatim consecutively or skipped completely between ASCII boundaries.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Matches a bounded single-character / escaped-character literal starting at `open_idx` (`'`).
/// Returns the byte index of the closing `'` if present on the same line, or `None` for Rust
/// lifetimes (`'a`, `'static`) and unmatched quotes.
fn match_short_char_literal(bytes: &[u8], open_idx: usize) -> Option<usize> {
    let len = bytes.len();
    let next = open_idx + 1;
    if next >= len || bytes[next] == b'\n' || bytes[next] == b'\r' {
        return None;
    }
    if bytes[next] == b'\\' {
        let mut j = next + 1;
        let max_j = (open_idx + 14).min(len);
        if j < max_j && bytes[j] != b'\n' && bytes[j] != b'\r' {
            j += 1;
        }
        while j < max_j && bytes[j] != b'\n' && bytes[j] != b'\r' {
            if bytes[j] == b'\'' {
                return Some(j);
            }
            j += 1;
        }
        return None;
    }
    // Single UTF-8 scalar (1..=4 bytes) followed immediately by `'`.
    let lead = bytes[next];
    let char_len = if lead < 0x80 {
        1
    } else if lead & 0xE0 == 0xC0 {
        2
    } else if lead & 0xF0 == 0xE0 {
        3
    } else if lead & 0xF8 == 0xF0 {
        4
    } else {
        return None;
    };
    let close = next + char_len;
    if close < len && bytes[close] == b'\'' {
        Some(close)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{build_cleaned_code_buffer, build_cleaned_code_buffer_for_ext};

    #[test]
    fn preserves_utf8_soundness_across_comments_strings_and_multibyte_raw_delims() {
        let src = concat!(
            "int привет = 1; // комментарий 🚀\n",
            "/* блок { класс } мир */\n",
            "const char* a = \"текст \\я с \\\"кавычками\\\" { }\";\n",
            "const char* b = R\"я(сырой { текст )я) 🚀 )я\";\n",
            "struct Финал { int x; };\n",
        );
        let cleaned = build_cleaned_code_buffer(src);
        assert_eq!(cleaned.len(), src.len());
        assert!(std::str::from_utf8(cleaned.as_bytes()).is_ok());

        let lines: Vec<&str> = cleaned.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(lines[0].starts_with("int привет = 1;"));
        assert!(!lines[0].contains("комментарий"));
        assert!(lines[1].trim().is_empty());
        assert!(lines[2].starts_with("const char* a = \""));
        assert!(!lines[2].contains('{'));
        assert!(!lines[2].contains("текст"));
        assert!(lines[3].starts_with("const char* b = "));
        assert!(!lines[3].contains('{'));
        assert!(!lines[3].contains("сырой"));
        assert!(lines[3].ends_with(';'));
        assert_eq!(lines[4], "struct Финал { int x; };");
    }

    #[test]
    fn handles_cpp26_digit_separators_rust_lifetimes_raw_strings_backticks_and_python() {
        let cpp = "constexpr uint64_t kScale = 1'000'000; if (kScale > 0) { return 'x'; }\n";
        let c_clean = build_cleaned_code_buffer_for_ext(cpp, "hpp");
        assert!(c_clean.contains("if (kScale > 0) { return ' '; }"));

        let rs = concat!(
            "pub fn f<'a>(x: &'a str) -> &'static str {\n",
            "    let raw = r#\"say \"{\" inside\"#;\n",
            "    /* outer /* nested { */ still comment */\n",
            "    let c = '\\n';\n",
            "    x\n",
            "}\n",
        );
        let r_clean = build_cleaned_code_buffer_for_ext(rs, "rs");
        assert!(r_clean.contains("pub fn f<'a>(x: &'a str) -> &'static str {"));
        assert!(!r_clean.contains("inside"));
        assert!(!r_clean.contains("nested"));
        assert!(r_clean.contains("let c = '  ';"));

        let ts = "const s = `hello ${foo} { not code }`; const ok = call();\n";
        let t_clean = build_cleaned_code_buffer_for_ext(ts, "ts");
        assert!(!t_clean.contains("not code"));
        assert!(t_clean.contains("const ok = call();"));

        let py = "def f():\n    \"\"\"doc { with call() }\"\"\"\n    # comment call()\n    return real_call()\n";
        let p_clean = build_cleaned_code_buffer_for_ext(py, "py");
        assert!(!p_clean.contains("with call"));
        assert!(!p_clean.contains("comment"));
        assert!(p_clean.contains("return real_call()"));
    }

    #[test]
    fn simd_fast_path_matches_byte_for_byte_at_edge_offsets() {
        for &pad in &[31usize, 32, 33, 63, 64] {
            let prefix = format!("{} ", "a".repeat(pad - 1));

            // C++ line comment, string, raw string, and digit separator right at boundary.
            let cpp_src = format!("{prefix}// cmt\n{prefix}R\"d(hide)d\";{prefix}1'000 + 'z';\n");
            let cpp_exp = format!("{prefix}      \n{prefix}           ;{prefix}1'000 + ' ';\n");
            assert_eq!(build_cleaned_code_buffer_for_ext(&cpp_src, "cpp"), cpp_exp);

            // Rust raw string (`r#`), byte raw string (`br#`), lifetime, and block comment.
            let rs_src = format!("{prefix}r#\"hi\"#;{prefix}br#\"ok\"#;{prefix}'a /*x*/\n");
            let rs_exp = format!("{prefix}       ;{prefix}b       ;{prefix}'a      \n");
            assert_eq!(build_cleaned_code_buffer_for_ext(&rs_src, "rs"), rs_exp);

            // Backtick template string and single-quoted string in TS.
            let ts_src = format!("{prefix}`tpl`;{prefix}'sq';// end\n");
            let ts_exp = format!("{prefix}`   `;{prefix}'  ';      \n");
            assert_eq!(build_cleaned_code_buffer_for_ext(&ts_src, "ts"), ts_exp);

            // Python `#` comment and triple-quoted docstring right at boundary.
            let py_src = format!("{prefix}# note\n{prefix}\"\"\"doc\"\"\"\n");
            let py_exp = format!("{prefix}      \n{prefix}         \n");
            assert_eq!(build_cleaned_code_buffer_for_ext(&py_src, "py"), py_exp);
        }
    }
}
