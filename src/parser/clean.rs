//! Single-pass comment and string-interior blanking buffer preserving exact byte offsets.

/// Produces a single contiguous UTF-8 buffer matching `text.len()` byte-for-byte on line breaks,
/// blanking comments (`//`, `/* */`) and string literal interiors (`"..."`, `'...'`, C++
/// `R"delim(...)delim"`) with ASCII spaces so `line_offsets` indexes both identically.
pub(super) fn build_cleaned_code_buffer(text: &str) -> String {
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

    // SAFETY: `text` is valid UTF-8 and `out` is initialized to ASCII `b' '` (0x20).
    // Every state entry and exit checks strictly ASCII `< 0x80` delimiter bytes (`\n`, `\r`, `/`,
    // `*`, `R`, `"`, `'`, `(`, `)`, `\\`), which can never match UTF-8 multibyte lead (`>= 0xC2`)
    // or continuation (`0x80..=0xBF`) bytes. Consequently:
    //   1. Outside comments/strings, every multibyte UTF-8 sequence falls through consecutively
    //      and is copied intact byte-for-byte.
    //   2. Inside comments, quoted strings, and raw strings (including multibyte raw delimiters),
    //      only ASCII bytes (`b' '`, `\n`, `\r`, `"`, `'`) appear in `out`, and each state exits
    //      strictly at EOF or immediately after an ASCII delimiter byte (a valid UTF-8 boundary).
    // Therefore `out` consists solely of intact UTF-8 subsequences from `text` interleaved with
    // ASCII bytes, guaranteeing valid UTF-8.
    unsafe { String::from_utf8_unchecked(out) }
}

#[cfg(test)]
mod tests {
    use super::build_cleaned_code_buffer;

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
}
