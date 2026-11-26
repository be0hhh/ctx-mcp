//! Always-on lossless token compaction for docs/configs (`md|mdx|markdown|json|jsonc|yaml|yml|toml`).
//! Zero external crates, zero `div`/`idiv`.

#[inline]
pub fn is_doc_or_config_ext(ext: &str) -> bool {
    ["md", "mdx", "markdown", "json", "jsonc", "yaml", "yml", "toml"].iter().any(|k| ext.eq_ignore_ascii_case(k))
}

pub fn compact_lines_for_ext(ext: &str, lines: &[(usize, &str)], merge_json_leaves: bool) -> Vec<(usize, String)> {
    if ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("mdx") || ext.eq_ignore_ascii_case("markdown") {
        compact_markdown(lines)
    } else if ext.eq_ignore_ascii_case("json") || ext.eq_ignore_ascii_case("jsonc") {
        let rows = compact_json(lines);
        if merge_json_leaves { merge_short_json_leaves(rows) } else { rows }
    } else if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") {
        compact_yaml(lines)
    } else if ext.eq_ignore_ascii_case("toml") {
        compact_toml(lines)
    } else {
        lines.iter().map(|&(ln, s)| (ln, s.to_string())).collect()
    }
}

pub fn compact_text_for_ext(ext: &str, text: &str, merge_json_leaves: bool) -> String {
    if text.is_empty() { return String::new(); }
    let lines: Vec<(usize, &str)> = text.lines().enumerate().map(|(i, s)| (i + 1, s)).collect();
    let mut out = String::with_capacity(text.len());
    for (idx, (_, row)) in compact_lines_for_ext(ext, &lines, merge_json_leaves).into_iter().enumerate() {
        if idx > 0 { out.push('\n'); }
        out.push_str(&row);
    }
    if text.ends_with('\n') && !out.is_empty() { out.push('\n'); }
    out
}

fn compact_markdown(lines: &[(usize, &str)]) -> Vec<(usize, String)> {
    let mut out = Vec::with_capacity(lines.len());
    let (mut fence, mut in_html, mut blank_run, mut prev_non_empty) = (None::<(u8, usize)>, false, 0usize, false);
    let fm_end = (lines.len() > 1 && lines[0].0 == 1 && lines[0].1.trim() == "---")
        .then(|| lines.iter().enumerate().skip(1).find(|&(_, &(_, s))| matches!(s.trim(), "---" | "...")).map(|(i, _)| i))
        .flatten();
    for (idx, &(ln, raw)) in lines.iter().enumerate() {
        if fm_end.is_some_and(|end| idx <= end) {
            out.push((ln, raw.to_string())); blank_run = 0; prev_non_empty = !raw.trim().is_empty(); continue;
        }
        let ts = raw.trim_start();
        let sb = ts.as_bytes();
        if !in_html && matches!(sb.first(), Some(b'`' | b'~')) {
            let (first, run) = (sb[0], sb.iter().take_while(|&&b| b == sb[0]).count());
            if let Some((fc, flen)) = fence {
                out.push((ln, raw.to_string()));
                if first == fc && run >= flen && ts[run..].trim().is_empty() { fence = None; }
                blank_run = 0; prev_non_empty = true; continue;
            } else if run >= 3 && (first == b'~' || !sb[run..].contains(&b'`')) {
                fence = Some((first, run)); out.push((ln, raw.to_string())); blank_run = 0; prev_non_empty = true; continue;
            }
        }
        if fence.is_some() { out.push((ln, raw.to_string())); blank_run = 0; prev_non_empty = !raw.trim().is_empty(); continue; }
        let t = raw.trim();
        let tb = t.as_bytes();
        if prev_non_empty && !in_html && tb.len() >= 2 && (tb.iter().all(|&c| c == b'=') || tb.iter().all(|&c| c == b'-')) {
            out.push((ln, raw.trim_end().to_string())); blank_run = 0; prev_non_empty = true; continue;
        }
        let (stripped, touched) = strip_md_html_comments(raw, &mut in_html);
        let clean = stripped.trim_end();
        if clean.trim().is_empty() {
            if touched || (!t.is_empty() && in_html) { continue; }
            if blank_run == 0 { out.push((ln, String::new())); }
            blank_run += 1; prev_non_empty = false; continue;
        }
        blank_run = 0; prev_non_empty = true;
        out.push((ln, condense_table_divider(clean).unwrap_or_else(|| clean.to_string())));
    }
    out
}

fn strip_md_html_comments(raw: &str, in_comment: &mut bool) -> (String, bool) {
    let b = raw.as_bytes();
    let (mut out, mut i, mut touched) = (String::with_capacity(b.len()), 0usize, *in_comment);
    while i < b.len() {
        if *in_comment {
            if let Some(rel) = raw[i..].find("-->") { *in_comment = false; i += rel + 3; continue; }
            return (out, true);
        }
        if b[i] == b'`' {
            let run = b[i..].iter().take_while(|&&c| c == b'`').count();
            let (mut j, mut end) = (i + run, i + run);
            while j < b.len() {
                if b[j] == b'`' {
                    let r = b[j..].iter().take_while(|&&c| c == b'`').count();
                    if r == run { end = j + r; break; }
                    j += r;
                } else { j += 1; }
            }
            out.push_str(&raw[i..end]); i = end; continue;
        }
        if raw[i..].starts_with("<!--") {
            touched = true;
            if let Some(rel) = raw[i + 4..].find("-->") { i += 4 + rel + 3; continue; }
            *in_comment = true; break;
        }
        let Some(ch) = raw[i..].chars().next() else { break; };
        out.push(ch); i += ch.len_utf8();
    }
    (out, touched)
}

fn condense_table_divider(line: &str) -> Option<String> {
    let t = line.trim();
    if !t.contains('|') || !t.contains('-') || !t.bytes().all(|b| matches!(b, b'|' | b'-' | b':' | b' ' | b'\t')) { return None; }
    let indent = line.len() - line.trim_start().len();
    let mut out = String::with_capacity(t.len() + indent);
    for _ in 0..indent { out.push(' '); }
    if t.starts_with('|') { out.push('|'); }
    let mut cells = 0usize;
    for part in t.trim_matches('|').split('|') {
        let cell = part.trim();
        let core = cell.trim_matches(':');
        if core.is_empty() || !core.bytes().all(|b| b == b'-') { return None; }
        if cells > 0 { out.push('|'); }
        if cell.starts_with(':') { out.push(':'); }
        out.push('-');
        if cell.ends_with(':') && cell.len() > 1 { out.push(':'); }
        cells += 1;
    }
    if cells == 0 { return None; }
    if t.ends_with('|') { out.push('|'); }
    Some(out)
}

fn compact_json(lines: &[(usize, &str)]) -> Vec<(usize, String)> {
    let (mut out, mut in_block, mut depth) = (Vec::with_capacity(lines.len()), false, 0usize);
    for &(ln, raw) in lines {
        let stripped = strip_jsonc_line(raw, &mut in_block);
        let t = stripped.trim();
        if t.is_empty() { continue; }
        let indent = if matches!(t.as_bytes()[0], b'}' | b']') { depth.saturating_sub(1) } else { depth }.min(16);
        let mut row = String::with_capacity(indent + t.len());
        for _ in 0..indent { row.push(' '); }
        row.push_str(t);
        out.push((ln, row));
        let (opens, closes) = count_json_delims(t);
        depth = depth.saturating_add(opens).saturating_sub(closes);
    }
    out
}

fn strip_jsonc_line(raw: &str, in_block: &mut bool) -> String {
    let b = raw.as_bytes();
    let (mut out, mut i, mut in_str) = (String::with_capacity(b.len()), 0usize, false);
    while i < b.len() {
        if *in_block {
            if i + 1 < b.len() && b[i] == b'*' && b[i + 1] == b'/' { *in_block = false; i += 2; } else { i += 1; }
            continue;
        }
        if in_str {
            if b[i] == b'\\' && i + 1 < b.len() {
                let Some(c) = raw[i + 1..].chars().next() else { break; };
                out.push('\\'); out.push(c); i += 1 + c.len_utf8(); continue;
            }
            if b[i] == b'"' { in_str = false; }
        } else if b[i] == b'"' { in_str = true; }
        else if b[i] == b'/' && b.get(i + 1) == Some(&b'/') { break; }
        else if b[i] == b'/' && b.get(i + 1) == Some(&b'*') { *in_block = true; i += 2; continue; }
        let Some(c) = raw[i..].chars().next() else { break; };
        out.push(c); i += c.len_utf8();
    }
    out
}

fn count_json_delims(s: &str) -> (usize, usize) {
    let b = s.as_bytes();
    let (mut i, mut in_str, mut opens, mut closes) = (0usize, false, 0usize, 0usize);
    while i < b.len() {
        if in_str { if b[i] == b'\\' { i = (i + 2).min(b.len()); continue; } if b[i] == b'"' { in_str = false; } }
        else { match b[i] { b'"' => in_str = true, b'{' | b'[' => opens += 1, b'}' | b']' => closes += 1, _ => {} } }
        i += 1;
    }
    (opens, closes)
}

fn merge_short_json_leaves(rows: Vec<(usize, String)>) -> Vec<(usize, String)> {
    const MAX_LEAF: usize = 96;
    let (mut out, mut i) = (Vec::with_capacity(rows.len()), 0usize);
    while i < rows.len() {
        let cb = match rows[i].1.trim_end().as_bytes().last().copied() { Some(b'{') => Some(b'}'), Some(b'[') => Some(b']'), _ => None };
        if let Some(close_b) = cb {
            let (mut merged, mut hit) = (rows[i].1.clone(), None);
            if merged.len() <= MAX_LEAF {
                for j in (i + 1)..rows.len() {
                    let p = rows[j].1.trim();
                    let (op, cl) = count_json_delims(p);
                    if op > 0 { break; }
                    if cl > 0 {
                        let pb = p.as_bytes();
                        if cl == 1 && pb.first() == Some(&close_b) && pb.len() <= 2 && (pb.len() == 1 || pb[1] == b',') {
                            merged.push_str(p);
                            if merged.len() <= MAX_LEAF { hit = Some((j, merged)); }
                        }
                        break;
                    }
                    if j > i + 1 { merged.push(' '); }
                    merged.push_str(p);
                    if merged.len() > MAX_LEAF { break; }
                }
            }
            if let Some((end_idx, line)) = hit { out.push((rows[i].0, line)); i = end_idx + 1; continue; }
        }
        out.push(rows[i].clone()); i += 1;
    }
    out
}

fn compact_yaml(lines: &[(usize, &str)]) -> Vec<(usize, String)> {
    let (mut out, mut block_indent, mut blank_run) = (Vec::with_capacity(lines.len()), None, 0usize);
    for &(ln, raw) in lines {
        let indent = raw.bytes().take_while(|&b| b == b' ' || b == b'\t').count();
        let t = raw.trim();
        if let Some(bi) = block_indent {
            if t.is_empty() || indent > bi { out.push((ln, raw.to_string())); blank_run = 0; continue; }
            block_indent = None;
        }
        if t.is_empty() { if blank_run == 0 { out.push((ln, String::new())); } blank_run += 1; continue; }
        if t.starts_with('#') { continue; }
        blank_run = 0; out.push((ln, raw.trim_end().to_string()));
        let tail = t.find(':').filter(|&p| matches!(t.as_bytes().get(p + 1), None | Some(b' ' | b'\t'))).map(|p| t[p + 1..].trim()).or_else(|| t.strip_prefix("- ").map(str::trim));
        if let Some(vr) = tail {
            let v = vr.find(" #").or_else(|| vr.find("\t#")).map_or(vr, |p| vr[..p].trim()).as_bytes();
            if matches!(v.first(), Some(b'|' | b'>')) && v[1..].len() <= 2 && v[1..].iter().all(|&c| matches!(c, b'-' | b'+' | b'1'..=b'9')) { block_indent = Some(indent); }
        }
    }
    out
}

fn compact_toml(lines: &[(usize, &str)]) -> Vec<(usize, String)> {
    let (mut out, mut ml, mut blank_run) = (Vec::with_capacity(lines.len()), None::<u8>, 0usize);
    for &(ln, raw) in lines {
        if ml.is_some() { out.push((ln, raw.to_string())); scan_toml_ml(raw.as_bytes(), &mut ml); blank_run = 0; continue; }
        let t = raw.trim();
        if t.is_empty() { if blank_run == 0 { out.push((ln, String::new())); } blank_run += 1; continue; }
        if t.starts_with('#') { continue; }
        blank_run = 0; scan_toml_ml(raw.as_bytes(), &mut ml);
        out.push((ln, if ml.is_some() { raw.to_string() } else { raw.trim_end().to_string() }));
    }
    out
}

fn scan_toml_ml(b: &[u8], ml: &mut Option<u8>) {
    let (mut i, mut sq) = (0usize, None::<u8>);
    while i < b.len() {
        if let Some(q) = *ml {
            if q == b'"' && b[i] == b'\\' { i = (i + 2).min(b.len()); continue; }
            if i + 2 < b.len() && b[i] == q && b[i + 1] == q && b[i + 2] == q { *ml = None; i += 3; continue; }
        } else if let Some(q) = sq { if q == b'"' && b[i] == b'\\' { i = (i + 2).min(b.len()); continue; } if b[i] == q { sq = None; } }
        else if b[i] == b'#' { break; }
        else if (b[i] == b'"' || b[i] == b'\'') && i + 2 < b.len() && b[i + 1] == b[i] && b[i + 2] == b[i] { *ml = Some(b[i]); i += 3; continue; }
        else if b[i] == b'"' || b[i] == b'\'' { sq = Some(b[i]); }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn markdown_preserves_fences_frontmatter_setext_inline_code_and_tables() {
        let md = "---\ntitle: Demo\n\n\n---\nH1\n===\nH2\n---\n<!-- drop -->\nKeep `<!-- keep -->` ok   \n\n\n| A | B |\n| ----- | :---: |\n| 1 | 2 |\n````md\n```rs\n<!-- in4 -->\n\n\n```\n````\n~~~\n<!-- in~ -->\n~~~\n";
        let out = compact_text_for_ext("md", md, false);
        assert!(out.starts_with("---\ntitle: Demo\n\n\n---\nH1\n===\nH2\n---\n") && !out.contains("drop"));
        assert!(out.contains("Keep `<!-- keep -->` ok\n\n| A | B |\n|-|:-:|\n") && out.contains("<!-- in4 -->\n\n\n```") && out.contains("<!-- in~ -->"));
    }
    #[test]
    fn jsonc_preserves_urls_strips_comments_and_merges_short_leaves() {
        let js = "{\n    // top\n    \"url\": \"https://a.b/*ok*/\", /* inline */\n    \"cfg\": {\n        \"a\": 1,\n        \"b\": 2\n    }\n}\n";
        let lines: Vec<(usize, &str)> = js.lines().enumerate().map(|(i, s)| (i + 1, s)).collect();
        let keep = compact_lines_for_ext("jsonc", &lines, false);
        assert!(keep.iter().any(|&(ln, ref s)| ln == 3 && s == " \"url\": \"https://a.b/*ok*/\",") && keep.iter().any(|&(ln, ref s)| ln == 5 && s == "  \"a\": 1,"));
        assert!(compact_text_for_ext("jsonc", js, true).contains(" \"cfg\": {\"a\": 1, \"b\": 2}\n"));
    }
    #[test]
    fn yaml_and_toml_preserve_block_scalars_and_multiline_strings() {
        let yml = "# drop\nscript: |\n  # keep\n\n\n  echo ok\nfolded: >-\n  # keep2\n\n\nkey: val   \n";
        let y_out = compact_text_for_ext("yaml", yml, false);
        assert!(!y_out.contains("# drop") && y_out.contains("  # keep\n\n\n  echo ok") && y_out.contains("  # keep2\n\n\nkey: val\n"));
        let toml = "# drop\ndoc = \"\"\"\n# keep\n\n\nline\n\"\"\"\nlit = '''\n# lit\n'''\n\n\nk = 1   \n";
        let t_out = compact_text_for_ext("toml", toml, false);
        assert!(!t_out.contains("# drop") && t_out.contains("# keep\n\n\nline") && t_out.contains("# lit") && t_out.ends_with("\n\nk = 1\n"));
        assert!(is_doc_or_config_ext("MD") && is_doc_or_config_ext("jsonc") && !is_doc_or_config_ext("rs"));
    }
}
