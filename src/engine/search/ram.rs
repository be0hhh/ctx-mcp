use super::rank::{rank_and_select_hits, SearchHitSet};
use super::{
    parse_literal_alternation, search_snippet, search_time_left, RgMatchMode, SearchError,
    SearchHit,
};
use crate::base::simd::{
    bloom128_may_contain, line_slice_at, search_lines_literals, trigram_bloom128_ascii_lower,
};
use crate::engine::walk_source_dir;
use crate::rpc::BrokerService;
use std::path::{Path, PathBuf};
use std::time::Instant;

const IN_RAM_SEARCH_MAX_FILES: usize = 256;
const PER_FILE_SCAN_CANDIDATES: usize = 256;

pub(super) fn try_in_ram_simd_search(
    svc: &BrokerService,
    needles: &[&str],
    search_roots: &[(PathBuf, PathBuf, bool)],
    cap: usize,
    code_only: bool,
    deadline: Instant,
) -> Result<Option<SearchHitSet>, SearchError> {
    let mut targets: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(32);
    for (canon, ws_root, is_dir) in search_roots {
        search_time_left(deadline)?;
        if *is_dir {
            let mut sub = Vec::new();
            walk_source_dir(
                canon,
                &mut sub,
                (IN_RAM_SEARCH_MAX_FILES + 1).saturating_sub(targets.len()),
            );
            for f in sub {
                if !targets.iter().any(|(existing, _)| existing == &f) {
                    targets.push((f, ws_root.clone()));
                }
                if targets.len() > IN_RAM_SEARCH_MAX_FILES {
                    return Ok(None);
                }
            }
        } else {
            if !targets.iter().any(|(existing, _)| existing == canon) {
                targets.push((canon.clone(), ws_root.clone()));
            }
            if targets.len() > IN_RAM_SEARCH_MAX_FILES {
                return Ok(None);
            }
        }
    }

    let case_sensitive = needles.iter().any(|n| n.chars().any(char::is_uppercase));
    // Strictly gate 128-bit ASCII trigram bloom prefilter on ALL needles >= 3 ASCII bytes
    // (guarantees zero false negatives on UTF-8 case-insensitive or short queries).
    let needle_blooms: Option<Vec<[u64; 2]>> =
        if !needles.is_empty() && needles.iter().all(|n| n.len() >= 3 && n.is_ascii()) {
            Some(
                needles
                    .iter()
                    .map(|n| trigram_bloom128_ascii_lower(n.as_bytes()))
                    .collect(),
            )
        } else {
            None
        };
    let single_file = targets.len() == 1;
    let per_file_scan_cap = if single_file {
        cap.max(PER_FILE_SCAN_CANDIDATES)
    } else {
        PER_FILE_SCAN_CANDIDATES
    };
    let mut per_file: Vec<Vec<SearchHit>> = Vec::with_capacity(targets.len().min(16));
    let mut scan_truncated = false;

    for (file, ws_root) in targets {
        search_time_left(deadline)?;
        let Ok(entry) = svc.store.get_full_entry(&file, Some(&ws_root)) else {
            continue;
        };
        if let Some(ref blooms) = needle_blooms {
            if entry.content_bloom != [0, 0]
                && !blooms
                    .iter()
                    .any(|&nb| bloom128_may_contain(entry.content_bloom, nb))
            {
                continue;
            }
        }
        let Some(text) = entry.content.as_deref() else {
            continue;
        };
        let mut line_nums = search_lines_literals(
            text,
            &entry.line_offsets,
            needles,
            case_sensitive,
            per_file_scan_cap,
        );
        if line_nums.is_empty() {
            continue;
        }
        if line_nums.len() >= per_file_scan_cap {
            scan_truncated = true;
        }
        if code_only {
            let mut ext_buf = [0u8; 16];
            let ext = ext_lower_buf(&file, &mut ext_buf);
            let Some(cleaned) = entry.cleaned_code_for_ext(ext, &svc.store) else {
                continue;
            };
            line_nums.retain(|&ln| {
                let clean = line_slice_at(&cleaned, &entry.line_offsets, ln);
                line_contains_any_needle(clean, needles, case_sensitive)
            });
            if line_nums.is_empty() {
                continue;
            }
        }
        let mut file_hits = Vec::with_capacity(line_nums.len());
        for ln in line_nums {
            file_hits.push(SearchHit {
                path: file.clone(),
                workspace: ws_root.clone(),
                line: ln as usize,
                snippet: search_snippet(entry.line_slice(ln)),
            });
        }
        per_file.push(file_hits);
    }
    Ok(Some(rank_and_select_hits(svc, per_file, cap, scan_truncated)))
}

pub(super) fn filter_grouped_hits_code_only(
    svc: &BrokerService,
    query: &str,
    match_mode: RgMatchMode,
    grouped: &mut Vec<Vec<SearchHit>>,
) {
    enum Filter<'a> {
        Literals(Vec<&'a str>, bool),
        Regex(Vec<Vec<String>>, bool),
    }
    let filter = match match_mode {
        RgMatchMode::FixedSmartCase => {
            Filter::Literals(vec![query], query.chars().any(char::is_uppercase))
        }
        RgMatchMode::FixedCi => Filter::Literals(vec![query], false),
        RgMatchMode::Regex => {
            if let Some(needles) = parse_literal_alternation(query) {
                let cs = needles.iter().any(|n| n.chars().any(char::is_uppercase));
                Filter::Literals(needles, cs)
            } else {
                let branches = extract_regex_required_branches(query);
                let cs = !query.contains("(?")
                    && branches.iter().flatten().any(|s| s.chars().any(char::is_uppercase));
                Filter::Regex(branches, cs)
            }
        }
    };

    for hits in grouped.iter_mut() {
        let Some(first) = hits.first() else {
            continue;
        };
        let Ok(entry) = svc.store.get_full_entry(&first.path, Some(&first.workspace)) else {
            continue;
        };
        let mut ext_buf = [0u8; 16];
        let ext = ext_lower_buf(&first.path, &mut ext_buf);
        let Some(cleaned) = entry.cleaned_code_for_ext(ext, &svc.store) else {
            continue;
        };
        hits.retain(|hit| {
            let clean = line_slice_at(&cleaned, &entry.line_offsets, hit.line as u32);
            if clean.trim().is_empty() {
                return false;
            }
            match &filter {
                Filter::Literals(needles, cs) => line_contains_any_needle(clean, needles, *cs),
                Filter::Regex(branches, cs) => {
                    branches.is_empty()
                        || branches
                            .iter()
                            .any(|req| req.iter().all(|tok| line_contains_needle(clean, tok, *cs)))
                }
            }
        });
    }
    grouped.retain(|g| !g.is_empty());
}

fn ext_lower_buf<'a>(path: &Path, buf: &'a mut [u8; 16]) -> &'a str {
    let Some(raw) = path.extension().and_then(|s| s.to_str()) else {
        return "";
    };
    if raw.len() > buf.len() || !raw.is_ascii() {
        return "";
    }
    for (i, b) in raw.bytes().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    std::str::from_utf8(&buf[..raw.len()]).unwrap_or("")
}

fn line_contains_any_needle(line: &str, needles: &[&str], case_sensitive: bool) -> bool {
    needles.iter().any(|&n| line_contains_needle(line, n, case_sensitive))
}

fn line_contains_needle(line: &str, needle: &str, case_sensitive: bool) -> bool {
    if needle.is_empty() {
        return true;
    }
    if case_sensitive {
        return line.contains(needle);
    }
    if needle.is_ascii() {
        let (hay, ndl) = (line.as_bytes(), needle.as_bytes());
        return ndl.len() <= hay.len()
            && hay.windows(ndl.len()).any(|w| w.eq_ignore_ascii_case(ndl));
    }
    line.to_lowercase().contains(&needle.to_lowercase())
}

fn extract_regex_required_branches(pattern: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = pattern.chars().collect();
    // Bail out safely on extended free-spacing mode `(?x)` where whitespace is insignificant.
    if has_extended_flag(&chars) {
        return Vec::new();
    }
    let Some(branches) = split_top_level_alt(&chars) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(branches.len());
    for slice in branches {
        let mut req = Vec::new();
        collect_required_literals(slice, &mut req);
        out.push(req);
    }
    out
}

fn has_extended_flag(chars: &[char]) -> bool {
    let mut i = 0;
    while i + 2 < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == '(' && chars[i + 1] == '?' {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != ')' && chars[j] != ':' {
                if chars[j] == 'x' {
                    return true;
                }
                j += 1;
            }
        }
        i += 1;
    }
    false
}

fn split_top_level_alt(chars: &[char]) -> Option<Vec<&[char]>> {
    let mut branches = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut in_class = false;
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            i += 2;
            continue;
        }
        if in_class {
            if c == ']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match c {
            '[' => {
                in_class = true;
                if chars.get(i + 1) == Some(&'^') {
                    i += 1;
                }
                if chars.get(i + 1) == Some(&']') {
                    i += 1;
                }
            }
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
            }
            '|' if depth == 0 => {
                branches.push(&chars[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if depth != 0 || in_class {
        return None;
    }
    branches.push(&chars[start..]);
    Some(branches)
}

fn collect_required_literals(chars: &[char], out: &mut Vec<String>) {
    let mut cur = String::new();
    let mut i = 0usize;
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if !cur.is_empty() {
            out.push(std::mem::take(cur));
        }
    };
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                let Some(&next) = chars.get(i + 1) else {
                    break;
                };
                if matches!(
                    next,
                    '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
                        | '\\' | '/' | '-' | ':' | ';' | ',' | '=' | '<' | '>'
                ) {
                    cur.push(next);
                    i += 2;
                } else {
                    flush(&mut cur, out);
                    i += 2;
                    if matches!(next, 'p' | 'P' | 'u' | 'x') && chars.get(i) == Some(&'{') {
                        while i < chars.len() && chars[i] != '}' {
                            i += 1;
                        }
                        if i < chars.len() {
                            i += 1;
                        }
                    } else if next == 'x' {
                        i = (i + 2).min(chars.len());
                    }
                }
            }
            '[' => {
                flush(&mut cur, out);
                i += 1;
                if chars.get(i) == Some(&'^') {
                    i += 1;
                }
                if chars.get(i) == Some(&']') {
                    i += 1;
                }
                while i < chars.len() {
                    if chars[i] == '\\' {
                        i += 2;
                    } else if chars[i] == ']' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            '(' => {
                flush(&mut cur, out);
                let mut depth = 1usize;
                let mut in_class = false;
                let mut j = i + 1;
                let mut has_alt = false;
                while j < chars.len() && depth > 0 {
                    if chars[j] == '\\' {
                        j += 2;
                        continue;
                    }
                    if in_class {
                        if chars[j] == ']' {
                            in_class = false;
                        }
                    } else if chars[j] == '[' {
                        in_class = true;
                        if chars.get(j + 1) == Some(&'^') {
                            j += 1;
                        }
                        if chars.get(j + 1) == Some(&']') {
                            j += 1;
                        }
                    } else if chars[j] == '(' {
                        depth += 1;
                    } else if chars[j] == ')' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    } else if chars[j] == '|' && depth == 1 {
                        has_alt = true;
                    }
                    j += 1;
                }
                let after = chars.get(j + 1).copied();
                let optional = matches!(after, Some('?' | '*' | '{'));
                let inner_start = if chars.get(i + 1) == Some(&'?') {
                    if chars.get(i + 2) == Some(&':') { Some(i + 3) } else { None }
                } else {
                    Some(i + 1)
                };
                if depth == 0 && !has_alt && !optional {
                    if let Some(s) = inner_start {
                        if s <= j {
                            collect_required_literals(&chars[s..j], out);
                        }
                    }
                }
                i = (j + 1).min(chars.len());
            }
            '?' | '*' => {
                cur.pop();
                flush(&mut cur, out);
                i += 1;
            }
            '+' => {
                flush(&mut cur, out);
                i += 1;
            }
            '{' => {
                cur.pop();
                flush(&mut cur, out);
                while i < chars.len() && chars[i] != '}' {
                    i += 1;
                }
                if i < chars.len() {
                    i += 1;
                }
            }
            '.' | '^' | '$' => {
                flush(&mut cur, out);
                i += 1;
            }
            c => {
                cur.push(c);
                i += 1;
            }
        }
    }
    flush(&mut cur, out);
}

#[cfg(test)]
mod tests {
    use super::super::{op_search, op_search_batch, SearchOptions};
    use crate::base::json::Json;
    use crate::rpc::BrokerService;
    use std::fs;
    use std::path::PathBuf;

    fn temp_ws(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ctx-codeonly-{tag}-{}-{}", std::process::id(), crate::store::now_ms_u64()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn code_only_drops_comments_and_strings_in_cpp_rust_python_single_and_batch() {
        let ws = temp_ws("langs");
        fs::write(
            ws.join("calc.hpp"),
            concat!(
                "// target_sym(1) in cpp line comment\n",
                "/* target_sym(2) in block comment */\n",
                "const char* a = \"target_sym(3) in string\";\n",
                "const char* b = R\"(target_sym(4) in raw)\";\n",
                "int res = target_sym(42);\n",
            ),
        ).unwrap();
        fs::write(
            ws.join("calc.rs"),
            concat!(
                "// target_sym(1) in rust comment\n",
                "/* outer /* target_sym(2) nested */ */\n",
                "let s = r#\"target_sym(3) in rust raw\"#;\n",
                "let v = target_sym(7);\n",
            ),
        ).unwrap();
        fs::write(
            ws.join("calc.py"),
            concat!(
                "# target_sym(1) in py comment\n",
                "\"\"\"target_sym(2) in docstring\"\"\"\n",
                "msg = 'target_sym(3) in py string'\n",
                "val = target_sym(9)\n",
            ),
        ).unwrap();

        let svc = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();

        // Single search with code_only=true via in-RAM literal path
        let opts_code = SearchOptions::from_request(&Json::obj(vec![("code_only", Json::Bool(true))]), 20);
        assert!(opts_code.code_only);
        let only = op_search(&svc, "target_sym", &[], opts_code, Some(&ws)).unwrap();
        assert!(only.contains("calc.hpp:5: int res = target_sym(42);"));
        assert!(only.contains("calc.rs:4: let v = target_sym(7);"));
        assert!(only.contains("calc.py:4: val = target_sym(9)"));
        for noise in ["comment", "string", "raw", "nested", "docstring"] {
            assert!(!only.contains(noise), "leaked noise `{noise}` in:\n{only}");
        }

        // Default code_only=false retains comment & string hits
        let opts_all = SearchOptions::from_request(&Json::Null, 20);
        assert!(!opts_all.code_only);
        let all = op_search(&svc, "target_sym", &[], opts_all, Some(&ws)).unwrap();
        assert!(all.contains("cpp line comment") && all.contains("docstring"));

        // Batch search with global code_only=true and per-item override code_only=false
        let batch_items = [
            Json::Str("calc.hpp:target_sym".into()),
            Json::obj(vec![
                ("q", Json::Str("calc.py:target_sym".into())),
                ("code_only", Json::Bool(false)),
            ]),
        ];
        let batch = op_search_batch(&svc, &batch_items, opts_code, Some(&ws)).unwrap();
        assert!(batch.contains("calc.hpp:5: int res = target_sym(42);"));
        assert!(!batch.contains("cpp line comment"));
        assert!(batch.contains("py comment") && batch.contains("val = target_sym(9)"));

        // Direct post-filter verification for Regex mode (runs deterministically on all OSes even without `rg`)
        let canon_ws = fs::canonicalize(&ws).unwrap();
        let mk_group = |name: &str, lines: usize| -> Vec<super::super::SearchHit> {
            let p = canon_ws.join(name);
            (1..=lines)
                .map(|ln| super::super::SearchHit {
                    path: p.clone(),
                    workspace: canon_ws.clone(),
                    line: ln,
                    snippet: format!("{name}:{ln}"),
                })
                .collect()
        };
        let mut grouped = vec![mk_group("calc.hpp", 5), mk_group("calc.rs", 4), mk_group("calc.py", 4)];
        super::filter_grouped_hits_code_only(&svc, r"target_sym\s*\(", super::super::RgMatchMode::Regex, &mut grouped);
        let kept: Vec<(String, usize)> = grouped
            .iter()
            .flatten()
            .map(|h| (h.path.file_name().unwrap().to_string_lossy().into_owned(), h.line))
            .collect();
        assert_eq!(kept, vec![("calc.hpp".into(), 5), ("calc.rs".into(), 4), ("calc.py".into(), 4)]);

        // End-to-end regex search via external `rg` when available in the environment
        let has_rg = crate::base::platform::hidden_command(crate::base::platform::resolve_tool("rg"))
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if has_rg {
            let rx_all = op_search(&svc, r"target_sym\s*\(", &[], opts_all, Some(&ws)).unwrap();
            assert!(rx_all.contains("cpp line comment") && rx_all.contains("py string"));
            let rx = op_search(&svc, r"target_sym\s*\(", &[], opts_code, Some(&ws)).unwrap();
            assert!(rx.contains("calc.hpp:5:") && rx.contains("calc.rs:4:") && rx.contains("calc.py:4:"));
            for noise in ["comment", "string", "raw", "nested", "docstring"] {
                assert!(!rx.contains(noise), "regex leaked noise `{noise}` in:\n{rx}");
            }
        }

        let _ = fs::remove_dir_all(&ws);
    }
}
