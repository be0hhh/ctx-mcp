//! Byte-bounded search responses. Every section gets a turn before optional context.

use super::rank::{enclosing_scope, OmittedScope, SearchHitSet};
use super::{search_snippet, SearchError, SearchHit, SearchOptions};
use crate::base::simd::line_slice_at;
use crate::parser::build_cleaned_code_buffer_for_ext;
use crate::rpc::BrokerService;
use crate::store::{display_workspace_path, CachedFile};
use std::fmt::Write;
use std::sync::Arc;

const CAPPED: &str = "... [response capped]\n";
const FOOTER_MAX_BYTES: usize = 180;

pub fn cap_text(text: &str, budget: usize) -> String {
    if text.len() <= budget { return text.into(); }
    if budget < CAPPED.len() { return CAPPED[..budget].into(); }
    let mut end = budget - CAPPED.len();
    while !text.is_char_boundary(end) { end -= 1; }
    let mut out = String::with_capacity(end + CAPPED.len());
    out.push_str(&text[..end]);
    out.push_str(CAPPED);
    out
}

#[inline]
fn fair_share(rem: usize, n: usize) -> usize {
    match n {
        0 | 1 => rem,
        2 => rem >> 1,
        3 => (rem.saturating_mul(341)) >> 10,
        4 => rem >> 2,
        5 => (rem.saturating_mul(205)) >> 10,
        _ => (rem.saturating_mul(171)) >> 10,
    }
}

pub(super) fn render(
    svc: &BrokerService,
    results: Vec<(Result<Arc<SearchHitSet>, SearchError>, SearchOptions)>,
    numbered: bool,
    budget: usize,
) -> String {
    let mut sections: Vec<_> = results
        .into_iter()
        .enumerate()
        .map(|(i, (res, opts))| Section::new(res, opts, numbered.then_some(i + 1)))
        .collect();
    let reserved: usize = sections
        .iter()
        .map(|s| {
            s.text.len()
                + s.diagnostic.as_ref().map_or(0, String::len)
                + s.footer.as_ref().map_or(0, String::len)
        })
        .sum();
    let mut remaining = budget.saturating_sub(reserved + CAPPED.len());
    let mut capped = reserved > budget;

    let mut first_rows: Vec<_> = sections
        .iter_mut()
        .map(|s| {
            let mut row = String::new();
            if !s.hits().is_empty() {
                s.match_row(svc, &mut row);
            }
            row
        })
        .collect();
    if first_rows.iter().map(String::len).sum::<usize>() > remaining {
        for (s, row) in sections.iter_mut().zip(&mut first_rows) {
            if let (Some(hit), Some(group)) = (s.hits().first(), s.file.as_ref()) {
                row.clear();
                let _ = writeln!(row, "{}:{}: {}", group.path, hit.line, hit.snippet);
                s.standalone = true;
            }
        }
        capped = true;
    }
    for (s, row) in sections.iter_mut().zip(first_rows) {
        if row.is_empty() {
            continue;
        }
        if append(&mut s.text, &row, &mut remaining) {
            s.emitted = 1;
        } else {
            s.blocked = true;
            capped = true;
        }
    }

    // Pass 1 (batch): guarantee each active section its zero-div fair share so late queries
    // `[4..6]` are never starved by verbose earlier queries `[1..3]`.
    let active_sections = sections
        .iter()
        .filter(|s| !s.blocked && s.emitted < s.hits().len())
        .count();
    if sections.len() > 1 && active_sections > 1 && remaining > 0 {
        let quota = fair_share(remaining, active_sections);
        for s in &mut sections {
            if s.blocked || s.emitted >= s.hits().len() {
                continue;
            }
            let mut sec_budget = quota.min(remaining);
            while s.emitted < s.hits().len() {
                let row_len = s.ensure_pending_row(svc);
                if row_len <= sec_budget {
                    if let Some(row) = s.pending_row.take() {
                        s.text.push_str(&row);
                        sec_budget -= row.len();
                        remaining -= row.len();
                        s.emitted += 1;
                    }
                } else {
                    break;
                }
            }
        }
    }

    // Pass 2: distribute any unused surplus budget round-robin across remaining sections.
    loop {
        let mut progress = false;
        for s in &mut sections {
            if s.blocked || s.emitted >= s.hits().len() {
                continue;
            }
            let row_len = s.ensure_pending_row(svc);
            if row_len <= remaining {
                if let Some(row) = s.pending_row.take() {
                    s.text.push_str(&row);
                    remaining -= row.len();
                    s.emitted += 1;
                    progress = true;
                }
            } else {
                s.blocked = true;
                capped = true;
            }
        }
        if !progress {
            break;
        }
    }

    let mut out = String::with_capacity(budget.min(2048));
    for s in sections {
        out.push_str(&s.text);
        if let Some(d) = &s.diagnostic {
            out.push_str(d);
        }
        if let Some(f) = &s.footer {
            out.push_str(f);
        }
        capped |= !s.append_context(svc, &mut out, &mut remaining);
    }
    if capped && out.len() + CAPPED.len() <= budget {
        out.push_str(CAPPED);
        return out;
    }
    cap_text(&out, budget)
}

fn format_omitted_footer(omitted_total: usize, scopes: &[OmittedScope]) -> Option<String> {
    if scopes.is_empty() || omitted_total == 0 { return None; }
    let mut line = format!("... +{omitted_total} more: ");
    let mut added = 0usize;
    for scope in scopes {
        let sep = if added == 0 { "" } else { ", " };
        let part = format!("{sep}@{} L{} (+{})", scope.label, scope.first_line, scope.count);
        if line.len() + part.len() + 1 > FOOTER_MAX_BYTES {
            if added == 0 {
                let mut combined = format!("{line}{part}");
                let mut end = combined.len().min(FOOTER_MAX_BYTES.saturating_sub(4));
                while end > 0 && !combined.is_char_boundary(end) { end -= 1; }
                combined.truncate(end);
                combined.push_str("...\n");
                return Some(combined);
            }
            break;
        }
        line.push_str(&part);
        added += 1;
    }
    line.push('\n');
    Some(line)
}

fn append(out: &mut String, row: &str, remaining: &mut usize) -> bool {
    if row.len() > *remaining { return false; }
    out.push_str(row);
    *remaining -= row.len();
    true
}

struct Section {
    text: String,
    set: Option<Arc<SearchHitSet>>,
    options: SearchOptions,
    diagnostic: Option<String>,
    footer: Option<String>,
    emitted: usize,
    blocked: bool,
    standalone: bool,
    file: Option<FileGroup>,
    pending_row: Option<String>,
}

struct FileGroup {
    end: usize,
    path: String,
    outline: Option<Arc<CachedFile>>,
    last_scope: Option<usize>,
}

fn same_file(a: &SearchHit, b: &SearchHit) -> bool { a.path == b.path && a.workspace == b.workspace }

impl Section {
    #[inline]
    fn hits(&self) -> &[SearchHit] {
        self.set.as_deref().map_or(&[], |s| s.hits.as_slice())
    }

    fn new(
        result: Result<Arc<SearchHitSet>, SearchError>,
        options: SearchOptions,
        number: Option<usize>,
    ) -> Self {
        let mut text = number.map_or_else(String::new, |n| format!("[{n}]\n"));
        let (mut diagnostic, mut footer) = (None, None);
        let set = match result {
            Ok(set) if set.hits.is_empty() => {
                if set.scan_truncated {
                    let why = set
                        .incomplete_note
                        .unwrap_or("scan stopped early at budget limit");
                    let _ = writeln!(
                        text,
                        "0 matches (INCOMPLETE scan: {why}; scope with 'dir:pattern' or install ripgrep 'rg')"
                    );
                } else {
                    text.push_str("0 matches\n");
                }
                Some(set)
            }
            Ok(set) => {
                let inc_suffix = match set.incomplete_note {
                    Some(why) => format!(" [INCOMPLETE: {why}]"),
                    None => String::new(),
                };
                if set.total_found == set.hits.len() && !set.scan_truncated {
                    let _ = writeln!(text, "Matches ({}){inc_suffix}:", set.hits.len());
                } else {
                    let plus = if set.scan_truncated { "+" } else { "" };
                    let _ = writeln!(
                        text,
                        "Matches ({} of {}{plus}){inc_suffix}:",
                        set.hits.len(),
                        set.total_found
                    );
                }
                footer = format_omitted_footer(
                    set.total_found.saturating_sub(set.hits.len()),
                    &set.omitted_scopes,
                );
                Some(set)
            }
            Err(err) => {
                diagnostic = Some(match err {
                    SearchError::Timeout => "Timeout: shared search budget exhausted\n".into(),
                    SearchError::Busy => "Error: search busy\n".into(),
                    SearchError::Failed(e) => format!("Error: {e}\n"),
                });
                None
            }
        };
        Self {
            text,
            set,
            options,
            diagnostic,
            footer,
            emitted: 0,
            blocked: false,
            standalone: false,
            file: None,
            pending_row: None,
        }
    }

    fn ensure_pending_row(&mut self, svc: &BrokerService) -> usize {
        if let Some(ref existing) = self.pending_row {
            return existing.len();
        }
        let mut row = String::new();
        self.match_row(svc, &mut row);
        let len = row.len();
        self.pending_row = Some(row);
        len
    }

    fn match_row(&mut self, svc: &BrokerService, row: &mut String) {
        let index = self.emitted;
        let Some(set) = self.set.as_deref() else {
            row.clear();
            return;
        };
        let hits = set.hits.as_slice();
        let hit = &hits[index];
        let new_file = self.file.as_ref().is_none_or(|g| index == g.end);
        if new_file {
            self.standalone = false;
            let end = index + hits[index..].iter().take_while(|n| same_file(hit, n)).count();
            let outline = svc.store.get_outline_entry(&hit.path, Some(&hit.workspace)).ok();
            self.file = Some(FileGroup {
                end, path: display_workspace_path(&hit.path, Some(&hit.workspace)), outline, last_scope: None,
            });
        }
        let Some(group) = self.file.as_mut() else { return; };
        let outline = group.outline.as_deref();
        let enclosing = outline.and_then(|e| enclosing_scope(e, hit.line));

        row.clear();
        if self.options.with_scopes {
            let _ = write!(row, "{}:{}", group.path, hit.line);
            if let Some(e) = outline {
                if let Some((_, sym)) = enclosing {
                    let _ = write!(row, " [in {} {} L{}-L{}, {}L]", sym.kind.as_str(), sym.name, sym.start_line, sym.end_line, e.line_count);
                } else {
                    let _ = write!(row, " [{}L]", e.line_count);
                }
            }
            let _ = writeln!(row, ": {}", hit.snippet);
        } else if self.standalone || self.options.context_lines != 0 || (new_file && group.end == index + 1) {
            let tag = enclosing
                .filter(|(_, s)| hit.line > s.start_line as usize)
                .map(|(_, s)| s.name.trim_start_matches("::"))
                .filter(|n| !n.is_empty());
            if let Some(name) = tag {
                let _ = writeln!(row, "{}:{} [@{name}]: {}", group.path, hit.line, hit.snippet);
            } else {
                let _ = writeln!(row, "{}:{}: {}", group.path, hit.line, hit.snippet);
            }
        } else {
            if new_file { let _ = writeln!(row, "{}", group.path); }
            let scope = enclosing.map(|(pos, _)| pos);
            if scope != group.last_scope {
                group.last_scope = scope;
                if let Some((_, sym)) = enclosing {
                    let name = sym.name.trim_start_matches("::");
                    if !name.is_empty() { let _ = writeln!(row, "  @{name}"); }
                }
            }
            let _ = writeln!(row, "  {}: {}", hit.line, hit.snippet);
        }
    }

    fn append_context(&self, svc: &BrokerService, out: &mut String, remaining: &mut usize) -> bool {
        if self.options.with_scopes || self.emitted == 0 { return true; }
        let auto_ctx = self.options.context_lines == 0 && self.emitted <= 6;
        let context = if self.options.context_lines > 0 { self.options.context_lines } else { usize::from(auto_ctx) };
        if context == 0 || (auto_ctx && *remaining < 128) { return true; }
        let mut row = String::new();
        for group in self.hits()[..self.emitted].chunk_by(same_file) {
            let first = &group[0];
            if *remaining == 0 { return auto_ctx; }
            let Ok(entry) = svc.store.get_full_entry(&first.path, Some(&first.workspace)) else { continue; };
            let total = entry.line_count as usize;
            if group.iter().any(|h| h.line == 0 || h.line > total || search_snippet(entry.line_slice(h.line as u32)) != h.snippet) {
                continue;
            }
            let cleaned_code = if auto_ctx && self.options.code_only {
                let ext = first.path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).unwrap_or_default();
                entry.content().map(|t| build_cleaned_code_buffer_for_ext(t, &ext))
            } else { None };
            let mut hit_lines: Vec<usize> = group.iter().map(|h| h.line).collect();
            hit_lines.sort_unstable();
            hit_lines.dedup();
            let (mut first_row, mut next_line) = (true, 1usize);
            for (idx, &hit_ln) in hit_lines.iter().enumerate() {
                let start = hit_ln.saturating_sub(context).max(next_line);
                let raw_end = hit_ln.saturating_add(context).min(total);
                let end = hit_lines.get(idx + 1).map_or(raw_end, |&n| raw_end.min(n.saturating_sub(1)));
                for line in (start..=end).filter(|&l| l != hit_ln) {
                    let snip = search_snippet(entry.line_slice(line as u32));
                    if auto_ctx && snip.is_empty() { continue; }
                    if let Some(ref cbuf) = cleaned_code {
                        if search_snippet(line_slice_at(cbuf, entry.line_offsets(), line as u32)) != snip { continue; }
                    }
                    row.clear();
                    if first_row {
                        let _ = writeln!(row, "-- {} --", display_workspace_path(&first.path, Some(&first.workspace)));
                        first_row = false;
                    }
                    let _ = writeln!(row, "  {line}- {snip}");
                    if !append(out, &row, remaining) { return auto_ctx; }
                }
                next_line = end + 1;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_hit() -> SearchHit {
        SearchHit { path: PathBuf::from("/tmp/ws/a.rs"), workspace: PathBuf::from("/tmp/ws"), line: 10, snippet: "let x = 1;".into() }
    }

    fn mk_set(
        hits: Vec<SearchHit>,
        total_found: usize,
        scan_truncated: bool,
        omitted_scopes: Vec<OmittedScope>,
    ) -> Result<Arc<SearchHitSet>, SearchError> {
        Ok(Arc::new(SearchHitSet {
            hits,
            total_found,
            scan_truncated,
            incomplete_note: None,
            omitted_scopes,
        }))
    }

    #[test]
    fn headers_and_omitted_scope_footer_respect_compatibility_and_cap() {
        let svc = BrokerService::new_ephemeral_inproc(PathBuf::from("/tmp/unused"));
        let opts = SearchOptions { max_results: 10, with_scopes: false, context_lines: 0, max_bytes: 4096, code_only: false };
        let scopes = || vec![
            OmittedScope { label: "scopeA".into(), first_line: 295, count: 2 },
            OmittedScope { label: "scopeB".into(), first_line: 410, count: 1 },
        ];

        let exact = render(&svc, vec![(mk_set(vec![sample_hit()], 1, false, Vec::new()), opts)], false, 4096);
        assert!(exact.starts_with("Matches (1):\n") && !exact.contains("more:"));

        let partial = render(&svc, vec![(mk_set(vec![sample_hit()], 4, false, scopes()), opts)], false, 4096);
        assert!(partial.starts_with("Matches (1 of 4):\n"));
        assert!(partial.contains("... +3 more: @scopeA L295 (+2), @scopeB L410 (+1)\n"));

        let omitted = render(&svc, vec![(mk_set(vec![sample_hit()], 4, true, scopes()), opts)], false, 4096);
        assert!(omitted.starts_with("Matches (1 of 4+):\n"));
        assert!(omitted.contains("... +3 more: @scopeA L295 (+2), @scopeB L410 (+1)\n"));

        let long_footer = format_omitted_footer(12, &[OmittedScope { label: "é".repeat(120), first_line: 10, count: 12 }]).unwrap();
        assert!(long_footer.len() <= FOOTER_MAX_BYTES && long_footer.ends_with("...\n"));

        let bulk_hits: Vec<SearchHit> = (1..=120).map(|line| SearchHit {
            path: PathBuf::from("/tmp/ws/bulk.cpp"), workspace: PathBuf::from("/tmp/ws"), line,
            snippet: format!("int bulk_line_{line:04}_padding_payload_text = {line};"),
        }).collect();
        let batch_out = render(&svc, vec![
            (mk_set(vec![sample_hit()], 5, false, vec![OmittedScope { label: "lateFn".into(), first_line: 200, count: 4 }]), opts),
            (Err(SearchError::Failed("REFUSED: path outside workspace".into())), opts),
            (mk_set(bulk_hits, 120, false, Vec::new()), opts),
        ], true, 1024);
        assert!(batch_out.len() <= 1024);
        assert!(batch_out.contains("REFUSED: path outside workspace"), "{batch_out}");
        assert!(batch_out.contains("@lateFn L200 (+4)"), "{batch_out}");
        assert!(batch_out.ends_with(CAPPED), "{batch_out}");

        let ws = std::env::temp_dir().join(format!("ctx-render-ctx-{}-{}", std::process::id(), crate::store::now_ms_u64()));
        std::fs::create_dir_all(&ws).unwrap();
        let src = (1..=12).map(|i| format!("int line_{i} = {i};\n")).collect::<String>();
        let fpath = ws.join("ranked.cpp");
        std::fs::write(&fpath, &src).unwrap();
        let svc_ws = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
        svc_ws.allowlist.register_hint(&ws, true).unwrap();
        let canon = std::fs::canonicalize(&fpath).unwrap();
        let mk_hit = |line: usize| SearchHit {
            path: canon.clone(), workspace: ws.clone(), line, snippet: format!("int line_{line} = {line};"),
        };
        let ranked_small = render(&svc_ws, vec![(mk_set(vec![mk_hit(9), mk_hit(3)], 2, false, Vec::new()), opts)], false, 4096);
        assert!(ranked_small.contains("-- ranked.cpp --"), "{ranked_small}");
        assert!(ranked_small.contains("  2- int line_2 = 2;") && ranked_small.contains("  4- int line_4 = 4;"));
        assert!(ranked_small.contains("  8- int line_8 = 8;") && ranked_small.contains("  10- int line_10 = 10;"));
        assert!(!ranked_small.contains(CAPPED));
        let many: Vec<SearchHit> = (1..=8).map(mk_hit).collect();
        let dense = render(&svc_ws, vec![(mk_set(many, 8, false, Vec::new()), opts)], false, 4096);
        assert!(!dense.contains("-- ranked.cpp --"), "{dense}");

        // Truncated 0-match result MUST emit an explicit INCOMPLETE scan warning (never silent `0 matches`).
        let incomplete_zero = Ok(Arc::new(SearchHitSet {
            hits: Vec::new(),
            total_found: 0,
            scan_truncated: true,
            incomplete_note: Some("rg/git unavailable; fallback walker stopped at 8,000 files"),
            omitted_scopes: Vec::new(),
        }));
        let zero_out = render(&svc, vec![(incomplete_zero, opts)], true, 4096);
        assert!(zero_out.contains("INCOMPLETE scan"), "{zero_out}");
        assert!(zero_out.contains("8,000 files"), "{zero_out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn six_query_batch_fair_share_never_starves_late_sections() {
        let svc = BrokerService::new_ephemeral_inproc(PathBuf::from("/tmp/unused"));
        let opts = SearchOptions {
            max_results: 30,
            with_scopes: false,
            context_lines: 0,
            max_bytes: 3072,
            code_only: false,
        };
        let heavy = |tag: &str| -> Vec<SearchHit> {
            (1..=40)
                .map(|line| SearchHit {
                    path: PathBuf::from(format!("/tmp/ws/{tag}.cpp")),
                    workspace: PathBuf::from("/tmp/ws"),
                    line,
                    snippet: format!("int {tag}_very_verbose_payload_{line:03}_{};", "x".repeat(120)),
                })
                .collect()
        };
        let light = |tag: &str| -> Vec<SearchHit> {
            (1..=6)
                .map(|line| SearchHit {
                    path: PathBuf::from(format!("/tmp/ws/{tag}.rs")),
                    workspace: PathBuf::from("/tmp/ws"),
                    line,
                    snippet: format!("fn {tag}_{line}() {{}}"),
                })
                .collect()
        };
        let results = vec![
            (mk_set(heavy("q1"), 40, false, Vec::new()), opts),
            (mk_set(heavy("q2"), 40, false, Vec::new()), opts),
            (mk_set(heavy("q3"), 40, false, Vec::new()), opts),
            (mk_set(light("q4"), 6, false, Vec::new()), opts),
            (mk_set(light("q5"), 6, false, Vec::new()), opts),
            (mk_set(light("q6"), 6, false, Vec::new()), opts),
        ];
        let out = render(&svc, results, true, 3072);
        assert!(out.len() <= 3072, "len={}", out.len());
        assert!(out.ends_with(CAPPED), "{out}");
        for idx in 1..=6 {
            assert!(out.contains(&format!("[{idx}]\n")), "missing [{idx}] in:\n{out}");
        }
        // Late light queries [4..6] each received all 6 hits without starvation!
        for tag in ["q4", "q5", "q6"] {
            for line in 1..=6 {
                assert!(
                    out.contains(&format!("fn {tag}_{line}()")),
                    "starved {tag} line {line} in:\n{out}"
                );
            }
        }
    }
}
