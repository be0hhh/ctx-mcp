//! Byte-bounded search responses. Every section gets a turn before optional context.

use crate::engine::{search_snippet, SearchError, SearchHit, SearchOptions};
use crate::parser::{SymbolKind, SymbolSpan};
use crate::protocol::BrokerService;
use crate::store::{display_workspace_path, CachedFile};
use std::fmt::Write;
use std::sync::Arc;

const CAPPED: &str = "... [response capped]\n";

pub(crate) fn cap_text(text: &str, budget: usize) -> String {
    if text.len() <= budget {
        return text.into();
    }
    if budget < CAPPED.len() {
        return CAPPED[..budget].into();
    }
    let mut end = budget - CAPPED.len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + CAPPED.len());
    out.push_str(&text[..end]);
    out.push_str(CAPPED);
    out
}

pub(crate) fn render(
    svc: &BrokerService,
    results: Vec<(Result<Vec<SearchHit>, SearchError>, SearchOptions)>,
    numbered: bool,
    budget: usize,
) -> String {
    let mut sections: Vec<_> = results
        .into_iter()
        .enumerate()
        .map(|(index, (result, options))| Section::new(result, options, numbered.then_some(index + 1)))
        .collect();
    let headers = sections.iter().map(|section| section.text.len()).sum::<usize>();
    let mut remaining = budget.saturating_sub(headers + CAPPED.len());
    let mut capped = false;

    let mut first_rows: Vec<_> = sections.iter_mut().map(|section| {
        let mut row = String::new();
        if !section.hits.is_empty() {
            section.match_row(svc, &mut row);
        }
        row
    }).collect();
    if first_rows.iter().map(String::len).sum::<usize>() > remaining {
        for (section, row) in sections.iter_mut().zip(&mut first_rows) {
            if let Some(hit) = section.hits.first() {
                row.clear();
                let group = section.file.as_ref().expect("first match has a file group");
                let _ = writeln!(row, "{}:{}: {}", group.path, hit.line, hit.snippet);
                section.standalone = true;
            }
        }
        capped = true;
    }
    for (section, row) in sections.iter_mut().zip(first_rows) {
        if row.is_empty() {
            continue;
        }
        if append(&mut section.text, &row, &mut remaining) {
            section.emitted = 1;
        } else {
            section.blocked = true;
            capped = true;
        }
    }

    let mut row = String::new();
    loop {
        let mut progress = false;
        for section in &mut sections {
            if section.blocked || section.emitted == section.hits.len() {
                continue;
            }
            section.match_row(svc, &mut row);
            if append(&mut section.text, &row, &mut remaining) {
                section.emitted += 1;
                progress = true;
            } else {
                section.blocked = true;
                capped = true;
            }
        }
        if !progress {
            break;
        }
    }

    let mut out = String::with_capacity(budget.min(2048));
    for section in sections {
        out.push_str(&section.text);
        if let Some(diagnostic) = &section.diagnostic {
            if !append(&mut out, diagnostic, &mut remaining) {
                capped = true;
            }
        }
        capped |= !section.append_context(svc, &mut out, &mut remaining);
    }
    if capped && out.len() + CAPPED.len() <= budget {
        out.push_str(CAPPED);
    } else if capped {
        return cap_text(CAPPED, budget);
    }
    cap_text(&out, budget)
}

fn append(out: &mut String, row: &str, remaining: &mut usize) -> bool {
    if row.len() > *remaining {
        return false;
    }
    out.push_str(row);
    *remaining -= row.len();
    true
}

struct Section {
    text: String,
    hits: Vec<SearchHit>,
    options: SearchOptions,
    diagnostic: Option<String>,
    emitted: usize,
    blocked: bool,
    standalone: bool,
    file: Option<FileGroup>,
}

struct FileGroup {
    end: usize,
    path: String,
    outline: Option<Arc<CachedFile>>,
    last_scope: Option<usize>,
}

fn same_file(a: &SearchHit, b: &SearchHit) -> bool {
    a.path == b.path && a.workspace == b.workspace
}

fn enclosing_scope(outline: &CachedFile, line: usize) -> Option<(usize, &SymbolSpan)> {
    outline.symbols.iter().enumerate()
        .filter(|(_, sym)| sym.kind != SymbolKind::Namespace && (sym.start_line as usize..=sym.end_line as usize).contains(&line))
        .min_by_key(|(_, sym)| sym.end_line.saturating_sub(sym.start_line))
}

impl Section {
    fn new(
        result: Result<Vec<SearchHit>, SearchError>,
        options: SearchOptions,
        number: Option<usize>,
    ) -> Self {
        let mut text = number.map_or_else(String::new, |index| format!("[{index}]\n"));
        let mut diagnostic = None;
        let hits = match result {
            Ok(hits) if hits.is_empty() => {
                text.push_str("0 matches\n");
                hits
            }
            Ok(hits) => {
                let _ = writeln!(text, "Matches ({}):", hits.len());
                hits
            }
            Err(error) => {
                diagnostic = Some(match error {
                    SearchError::Timeout => "Timeout: shared search budget exhausted\n".into(),
                    SearchError::Busy => "Error: search busy\n".into(),
                    SearchError::Failed(error) => format!("Error: {error}\n"),
                });
                Vec::new()
            }
        };
        Self { text, hits, options, diagnostic, emitted: 0, blocked: false, standalone: false, file: None }
    }

    fn match_row(&mut self, svc: &BrokerService, row: &mut String) {
        let index = self.emitted;
        let hit = &self.hits[index];
        let new_file = self.file.as_ref().is_none_or(|group| index == group.end);
        if new_file {
            self.standalone = false;
            let end = index + self.hits[index..].iter().take_while(|next| same_file(hit, next)).count();
            let grouped = end > index + 1 && self.options.context_lines == 0;
            let outline = (self.options.with_scopes || grouped)
                .then(|| svc.store.get_outline_entry(&hit.path, Some(&hit.workspace)).ok())
                .flatten();
            self.file = Some(FileGroup {
                end,
                path: display_workspace_path(&hit.path, Some(&hit.workspace)),
                outline,
                last_scope: None,
            });
        }
        let group = self.file.as_mut().expect("current match has a file group");
        let outline = group.outline.as_deref();
        let enclosing = outline.and_then(|entry| enclosing_scope(entry, hit.line));

        row.clear();
        if self.options.with_scopes {
            let _ = write!(row, "{}:{}", group.path, hit.line);
            if let Some(entry) = outline {
                if let Some((_, sym)) = enclosing {
                    let _ = write!(row, " [in {} {} L{}-L{}, {}L]", sym.kind.as_str(), sym.name, sym.start_line, sym.end_line, entry.line_count);
                } else {
                    let _ = write!(row, " [{}L]", entry.line_count);
                }
            }
            let _ = writeln!(row, ": {}", hit.snippet);
        } else if self.standalone || self.options.context_lines != 0 || (new_file && group.end == index + 1) {
            let _ = writeln!(row, "{}:{}: {}", group.path, hit.line, hit.snippet);
        } else {
            if new_file {
                let _ = writeln!(row, "{}", group.path);
            }
            let scope = enclosing.map(|(position, _)| position);
            if scope != group.last_scope {
                group.last_scope = scope;
                if let Some((_, sym)) = enclosing {
                    let name = sym.name.trim_start_matches("::");
                    if !name.is_empty() {
                        let _ = writeln!(row, "  @{name}");
                    }
                }
            }
            let _ = writeln!(row, "  {}: {}", hit.line, hit.snippet);
        }
    }

    fn append_context(&self, svc: &BrokerService, out: &mut String, remaining: &mut usize) -> bool {
        let context = self.options.context_lines;
        if context == 0 || self.options.with_scopes {
            return true;
        }
        let mut row = String::new();
        for group in self.hits[..self.emitted].chunk_by(same_file) {
            let first = &group[0];
            if *remaining == 0 {
                return false;
            }
            let Ok(entry) = svc.store.get_full_entry(&first.path, Some(&first.workspace)) else { continue };
            let total = entry.line_count as usize;
            if group.windows(2).any(|pair| pair[0].line >= pair[1].line) || group.iter().any(|hit| {
                hit.line == 0 || hit.line > total || search_snippet(entry.line_slice(hit.line as u32)) != hit.snippet
            }) {
                continue;
            }
            let mut first_row = true;
            let mut next_line = 1;
            for (index, hit) in group.iter().enumerate() {
                let start = hit.line.saturating_sub(context).max(next_line);
                let end = hit.line.saturating_add(context).min(total);
                let end = group.get(index + 1).map_or(end, |next| end.min(next.line - 1));
                for line in (start..=end).filter(|&line| line != hit.line) {
                    row.clear();
                    if first_row {
                        let path = display_workspace_path(&first.path, Some(&first.workspace));
                        let _ = writeln!(row, "-- {path} --");
                        first_row = false;
                    }
                    let _ = writeln!(row, "  {line}- {}", search_snippet(entry.line_slice(line as u32)));
                    if !append(out, &row, remaining) {
                        return false;
                    }
                }
                next_line = end + 1;
            }
        }
        true
    }
}
