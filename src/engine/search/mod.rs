mod ram;
mod render;
mod rg;

pub use render::cap_text;

use crate::base::json::Json;
use crate::base::security::is_sensitive_path;
use crate::engine::is_safe_shorthand_candidate;
use crate::rpc::BrokerService;
use crate::store::resolve_input_path;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum SearchError {
    Busy,
    Timeout,
    Failed(String),
}

const SEARCH_TIMEOUT: Duration = Duration::from_secs(5);
pub const SEARCH_RESPONSE_BYTES: usize = 8 * 1024;
const SEARCH_SNIPPET_CHARS: usize = 200;

struct SearchHit {
    path: PathBuf,
    workspace: PathBuf,
    line: usize,
    snippet: String,
}

struct SearchCollection<'a> {
    svc: &'a BrokerService,
    cwd: Option<&'a Path>,
    deadline: Instant,
    cap: usize,
    hits: Vec<SearchHit>,
}

fn search_time_left(deadline: Instant) -> Result<Duration, SearchError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(SearchError::Timeout)
}

fn search_snippet(text: &str) -> String {
    text.trim().chars().take(SEARCH_SNIPPET_CHARS).collect()
}

#[derive(Clone, Copy)]
pub struct SearchOptions {
    pub max_results: usize,
    pub with_scopes: bool,
    pub context_lines: usize,
    pub max_bytes: usize,
}

impl SearchOptions {
    pub fn from_request(request: &Json, default_results: usize) -> Self {
        Self {
            max_results: request.get_usize("max_results").unwrap_or(default_results),
            with_scopes: request.get_str("detail") == Some("scopes"),
            context_lines: request.get_usize("context_lines").unwrap_or(0).min(4),
            max_bytes: request
                .get_i64("max_bytes")
                .unwrap_or(SEARCH_RESPONSE_BYTES as i64)
                .clamp(1, SEARCH_RESPONSE_BYTES as i64) as usize,
        }
    }

    fn for_item(self, item: &Json) -> Self {
        Self {
            max_results: item.get_usize("max_results").unwrap_or(self.max_results),
            with_scopes: item
                .get_str("detail")
                .map_or(self.with_scopes, |detail| detail == "scopes"),
            context_lines: item
                .get_usize("context_lines")
                .unwrap_or(self.context_lines)
                .min(4),
            ..self
        }
    }
}

pub fn op_search(
    svc: &BrokerService,
    query: &str,
    roots: &[String],
    options: SearchOptions,
    cwd: Option<&Path>,
) -> Result<String, SearchError> {
    let hits = collect_search_hits(
        svc,
        query,
        roots,
        options.max_results,
        cwd,
        Instant::now() + SEARCH_TIMEOUT,
    )?;
    if hits.is_empty() {
        return Ok(render::cap_text(
            &format!("0 matches for `{}`.\n", query.trim()),
            options.max_bytes,
        ));
    }
    Ok(render::render(
        svc,
        vec![(Ok(hits), options)],
        false,
        options.max_bytes,
    ))
}

fn is_plausible_root_spec(left: &str) -> bool {
    let trimmed = left.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut any_part = false;
    for raw_part in trimmed.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            return false;
        }
        any_part = true;
        for ch in part.chars() {
            if matches!(
                ch,
                ':' | ' '
                    | '\t'
                    | '|'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '*'
                    | '+'
                    | '?'
                    | '^'
                    | '$'
                    | '"'
            ) {
                return false;
            }
        }
    }
    any_part
}

/// Parses `"root1,root2:query"` shorthand while preserving C++ `::` (`Foo::bar` or `Mod:::globalFn`).
pub fn parse_shorthand_search_spec(
    raw: &str,
    require_root: bool,
) -> Result<(String, Vec<String>), SearchError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(SearchError::Failed("query must not be empty".to_string()));
    }
    let bytes = s.as_bytes();
    let mut split_at: Option<usize> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b':' {
            let is_win_drive = i == 1
                && bytes[0].is_ascii_alphabetic()
                && matches!(bytes.get(2), Some(b'/' | b'\\'));
            if is_win_drive {
                i += 1;
                continue;
            }
            if bytes.get(i..i + 3) == Some(b":::") {
                split_at = Some(i);
                break;
            }
            if bytes.get(i..i + 2) == Some(b"::") {
                // C++ `::` cannot appear inside a file/module root; stop scanning for a root prefix.
                break;
            }
            split_at = Some(i);
            break;
        }
        i += 1;
    }

    if let Some(colon_idx) = split_at {
        let left = &s[..colon_idx];
        if is_plausible_root_spec(left) {
            let query = s[colon_idx + 1..].trim();
            if query.is_empty() {
                return Err(SearchError::Failed("query must not be empty".to_string()));
            }
            let roots: Vec<String> = left
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
            return Ok((query.to_string(), roots));
        }
    }

    if require_root {
        return Err(SearchError::Failed(
            "shorthand batch item must be 'root:query'".to_string(),
        ));
    }
    Ok((s.to_string(), Vec::new()))
}

#[inline]
fn is_comment_only_line(path: &Path, snippet: &str) -> bool {
    let t = snippet.trim_start();
    if t.starts_with("//")
        || t.starts_with("/*")
        || t.starts_with("*/")
        || t == "*"
        || t.starts_with("* ")
        || t.starts_with("*\t")
        || t.starts_with("-- ")
    {
        return true;
    }
    if t.starts_with('#') {
        let is_md = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| {
                e.eq_ignore_ascii_case("md")
                    || e.eq_ignore_ascii_case("mdx")
                    || e.eq_ignore_ascii_case("markdown")
            });
        // Preserve Markdown headings (`# Title`) and C/C++ preprocessor directives (`#include`/`#define`).
        if !is_md && !t.starts_with("#include") && !t.starts_with("#define") && !t.starts_with("#pragma") && !t.starts_with("#if") && !t.starts_with("#endif") && !t.starts_with("#[") && !t.starts_with("#![") {
            return true;
        }
    }
    false
}

/// Zero-division round-robin quota across files, prioritizing code lines over comment-only lines
/// when total matches exceed `cap`, while preserving exact file order and ascending line numbers.
fn prioritize_and_balance_file_hits(per_file: Vec<Vec<SearchHit>>, cap: usize) -> Vec<SearchHit> {
    let total: usize = per_file.iter().map(Vec::len).sum();
    if total <= cap {
        let mut flat = Vec::with_capacity(total);
        for mut group in per_file {
            flat.append(&mut group);
        }
        return flat;
    }

    let file_count = per_file.len();
    let mut priority_orders: Vec<Vec<usize>> = Vec::with_capacity(file_count);
    let mut picked_masks: Vec<Vec<bool>> = Vec::with_capacity(file_count);

    for group in &per_file {
        let mut order = Vec::with_capacity(group.len());
        for (idx, hit) in group.iter().enumerate() {
            if !is_comment_only_line(&hit.path, &hit.snippet) {
                order.push(idx);
            }
        }
        for (idx, hit) in group.iter().enumerate() {
            if is_comment_only_line(&hit.path, &hit.snippet) {
                order.push(idx);
            }
        }
        priority_orders.push(order);
        picked_masks.push(vec![false; group.len()]);
    }

    let mut cursors = vec![0usize; file_count];
    let mut picked = 0usize;
    while picked < cap {
        let mut advanced = false;
        for f_idx in 0..file_count {
            let cur = cursors[f_idx];
            if cur < priority_orders[f_idx].len() {
                let hit_idx = priority_orders[f_idx][cur];
                cursors[f_idx] = cur + 1;
                picked_masks[f_idx][hit_idx] = true;
                picked += 1;
                advanced = true;
                if picked >= cap {
                    break;
                }
            }
        }
        if !advanced {
            break;
        }
    }

    let mut out = Vec::with_capacity(picked);
    for (f_idx, group) in per_file.into_iter().enumerate() {
        for (h_idx, hit) in group.into_iter().enumerate() {
            if picked_masks[f_idx][h_idx] {
                out.push(hit);
            }
        }
    }
    out
}

fn parse_literal_alternation(query: &str) -> Option<Vec<&str>> {
    if query.is_empty() {
        return None;
    }
    for ch in query.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$'
        ) {
            return None;
        }
    }
    let parts: Vec<&str> = query.split('|').collect();
    if parts.len() > 8 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    Some(parts)
}

fn collect_search_hits(
    svc: &BrokerService,
    query: &str,
    roots: &[String],
    max_results: usize,
    cwd: Option<&Path>,
    deadline: Instant,
) -> Result<Vec<SearchHit>, SearchError> {
    search_time_left(deadline)?;
    let q = query.trim();
    if q.is_empty() {
        return Err(SearchError::Failed("query must not be empty".to_string()));
    }
    let cap = max_results.clamp(1, 120);

    // (canon_path, ws_root, is_dir)
    let mut admitted_roots: Vec<(PathBuf, PathBuf, bool)> = Vec::with_capacity(roots.len().max(1));
    if roots.is_empty() {
        let base = cwd
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let (canon_dir, ws_root) = svc
            .allowlist
            .admit_dir(&base, Some(&base))
            .map_err(SearchError::Failed)?;
        admitted_roots.push((canon_dir, ws_root, true));
    } else {
        let mut first_non_refusal_err: Option<String> = None;
        for r in roots {
            search_time_left(deadline)?;
            let cleaned = r.trim().trim_end_matches("/**").trim_end_matches("/*");
            let resolved = resolve_input_path(cleaned, cwd);
            if !resolved.exists()
                && is_safe_shorthand_candidate(cleaned)
                && !is_sensitive_path(&resolved)
            {
                let base = cwd.map(Path::to_path_buf).unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                });
                if let Ok((_, ws_root)) = svc.allowlist.admit_dir(&base, Some(&base)) {
                    let dirs = svc.store.find_workspace_dirs(cleaned, &ws_root, 8);
                    if !dirs.is_empty() {
                        let mut any_admitted = false;
                        for dir in dirs {
                            match svc.allowlist.admit_dir(&dir, cwd) {
                                Ok((cd, wr)) => {
                                    admitted_roots.push((cd, wr, true));
                                    any_admitted = true;
                                }
                                Err(e) if e.starts_with("REFUSED") => {
                                    return Err(SearchError::Failed(e));
                                }
                                Err(e) => {
                                    if first_non_refusal_err.is_none() {
                                        first_non_refusal_err = Some(e);
                                    }
                                }
                            }
                        }
                        if any_admitted {
                            continue;
                        }
                    } else {
                        let matches = svc.store.find_workspace_paths(cleaned, &ws_root, 16);
                        if !matches.is_empty() {
                            let mut any_admitted = false;
                            for m in matches {
                                if let Ok((cf, wr)) = svc.allowlist.admit_file(&m, cwd) {
                                    admitted_roots.push((cf, wr, false));
                                    any_admitted = true;
                                }
                            }
                            if any_admitted {
                                continue;
                            }
                        }
                    }
                }
            }

            if resolved.is_dir() {
                match svc.allowlist.admit_dir(&resolved, cwd) {
                    Ok((canon_dir, ws_root)) => admitted_roots.push((canon_dir, ws_root, true)),
                    Err(e) if e.starts_with("REFUSED") => return Err(SearchError::Failed(e)),
                    Err(e) => {
                        if first_non_refusal_err.is_none() {
                            first_non_refusal_err = Some(e);
                        }
                    }
                }
            } else {
                match svc.allowlist.admit_file(&resolved, cwd) {
                    Ok((canon_f, ws_root)) => {
                        if !canon_f.is_file() {
                            if first_non_refusal_err.is_none() {
                                first_non_refusal_err =
                                    Some(format!("search root is not a regular file: {}", r));
                            }
                        } else {
                            admitted_roots.push((canon_f, ws_root, false));
                        }
                    }
                    Err(e) if e.starts_with("REFUSED") => return Err(SearchError::Failed(e)),
                    Err(e) => {
                        if first_non_refusal_err.is_none() {
                            first_non_refusal_err = Some(e);
                        }
                    }
                }
            }
        }
        if admitted_roots.is_empty() {
            return Err(SearchError::Failed(first_non_refusal_err.unwrap_or_else(
                || "no readable search roots found".to_string(),
            )));
        }
    }

    if let Some(needles) = parse_literal_alternation(q) {
        if let Some(simd_hits) =
            ram::try_in_ram_simd_search(svc, &needles, &admitted_roots, cap, deadline)?
        {
            return Ok(simd_hits);
        }
    }

    let multi_roots = admitted_roots.len() > 1;
    let search_roots: Vec<PathBuf> = admitted_roots.into_iter().map(|(p, _, _)| p).collect();
    let collect_cap = if multi_roots {
        cap.saturating_mul(2).min(160)
    } else {
        cap
    };
    let mut collection = SearchCollection {
        svc,
        cwd,
        deadline,
        cap: collect_cap,
        hits: Vec::new(),
    };
    rg::run_rg_or_fallback(q, &search_roots, &mut collection)?;
    if collection.hits.len() <= cap {
        return Ok(collection.hits);
    }
    let mut grouped: Vec<Vec<SearchHit>> = Vec::new();
    for hit in collection.hits {
        if let Some(existing) = grouped
            .iter_mut()
            .find(|g| g[0].path == hit.path && g[0].workspace == hit.workspace)
        {
            existing.push(hit);
        } else {
            grouped.push(vec![hit]);
        }
    }
    Ok(prioritize_and_balance_file_hits(grouped, cap))
}

pub fn op_search_batch(
    svc: &BrokerService,
    queries: &[Json],
    defaults: SearchOptions,
    cwd: Option<&Path>,
) -> Result<String, SearchError> {
    if !(1..=4).contains(&queries.len()) {
        return Err(SearchError::Failed(
            "queries must contain 1–4 searches".to_string(),
        ));
    }
    let deadline = Instant::now() + SEARCH_TIMEOUT;
    let run = |item: &Json| {
        let options = defaults.for_item(item);
        (
            run_batch_item(svc, item, options.max_results, cwd, deadline),
            options,
        )
    };
    let results = if queries.len() == 1 {
        vec![run(&queries[0])]
    } else {
        thread::scope(|scope| {
            let run = &run;
            let handles: Vec<_> = queries
                .iter()
                .map(|item| scope.spawn(move || run(item)))
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle.join().unwrap_or_else(|_| {
                        (
                            Err(SearchError::Failed(
                                "batch search worker panicked".to_string(),
                            )),
                            defaults,
                        )
                    })
                })
                .collect()
        })
    };
    if results
        .iter()
        .all(|(result, _)| matches!(result, Err(SearchError::Busy)))
    {
        return Err(SearchError::Busy);
    }
    Ok(render::render(svc, results, true, defaults.max_bytes))
}

fn run_batch_item(
    svc: &BrokerService,
    item: &Json,
    max_results: usize,
    cwd: Option<&Path>,
    deadline: Instant,
) -> Result<Vec<SearchHit>, SearchError> {
    if let Some(spec) = item.as_str().or_else(|| item.get_str("q")) {
        let (query, roots) = parse_shorthand_search_spec(spec, true)?;
        return collect_search_hits(svc, &query, &roots, max_results, cwd, deadline);
    }
    let query = item.get_str("query").unwrap_or("");
    let roots = item.get("roots").and_then(Json::as_arr).and_then(|arr| {
        arr.iter()
            .map(|v| {
                v.as_str()
                    .filter(|root| !root.trim().is_empty())
                    .map(str::to_owned)
            })
            .collect::<Option<Vec<_>>>()
            .filter(|roots| !roots.is_empty())
    });
    let roots = roots.ok_or_else(|| {
        SearchError::Failed("roots must be a non-empty array of paths".to_string())
    })?;
    collect_search_hits(svc, query, &roots, max_results, cwd, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn literal_batch_completes_with_all_child_slots_reserved() {
        let workspace = std::env::temp_dir().join(format!(
            "ctx-search-ram-slots-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64(),
        ));
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("fixture.cpp"), "int simple_needle();\n").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
        svc.allowlist.register_hint(&workspace, true).unwrap();
        let permits: Vec<_> = (0..crate::rpc::MAX_CONCURRENT_SUBPROCS)
            .map(|_| svc.subproc_sem.acquire(Duration::from_secs(1)).unwrap())
            .collect();
        let term = Json::Str("fixture.cpp:simple_needle".into());
        let options = SearchOptions::from_request(&Json::Null, 1);
        let result = op_search_batch(&svc, &[term.clone(), term], options, Some(&workspace));
        fs::remove_dir_all(&workspace).unwrap();
        assert_eq!(
            result
                .unwrap()
                .matches("fixture.cpp:1: int simple_needle();")
                .count(),
            2
        );
        assert_eq!(svc.subproc_sem.active_count(), permits.len());
    }

    #[test]
    fn collected_search_reuses_the_callers_deadline() {
        let service = BrokerService::new_ephemeral_inproc(PathBuf::new());
        let expired = Instant::now() - SEARCH_TIMEOUT;
        assert!(matches!(
            collect_search_hits(&service, "sample", &[], 1, None, expired),
            Err(SearchError::Timeout)
        ));
    }

    #[test]
    fn shorthand_search_resolves_nested_workspace_dir_universally() {
        let workspace = std::env::temp_dir().join(format!(
            "ctx-search-dir-shorthand-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64(),
        ));
        let nested = workspace.join("deep/pkg/Alpha/Beta");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("Mod.hpp"), "int universal_dir_needle = 42;\n").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
        svc.allowlist.register_hint(&workspace, true).unwrap();
        let options = SearchOptions::from_request(&Json::Null, 10);
        let res = op_search(
            &svc,
            "universal_dir_needle",
            &["Alpha/Beta".into()],
            options,
            Some(&workspace),
        )
        .unwrap();
        fs::remove_dir_all(&workspace).unwrap();
        assert!(res.contains("deep/pkg/Alpha/Beta/Mod.hpp:1: int universal_dir_needle = 42;"));
    }
}
