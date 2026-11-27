mod ram;
mod rank;
mod render;
mod rg;

pub use render::cap_text;

use crate::base::ext::policy;
use crate::base::json::Json;
use crate::base::security::is_sensitive_path;
use crate::engine::is_safe_shorthand_candidate;
use crate::rpc::BrokerService;
use crate::store::resolve_input_path;
use rank::{rank_and_select_hits, SearchHitSet};
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

#[derive(Clone, Copy)]
enum RgMatchMode {
    Regex,
    FixedSmartCase,
    FixedCi,
}

struct SearchCollection<'a> {
    svc: &'a BrokerService,
    cwd: Option<&'a Path>,
    deadline: Instant,
    cap: usize,
    hits: Vec<SearchHit>,
    scan_truncated: bool,
    incomplete_note: Option<&'static str>,
    match_mode: RgMatchMode,
}

fn search_time_left(deadline: Instant) -> Result<Duration, SearchError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|r| !r.is_zero())
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
    pub code_only: bool,
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
            code_only: request.get_bool("code_only").unwrap_or(false),
        }
    }

    fn for_item(self, item: &Json) -> Self {
        Self {
            max_results: item.get_usize("max_results").unwrap_or(self.max_results),
            with_scopes: item.get_str("detail").map_or(self.with_scopes, |d| d == "scopes"),
            context_lines: item.get_usize("context_lines").unwrap_or(self.context_lines).min(4),
            code_only: item.get_bool("code_only").unwrap_or(self.code_only),
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
    let hit_set = collect_search_hits(
        svc, query, roots, options.max_results, options.code_only, cwd, Instant::now() + SEARCH_TIMEOUT,
    )?;
    if hit_set.hits.is_empty() {
        let msg = if hit_set.scan_truncated {
            let why = hit_set
                .incomplete_note
                .unwrap_or("scan stopped early at budget limit");
            format!(
                "0 matches for `{}` (INCOMPLETE scan: {why}; scope with 'dir:pattern' or install ripgrep 'rg').\n",
                query.trim()
            )
        } else {
            format!("0 matches for `{}`.\n", query.trim())
        };
        return Ok(render::cap_text(&msg, options.max_bytes));
    }
    Ok(render::render(svc, vec![(Ok(hit_set), options)], false, options.max_bytes))
}

fn is_plausible_root_spec(left: &str) -> bool {
    let trimmed = left.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut any_part = false;
    for part in trimmed.split(',').map(str::trim) {
        if part.is_empty()
            || part.chars().any(|ch| matches!(
                ch, ':' | ' ' | '\t' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '?' | '^' | '$' | '"'
            ))
        {
            return false;
        }
        any_part = true;
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
    let mut split_at = None;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b':' {
            if i == 1 && bytes[0].is_ascii_alphabetic() && matches!(bytes.get(2), Some(b'/' | b'\\')) {
                i += 1;
                continue;
            }
            if bytes.get(i..i + 3) == Some(b":::") {
                split_at = Some(i);
                break;
            }
            if bytes.get(i..i + 2) != Some(b"::") {
                split_at = Some(i);
            }
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
            let roots = left.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
            return Ok((query.to_string(), roots));
        }
    }
    if require_root {
        return Err(SearchError::Failed("shorthand batch item must be 'root:query'".to_string()));
    }
    Ok((s.to_string(), Vec::new()))
}

fn parse_literal_alternation(query: &str) -> Option<Vec<&str>> {
    if query.is_empty()
        || query.chars().any(|ch| {
            matches!(ch, '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$')
        })
    {
        return None;
    }
    let parts: Vec<&str> = query.split('|').collect();
    if parts.len() > 8 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    Some(parts)
}

fn admit_root_candidate(
    svc: &BrokerService,
    path: &Path,
    label: &str,
    cwd: Option<&Path>,
    admitted: &mut Vec<(PathBuf, PathBuf, bool)>,
    first_err: &mut Option<String>,
) -> Result<bool, SearchError> {
    let res = if path.is_dir() {
        svc.allowlist.admit_dir(path, cwd).map(|(p, w)| (p, w, true))
    } else {
        svc.allowlist.admit_file(path, cwd).and_then(|(p, w)| {
            if p.is_file() {
                Ok((p, w, false))
            } else {
                Err(format!("search root is not a regular file: {}", label))
            }
        })
    };
    match res {
        Ok(entry) => {
            admitted.push(entry);
            Ok(true)
        }
        Err(e) if e.starts_with("REFUSED") => Err(SearchError::Failed(e)),
        Err(e) => {
            if first_err.is_none() {
                *first_err = Some(e);
            }
            Ok(false)
        }
    }
}

fn resolve_shorthand_root(
    svc: &BrokerService,
    cleaned: &str,
    cwd: Option<&Path>,
    admitted: &mut Vec<(PathBuf, PathBuf, bool)>,
    first_err: &mut Option<String>,
) -> Result<bool, SearchError> {
    let base = cwd.map(Path::to_path_buf).unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });
    let Ok((_, ws_root)) = svc.allowlist.admit_dir(&base, Some(&base)) else {
        return Ok(false);
    };

    if let Some(domain_paths) = policy().resolve_domain_root(cleaned, &ws_root) {
        let mut any = false;
        for raw_p in domain_paths {
            let p = if raw_p.is_absolute() { raw_p } else { ws_root.join(raw_p) };
            if p.exists() && admit_root_candidate(svc, &p, cleaned, cwd, admitted, first_err)? {
                any = true;
            }
        }
        if any {
            return Ok(true);
        }
    }

    let dirs = svc.store.find_workspace_dirs(cleaned, &ws_root, 8);
    if !dirs.is_empty() {
        let mut any = false;
        for dir in dirs {
            any |= admit_root_candidate(svc, &dir, cleaned, cwd, admitted, first_err)?;
        }
        return Ok(any);
    }

    let matches = svc.store.find_workspace_paths(cleaned, &ws_root, 16);
    if !matches.is_empty() {
        let mut any = false;
        for m in matches {
            if let Ok((cf, wr)) = svc.allowlist.admit_file(&m, cwd) {
                admitted.push((cf, wr, false));
                any = true;
            }
        }
        return Ok(any);
    }
    Ok(false)
}

fn collect_search_hits(
    svc: &BrokerService,
    query: &str,
    roots: &[String],
    max_results: usize,
    code_only: bool,
    cwd: Option<&Path>,
    deadline: Instant,
) -> Result<SearchHitSet, SearchError> {
    search_time_left(deadline)?;
    let q = query.trim();
    if q.is_empty() {
        return Err(SearchError::Failed("query must not be empty".to_string()));
    }
    let cap = max_results.clamp(1, 120);

    let mut admitted_roots: Vec<(PathBuf, PathBuf, bool)> = Vec::with_capacity(roots.len().max(1));
    if roots.is_empty() {
        let base = cwd.map(Path::to_path_buf).unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        });
        let (canon_dir, ws_root) = svc
            .allowlist
            .admit_dir(&base, Some(&base))
            .map_err(SearchError::Failed)?;
        admitted_roots.push((canon_dir, ws_root, true));
    } else {
        let mut first_err: Option<String> = None;
        for r in roots {
            search_time_left(deadline)?;
            let cleaned = r.trim().trim_end_matches("/**").trim_end_matches("/*");
            let resolved = resolve_input_path(cleaned, cwd);
            if !resolved.exists()
                && is_safe_shorthand_candidate(cleaned)
                && !is_sensitive_path(&resolved)
                && resolve_shorthand_root(svc, cleaned, cwd, &mut admitted_roots, &mut first_err)?
            {
                continue;
            }
            admit_root_candidate(svc, &resolved, r, cwd, &mut admitted_roots, &mut first_err)?;
        }
        if admitted_roots.is_empty() {
            return Err(SearchError::Failed(
                first_err.unwrap_or_else(|| "no readable search roots found".to_string()),
            ));
        }
    }

    if let Some(needles) = parse_literal_alternation(q) {
        if let Some(hit_set) =
            ram::try_in_ram_simd_search(svc, &needles, &admitted_roots, cap, code_only, deadline)?
        {
            return Ok(hit_set);
        }
    }

    let search_roots: Vec<PathBuf> = admitted_roots.into_iter().map(|(p, _, _)| p).collect();
    let collect_cap = if code_only {
        cap.saturating_mul(4).clamp(cap, 400)
    } else {
        cap.saturating_mul(2).clamp(cap, 200)
    };
    let mut collection = SearchCollection {
        svc, cwd, deadline, cap: collect_cap, hits: Vec::new(), scan_truncated: false,
        incomplete_note: None, match_mode: RgMatchMode::Regex,
    };
    rg::run_rg_or_fallback(q, &search_roots, &mut collection)?;
    let mut grouped: Vec<Vec<SearchHit>> = Vec::new();
    for hit in collection.hits {
        if let Some(g) = grouped.iter_mut().find(|g| g[0].path == hit.path && g[0].workspace == hit.workspace) {
            g.push(hit);
        } else {
            grouped.push(vec![hit]);
        }
    }
    if code_only {
        ram::filter_grouped_hits_code_only(svc, q, collection.match_mode, &mut grouped);
    }
    let mut hit_set = rank_and_select_hits(svc, grouped, cap, collection.scan_truncated);
    hit_set.incomplete_note = collection.incomplete_note;
    Ok(hit_set)
}

pub fn op_search_batch(
    svc: &BrokerService,
    queries: &[Json],
    defaults: SearchOptions,
    cwd: Option<&Path>,
) -> Result<String, SearchError> {
    if !(1..=6).contains(&queries.len()) {
        return Err(SearchError::Failed("queries must contain 1–6 searches".to_string()));
    }
    let deadline = Instant::now() + SEARCH_TIMEOUT;
    let run = |item: &Json| {
        let options = defaults.for_item(item);
        (run_batch_item(svc, item, options.max_results, options.code_only, cwd, deadline), options)
    };
    let results = if queries.len() == 1 {
        vec![run(&queries[0])]
    } else {
        thread::scope(|scope| {
            let run = &run;
            let handles: Vec<_> = queries.iter().map(|item| scope.spawn(move || run(item))).collect();
            handles.into_iter().map(|h| {
                h.join().unwrap_or_else(|_| {
                    (Err(SearchError::Failed("batch search worker panicked".to_string())), defaults)
                })
            }).collect()
        })
    };
    if results.iter().all(|(r, _)| matches!(r, Err(SearchError::Busy))) {
        return Err(SearchError::Busy);
    }
    Ok(render::render(svc, results, true, defaults.max_bytes))
}

fn run_batch_item(
    svc: &BrokerService,
    item: &Json,
    max_results: usize,
    code_only: bool,
    cwd: Option<&Path>,
    deadline: Instant,
) -> Result<SearchHitSet, SearchError> {
    if let Some(spec) = item.as_str().or_else(|| item.get_str("q")) {
        let (query, roots) = parse_shorthand_search_spec(spec, false)?;
        return collect_search_hits(svc, &query, &roots, max_results, code_only, cwd, deadline);
    }
    let query = item.get_str("query").unwrap_or("");
    let roots = item
        .get("roots")
        .and_then(Json::as_arr)
        .and_then(|arr| {
            arr.iter()
                .map(|v| v.as_str().filter(|r| !r.trim().is_empty()).map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .filter(|roots| !roots.is_empty())
        })
        .ok_or_else(|| SearchError::Failed("roots must be a non-empty array of paths".to_string()))?;
    collect_search_hits(svc, query, &roots, max_results, code_only, cwd, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_ws(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ctx-search-{tag}-{}-{}", std::process::id(), crate::store::now_ms_u64()
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn literal_batch_completes_with_all_child_slots_reserved() {
        let workspace = temp_ws("ram-slots");
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
        assert_eq!(result.unwrap().matches("fixture.cpp:1: int simple_needle();").count(), 2);
        assert_eq!(svc.subproc_sem.active_count(), permits.len());
    }

    #[test]
    fn collected_search_reuses_the_callers_deadline() {
        let service = BrokerService::new_ephemeral_inproc(PathBuf::new());
        let expired = Instant::now() - SEARCH_TIMEOUT;
        assert!(matches!(collect_search_hits(&service, "sample", &[], 1, false, None, expired), Err(SearchError::Timeout)));
    }

    #[test]
    fn shorthand_search_resolves_nested_workspace_dir_universally() {
        let workspace = temp_ws("dir-shorthand");
        let nested = workspace.join("deep/pkg/Alpha/Beta");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("Mod.hpp"), "int universal_dir_needle = 42;\n").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
        svc.allowlist.register_hint(&workspace, true).unwrap();
        let options = SearchOptions::from_request(&Json::Null, 10);
        let res = op_search(&svc, "universal_dir_needle", &["Alpha/Beta".into()], options, Some(&workspace)).unwrap();
        fs::remove_dir_all(&workspace).unwrap();
        assert!(res.contains("deep/pkg/Alpha/Beta/Mod.hpp:1: int universal_dir_needle = 42;"));
    }

    #[test]
    fn batch_allows_up_to_six_including_multiple_unscoped_queries() {
        let workspace = temp_ws("batch6");
        fs::create_dir_all(workspace.join("sub")).unwrap();
        fs::write(workspace.join("a.rs"), "// alpha comment\nfn alpha() {}\n").unwrap();
        fs::write(workspace.join("b.rs"), "fn beta() {}\n").unwrap();
        fs::write(workspace.join("sub/c.rs"), "fn gamma() {}\n").unwrap();
        fs::write(workspace.join(".env"), "SECRET_ALPHA=alpha\nSECRET_ONLY=1\n").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
        svc.allowlist.register_hint(&workspace, true).unwrap();
        let options = SearchOptions::from_request(&Json::Null, 5);

        // Mixed unscoped + scoped up to 6
        let six_mixed = [
            Json::Str("alpha".into()), Json::Str("beta".into()), Json::Str("sub:gamma".into()),
            Json::Str("a.rs:alpha".into()), Json::Str("b.rs:beta".into()), Json::Str("sub/c.rs:gamma".into()),
        ];
        let mixed_out = op_search_batch(&svc, &six_mixed, options, Some(&workspace)).unwrap();
        assert!(mixed_out.contains("[1]\n") && mixed_out.contains("[6]\n"), "{mixed_out}");
        assert!(mixed_out.contains("fn alpha() {}") && mixed_out.contains("b.rs:1: fn beta() {}"));
        assert!(mixed_out.contains("sub/c.rs:1: fn gamma() {}") && !mixed_out.contains("SECRET_ALPHA"));

        // Multiple unscoped queries (up to 6) succeed, hide `.env`, and honor per-item options
        let six_unscoped = [
            Json::obj(vec![("q", Json::Str("alpha".into())), ("code_only", Json::Bool(true))]),
            Json::Str("beta".into()),
            Json::Str("gamma".into()),
            Json::Str("SECRET_ONLY".into()),
            Json::Str("missing_needle".into()),
            Json::Str("alpha".into()),
        ];
        let unscoped_out = op_search_batch(&svc, &six_unscoped, options, Some(&workspace)).unwrap();
        assert!(unscoped_out.contains("[1]\n") && unscoped_out.contains("[6]\n"), "{unscoped_out}");
        assert!(unscoped_out.contains("a.rs:2: fn alpha() {}") && unscoped_out.contains("b.rs:1: fn beta() {}"));
        assert!(unscoped_out.contains("sub/c.rs:1: fn gamma() {}"));
        assert!(unscoped_out.contains("[4]\n0 matches\n") && unscoped_out.contains("[5]\n0 matches\n"));
        assert!(unscoped_out.contains("// alpha comment"));
        assert!(!unscoped_out.contains("SECRET_ONLY") && !unscoped_out.contains(".env"));

        // 0 and 7 queries are still rejected with the 1–6 batch cap
        assert!(matches!(
            op_search_batch(&svc, &[], options, Some(&workspace)),
            Err(SearchError::Failed(msg)) if msg.contains("1–6")
        ));
        let seven = vec![Json::Str("alpha".into()); 7];
        assert!(matches!(
            op_search_batch(&svc, &seven, options, Some(&workspace)),
            Err(SearchError::Failed(msg)) if msg.contains("1–6")
        ));
        fs::remove_dir_all(&workspace).unwrap();
    }
}
