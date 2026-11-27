use super::{
    parse_literal_alternation, search_snippet, search_time_left, RgMatchMode, SearchCollection,
    SearchError, SearchHit,
};
use crate::base::platform::{hidden_command, probe_tool_available, resolve_tool};
use crate::base::simd::search_lines_literals;
use crate::engine::is_searchable_source_file;
use crate::store::should_skip_dir;
use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, BufReader, ErrorKind, Read};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::mpsc::{self, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

const RG_RECORD_LIMIT: usize = 16 * 1024;
const RG_DIAGNOSTIC_LIMIT: usize = 4 * 1024;
const RG_MAX_COUNT_PER_FILE: usize = 25;
const FALLBACK_SEARCH_FILE_LIMIT: usize = 8_000;
const FALLBACK_INCOMPLETE_NOTE: &str =
    "rg/git unavailable; fallback walker stopped at 8,000 files";

#[cfg_attr(test, derive(Debug))]
enum RgError {
    Busy,
    Missing,
    Timeout,
    RegexSyntax(String),
    Process(String),
}

struct SearchProcess(Child);

impl Drop for SearchProcess {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn run_rg_once(
    query: &str,
    roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
    fixed_strings: bool,
) -> Result<(), RgError> {
    search_time_left(collection.deadline).map_err(|_| RgError::Timeout)?;
    let mut cmd = crate::base::platform::hidden_command(crate::base::platform::resolve_tool("rg"));
    cmd.args([
        "--no-config", "--threads=1", "--with-filename", "--null", "--line-number",
        "--no-heading", "--color=never", "--line-buffered", "--smart-case", "--max-count=25",
        "--glob=!**/.git/**", "--glob=!**/build*/**", "--glob=!**/node_modules/**", "--glob=!**/target/**",
    ]);
    if fixed_strings {
        cmd.arg("--fixed-strings");
    }
    cmd.arg("--").arg(query).args(roots);
    let _permit = collection
        .svc
        .subproc_sem
        .acquire_until(collection.deadline)
        .map_err(RgError::Process)?
        .ok_or(RgError::Busy)?;
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                RgError::Missing
            } else {
                RgError::Process(format!("cannot run rg: {}", e))
            }
        })?;
    collect_rg_output(SearchProcess(child), collection, fixed_strings, None, false)
}

enum RgOutput {
    Record(Vec<u8>),
    StdoutDone(io::Result<()>),
    StderrDone(io::Result<Vec<u8>>),
}

fn collect_rg_output(
    mut process: SearchProcess,
    collection: &mut SearchCollection<'_>,
    fixed_strings: bool,
    base_dir: Option<&Path>,
    git_mode: bool,
) -> Result<(), RgError> {
    let stdout = process
        .0
        .stdout
        .take()
        .ok_or_else(|| RgError::Process("missing piped rg stdout".to_string()))?;
    let stderr = process
        .0
        .stderr
        .take()
        .ok_or_else(|| RgError::Process("missing piped rg stderr".to_string()))?;
    let deadline = collection.deadline;
    let (tx, rx) = mpsc::sync_channel(8);
    let stdout_tx = tx.clone();
    // Returning drops the receiver and reaps rg, closing both pipe writers.
    let _stdout_reader = thread::Builder::new()
        .spawn(move || {
            let result = stream_rg_records(BufReader::new(stdout), deadline, &stdout_tx);
            let _ = stdout_tx.send(RgOutput::StdoutDone(result));
        })
        .map_err(|error| RgError::Process(format!("cannot start rg stdout reader: {error}")))?;
    let _stderr_reader = thread::Builder::new()
        .spawn(move || {
            let _ = tx.send(RgOutput::StderrDone(drain_rg_stderr(stderr, deadline)));
        })
        .map_err(|error| RgError::Process(format!("cannot start rg stderr reader: {error}")))?;

    let mut stdout_done = false;
    let mut diagnostic = None;
    let mut last_path: Option<PathBuf> = None;
    let mut file_hit_count = 0usize;
    while !stdout_done || diagnostic.is_none() {
        let remaining = search_time_left(deadline).map_err(|_| RgError::Timeout)?;
        let output = rx.recv_timeout(remaining).map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => RgError::Timeout,
            mpsc::RecvTimeoutError::Disconnected => {
                RgError::Process("rg readers ended early".to_string())
            }
        })?;
        match output {
            RgOutput::Record(record) => {
                let Some((raw_path, line, snippet)) = parse_grep_line(&record) else {
                    continue;
                };
                let candidate = match base_dir {
                    Some(base) if raw_path.is_relative() => base.join(&raw_path),
                    _ => raw_path,
                };
                let Ok((path, workspace)) =
                    collection.svc.allowlist.admit_file(&candidate, collection.cwd)
                else {
                    continue;
                };
                search_time_left(deadline).map_err(|_| RgError::Timeout)?;
                if last_path.as_ref() == Some(&path) {
                    file_hit_count += 1;
                } else {
                    last_path = Some(path.clone());
                    file_hit_count = 1;
                }
                if file_hit_count > RG_MAX_COUNT_PER_FILE {
                    collection.scan_truncated = true;
                    continue;
                }
                if file_hit_count == RG_MAX_COUNT_PER_FILE {
                    collection.scan_truncated = true;
                }
                collection.hits.push(SearchHit {
                    path,
                    workspace,
                    line,
                    snippet,
                });
                if collection.hits.len() >= collection.cap {
                    collection.scan_truncated = true;
                    return Ok(());
                }
            }
            RgOutput::StdoutDone(result) => {
                result.map_err(|error| rg_pipe_error("stdout", error))?;
                stdout_done = true;
            }
            RgOutput::StderrDone(result) => {
                diagnostic = Some(result.map_err(|error| rg_pipe_error("stderr", error))?);
            }
        }
    }

    // EOF can precede process exit. Keep the same deadline while checking status.
    let status = loop {
        let remaining = search_time_left(deadline).map_err(|_| RgError::Timeout)?;
        match process.0.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(remaining.min(Duration::from_millis(5))),
            Err(error) => return Err(RgError::Process(format!("cannot wait for rg: {error}"))),
        }
    };
    let diag = diagnostic.unwrap_or_default();
    if git_mode {
        check_git_grep_status(status, &diag, fixed_strings)
    } else {
        check_rg_status(status, &diag, fixed_strings)
    }
}

fn rg_pipe_error(stream: &str, error: io::Error) -> RgError {
    if error.kind() == ErrorKind::TimedOut {
        RgError::Timeout
    } else {
        RgError::Process(format!("cannot read rg {stream}: {error}"))
    }
}

fn stream_rg_records(
    mut input: impl BufRead,
    deadline: Instant,
    tx: &SyncSender<RgOutput>,
) -> io::Result<()> {
    while let Some(record) = read_rg_record(&mut input, deadline)? {
        if tx.send(RgOutput::Record(record)).is_err() {
            break;
        }
    }
    Ok(())
}

fn read_rg_record(input: &mut impl BufRead, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
    let mut record = Vec::new();
    let mut in_path = true;
    loop {
        search_time_left(deadline).map_err(|_| ErrorKind::TimedOut)?;
        let bytes = input.fill_buf()?;
        if bytes.is_empty() {
            return Ok((!record.is_empty()).then_some(record));
        }
        let delimiter = if in_path { 0 } else { b'\n' };
        let end = bytes.iter().position(|&byte| byte == delimiter);
        let consumed = end.map_or(bytes.len(), |index| index + 1);
        let stored = consumed.min(RG_RECORD_LIMIT - record.len());
        record.extend_from_slice(&bytes[..stored]);
        input.consume(consumed);
        if end.is_some() {
            if !in_path {
                return Ok(Some(record));
            }
            in_path = false;
        }
    }
}

fn drain_rg_stderr(mut input: impl Read, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut prefix = Vec::new();
    let mut buf = [0; RG_DIAGNOSTIC_LIMIT];
    loop {
        search_time_left(deadline).map_err(|_| ErrorKind::TimedOut)?;
        let n = input.read(&mut buf)?;
        if n == 0 {
            return Ok(prefix);
        }
        let stored = n.min(RG_DIAGNOSTIC_LIMIT - prefix.len());
        prefix.extend_from_slice(&buf[..stored]);
    }
}

fn check_rg_status(status: ExitStatus, stderr: &[u8], fixed_strings: bool) -> Result<(), RgError> {
    if matches!(status.code(), Some(0 | 1)) {
        return Ok(());
    }
    let diagnostic = String::from_utf8_lossy(stderr);
    let diagnostic = diagnostic.trim();
    if !fixed_strings
        && matches!(status.code(), Some(2))
        && (diagnostic.starts_with("regex parse error:")
            || diagnostic.starts_with("rg: regex parse error:"))
    {
        return Err(RgError::RegexSyntax(diagnostic.to_string()));
    }
    let diagnostic: String = diagnostic.chars().take(1_000).collect();
    Err(RgError::Process(if diagnostic.is_empty() {
        format!("rg failed ({})", status)
    } else {
        format!("rg failed ({}): {}", status, diagnostic)
    }))
}

fn check_git_grep_status(
    status: ExitStatus,
    stderr: &[u8],
    fixed_strings: bool,
) -> Result<(), RgError> {
    if matches!(status.code(), Some(0 | 1)) {
        return Ok(());
    }
    let diag = String::from_utf8_lossy(stderr);
    let low = diag.to_ascii_lowercase();
    if !fixed_strings
        && (low.contains("regex")
            || low.contains("invalid")
            || low.contains("unmatched")
            || low.contains("parenthes")
            || low.contains("bracket")
            || low.contains("repetition"))
    {
        return Err(RgError::RegexSyntax(diag.trim().to_string()));
    }
    Err(RgError::Missing)
}

fn find_git_worktree_root(path: &Path) -> Option<PathBuf> {
    let start = if path.is_file() { path.parent()? } else { path };
    let mut cur = Some(start);
    while let Some(dir) = cur {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

fn resolve_git_grep_scope(roots: &[PathBuf]) -> Option<(PathBuf, Vec<PathBuf>)> {
    if roots.is_empty() || probe_tool_available("git").is_none() {
        return None;
    }
    let git_root = find_git_worktree_root(&roots[0])?;
    let mut rel_roots: Vec<PathBuf> = Vec::with_capacity(roots.len());
    let mut whole_tree = false;
    for r in roots {
        let rel = r.strip_prefix(&git_root).ok()?;
        if rel.as_os_str().is_empty() {
            whole_tree = true;
        } else {
            rel_roots.push(rel.to_path_buf());
        }
    }
    if whole_tree {
        rel_roots.clear();
    }
    Some((git_root, rel_roots))
}

fn run_git_grep_once(
    query: &str,
    git_root: &Path,
    rel_roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
    fixed_strings: bool,
) -> Result<(), RgError> {
    search_time_left(collection.deadline).map_err(|_| RgError::Timeout)?;
    let mut cmd = hidden_command(resolve_tool("git"));
    cmd.arg("-C").arg(git_root).args([
        "-c",
        "core.quotePath=false",
        "--no-pager",
        "grep",
        "-n",
        "-I",
        "-z",
        "--untracked",
    ]);
    if !query.chars().any(char::is_uppercase) {
        cmd.arg("-i");
    }
    cmd.arg(if fixed_strings { "-F" } else { "-E" });
    cmd.arg("-e").arg(query);
    if !rel_roots.is_empty() {
        cmd.arg("--").args(rel_roots);
    }
    let _permit = collection
        .svc
        .subproc_sem
        .acquire_until(collection.deadline)
        .map_err(RgError::Process)?
        .ok_or(RgError::Busy)?;
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                RgError::Missing
            } else {
                RgError::Process(format!("cannot run git grep: {}", e))
            }
        })?;
    collect_rg_output(SearchProcess(child), collection, fixed_strings, Some(git_root), true)
}

fn run_git_grep(
    query: &str,
    roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
) -> Result<(), RgError> {
    let (git_root, rel_roots) = resolve_git_grep_scope(roots).ok_or(RgError::Missing)?;
    let has_regex_meta = query.chars().any(|c| {
        matches!(
            c,
            '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\'
        )
    });
    match run_git_grep_once(query, &git_root, &rel_roots, collection, false) {
        Ok(()) if collection.hits.is_empty() && has_regex_meta => {
            collection.match_mode = RgMatchMode::FixedSmartCase;
            run_git_grep_once(query, &git_root, &rel_roots, collection, true)
        }
        Err(RgError::RegexSyntax(_)) => {
            collection.hits.clear();
            collection.scan_truncated = false;
            collection.match_mode = RgMatchMode::FixedSmartCase;
            run_git_grep_once(query, &git_root, &rel_roots, collection, true)
        }
        other => other,
    }
}

pub(super) fn run_rg_or_fallback(
    query: &str,
    roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
) -> Result<(), SearchError> {
    let has_regex_meta = query.chars().any(|c| {
        matches!(
            c,
            '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\'
        )
    });
    let result = match run_rg_once(query, roots, collection, false) {
        Ok(()) if collection.hits.is_empty() && has_regex_meta => {
            collection.match_mode = RgMatchMode::FixedSmartCase;
            run_rg_once(query, roots, collection, true)
        }
        Err(RgError::RegexSyntax(_)) => {
            collection.hits.clear();
            collection.scan_truncated = false;
            collection.match_mode = RgMatchMode::FixedSmartCase;
            run_rg_once(query, roots, collection, true)
        }
        result => result,
    };
    match result {
        Ok(()) => Ok(()),
        Err(RgError::Missing) => match run_git_grep(query, roots, collection) {
            Ok(()) => Ok(()),
            Err(RgError::Missing) => search_without_rg(query, roots, collection),
            Err(RgError::Busy) => Err(SearchError::Busy),
            Err(RgError::Timeout) => Err(SearchError::Timeout),
            Err(RgError::Process(error) | RgError::RegexSyntax(error)) => {
                Err(SearchError::Failed(error))
            }
        },
        Err(RgError::Busy) => Err(SearchError::Busy),
        Err(RgError::Timeout) => Err(SearchError::Timeout),
        Err(RgError::Process(error) | RgError::RegexSyntax(error)) => {
            Err(SearchError::Failed(error))
        }
    }
}

fn visit_fallback_files(
    roots: &[PathBuf],
    deadline: Instant,
    mut visit: impl FnMut(&Path) -> Result<bool, SearchError>,
) -> Result<bool, SearchError> {
    let mut files_left = FALLBACK_SEARCH_FILE_LIMIT;
    let mut queue: VecDeque<(PathBuf, bool)> = roots.iter().cloned().map(|p| (p, true)).collect();
    while let Some((path, explicit)) = queue.pop_front() {
        search_time_left(deadline)?;
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            if !explicit && (should_skip_dir(name) || path.join(".git").exists()) {
                continue;
            }
            if let Ok(entries) = fs::read_dir(&path) {
                let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
                children.sort();
                for child in children {
                    queue.push_back((child, false));
                }
            }
        } else if is_searchable_source_file(&path, &meta) {
            files_left -= 1;
            let stopped = visit(&path)?;
            if stopped || files_left == 0 {
                search_time_left(deadline)?;
                return Ok(files_left == 0 && !stopped);
            }
        }
    }
    Ok(false)
}

fn search_without_rg(
    query: &str,
    roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
) -> Result<(), SearchError> {
    collection.match_mode = RgMatchMode::FixedCi;
    let deadline = collection.deadline;
    let needles = parse_literal_alternation(query).unwrap_or_else(|| vec![query]);
    let hit_file_limit = visit_fallback_files(roots, deadline, |path| {
        let Ok((path, workspace)) = collection.svc.allowlist.admit_file(path, collection.cwd)
        else {
            return Ok(false);
        };
        let Ok(entry) = collection.svc.store.get_full_entry(&path, Some(&workspace)) else {
            return Ok(false);
        };
        let Some(text) = entry.content() else {
            return Ok(false);
        };
        let remaining = collection.cap.saturating_sub(collection.hits.len());
        if remaining == 0 {
            collection.scan_truncated = true;
            return Ok(true);
        }
        let line_nums = search_lines_literals(text, entry.line_offsets(), &needles, false, remaining);
        for ln in line_nums {
            collection.hits.push(SearchHit {
                path: path.clone(),
                workspace: workspace.clone(),
                line: ln as usize,
                snippet: search_snippet(entry.line_slice(ln)),
            });
            if collection.hits.len() >= collection.cap {
                collection.scan_truncated = true;
                return Ok(true);
            }
        }
        Ok(false)
    })?;
    if hit_file_limit {
        collection.scan_truncated = true;
        collection.incomplete_note = Some(FALLBACK_INCOMPLETE_NOTE);
    }
    Ok(())
}

fn parse_grep_line(record: &[u8]) -> Option<(PathBuf, usize, String)> {
    let mut fields = record.splitn(2, |&byte| byte == 0);
    let path = fields.next()?;
    let rest = fields.next()?;
    // `rg --null --line-number` emits `path\0line:text`; `git grep -n -z` emits `path\0line\0text`.
    let sep = rest.iter().position(|&byte| byte == b':' || byte == 0)?;
    let number = std::str::from_utf8(&rest[..sep]).ok()?.parse().ok()?;
    let text = &rest[sep + 1..];
    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(path))
    };
    #[cfg(not(unix))]
    let path = PathBuf::from(std::str::from_utf8(path).ok()?);
    Some((path, number, search_snippet(&String::from_utf8_lossy(text))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::search::{SEARCH_SNIPPET_CHARS, SEARCH_TIMEOUT};
    use crate::rpc::BrokerService;

    fn exited(code: u8) -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(i32::from(code) << 8)
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(u32::from(code))
        }
    }

    fn new_collection<'a>(
        svc: &'a BrokerService,
        cwd: Option<&'a Path>,
        deadline: Instant,
        cap: usize,
    ) -> SearchCollection<'a> {
        SearchCollection {
            svc, cwd, deadline, cap, hits: Vec::new(), scan_truncated: false,
            incomplete_note: None, match_mode: RgMatchMode::Regex,
        }
    }

    #[test]
    fn rg_distinguishes_no_matches_regex_syntax_and_process_errors() {
        assert!(check_rg_status(exited(1), b"rg: No files were searched", false).is_ok());
        let syntax_error = b"regex parse error:\nerror: unclosed character class";
        assert!(matches!(check_rg_status(exited(2), syntax_error, false), Err(RgError::RegexSyntax(_))));
        assert!(matches!(check_rg_status(exited(2), syntax_error, true), Err(RgError::Process(_))));
        assert!(matches!(
            check_rg_status(exited(2), b"rg: Permission denied", false),
            Err(RgError::Process(message)) if message.contains("Permission denied")
        ));
    }

    #[test]
    fn rg_match_has_an_unambiguous_path_separator() {
        let hit = parse_grep_line(b"a:b.rs\x0017:example: value").unwrap();
        assert_eq!(hit, (PathBuf::from("a:b.rs"), 17, "example: value".to_string()));
        let git_hit = parse_grep_line(b"a:b.rs\x0017\x00example: value").unwrap();
        assert_eq!(git_hit, (PathBuf::from("a:b.rs"), 17, "example: value".to_string()));
    }

    #[test]
    fn rg_oversized_record_and_stderr_are_drained_with_bounded_prefixes() {
        let mut data = b"a\nb.rs\017:".to_vec();
        data.extend(std::iter::repeat(b'x').take(RG_RECORD_LIMIT * 2));
        data.extend_from_slice(b"\nnext.rs\018:next match\n");
        let mut reader = BufReader::with_capacity(7, io::Cursor::new(&data));
        let deadline = Instant::now() + SEARCH_TIMEOUT;
        let first = read_rg_record(&mut reader, deadline).unwrap().unwrap();
        assert_eq!(first.len(), RG_RECORD_LIMIT);
        assert_eq!(parse_grep_line(&first), Some((PathBuf::from("a\nb.rs"), 17, "x".repeat(SEARCH_SNIPPET_CHARS))));
        let second = read_rg_record(&mut reader, deadline).unwrap().unwrap();
        assert_eq!(parse_grep_line(&second), Some((PathBuf::from("next.rs"), 18, "next match".to_string())));
        assert!(read_rg_record(&mut reader, deadline).unwrap().is_none());

        let mut stderr = io::Cursor::new(&data);
        let diagnostic = drain_rg_stderr(&mut stderr, deadline).unwrap();
        assert_eq!(diagnostic, data[..RG_DIAGNOSTIC_LIMIT]);
        assert_eq!(stderr.position(), data.len() as u64);
    }

    #[test]
    fn fallback_uses_one_file_budget_for_directory_and_explicit_roots() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-search-files-{}-{}", std::process::id(), crate::store::now_ms_u64()
        ));
        fs::create_dir(&dir).unwrap();
        let in_directory = dir.join("first.txt");
        fs::write(&in_directory, "needle\n").unwrap();
        let mut roots = vec![dir.clone()];
        roots.extend(std::iter::repeat(in_directory.clone()).take(FALLBACK_SEARCH_FILE_LIMIT));

        let deadline = Instant::now() + SEARCH_TIMEOUT;
        let mut count = 0;
        let limited = visit_fallback_files(&roots, deadline, |path| {
            assert_eq!(path, in_directory.as_path());
            count += 1;
            Ok(false)
        })
        .unwrap();
        assert!(limited);

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        let workspace = svc.allowlist.register_hint(&dir, true).unwrap();
        let mut collection = new_collection(&svc, Some(&dir), deadline, 1);
        search_without_rg("NEEDLE", &roots, &mut collection).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(count, FALLBACK_SEARCH_FILE_LIMIT);
        assert!(collection.scan_truncated);
        let [hit] = collection.hits.as_slice() else { panic!("expected one fallback match"); };
        assert_eq!(hit.path, workspace.join("first.txt"));
        assert_eq!(hit.line, 1);
        assert_eq!(hit.snippet, "needle");
    }

    #[test]
    fn expired_fallback_deadline_stops_before_visiting_files() {
        let result = visit_fallback_files(&[PathBuf::from(".")], Instant::now(), |_| {
            panic!("expired search visited a file");
        });
        assert!(matches!(result, Err(SearchError::Timeout)));
    }

    #[cfg(unix)]
    #[test]
    fn rg_cap_counts_admitted_matches_and_stops_before_eof() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-search-rg-{}-{}", std::process::id(), crate::store::now_ms_u64()
        ));
        fs::create_dir(&dir).unwrap();
        let (sensitive, source) = (dir.join(".env"), dir.join("match.rs"));
        fs::write(&sensitive, "needle").unwrap();
        fs::write(&source, "needle").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        let workspace = svc.allowlist.register_hint(&dir, true).unwrap();
        let child = Command::new("sh")
            .args(["-c", r#"printf '%s\000%d:needle\n' "$1" 1 "$2" 1; exec sleep 30"#, "rg-test"])
            .arg(&sensitive)
            .arg(&source)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut collection = new_collection(&svc, Some(&dir), Instant::now() + SEARCH_TIMEOUT, 1);
        let result = collect_rg_output(SearchProcess(child), &mut collection, false, None, false);
        fs::remove_dir_all(&dir).unwrap();
        assert!(result.is_ok());
        assert!(collection.scan_truncated);
        let [hit] = collection.hits.as_slice() else { panic!("expected one admitted rg match"); };
        assert_eq!(hit.path, workspace.join("match.rs"));
    }

    #[cfg(unix)]
    #[test]
    fn rg_timeout_applies_with_silent_open_pipes() {
        let svc = BrokerService::new_ephemeral_inproc(PathBuf::from("unused"));
        let child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut collection = new_collection(&svc, None, Instant::now() + Duration::from_millis(25), 1);
        assert!(matches!(
            collect_rg_output(SearchProcess(child), &mut collection, false, None, false),
            Err(RgError::Timeout)
        ));
    }

    #[test]
    fn git_grep_and_bfs_fallback_skip_nested_git_and_ignored_files() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-search-gitgrep-{}-{}", std::process::id(), crate::store::now_ms_u64()
        ));
        fs::create_dir_all(dir.join("ccxt-rs/.git")).unwrap();
        fs::create_dir_all(dir.join("ignored_vendor")).unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join(".gitignore"), "ignored_vendor/\n").unwrap();
        fs::write(dir.join("ccxt-rs/junk.rs"), "struct OwnedCycleLedger;\n").unwrap();
        fs::write(dir.join("ignored_vendor/ign.rs"), "struct OwnedCycleLedger;\n").unwrap();
        fs::write(dir.join("src/ledger.rs"), "pub struct OwnedCycleLedger { id: u64 }\n").unwrap();

        // 1. BFS walker skips nested `.git` repo (`ccxt-rs/`) and supports `a|b` alternation.
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap"));
        let ws = svc.allowlist.register_hint(&dir, true).unwrap();
        let mut col = new_collection(&svc, Some(&dir), Instant::now() + SEARCH_TIMEOUT, 20);
        search_without_rg("OwnedCycleLedger|other_probe", &[ws.clone()], &mut col).unwrap();
        assert!(col.hits.iter().any(|h| h.path == ws.join("src/ledger.rs")));
        assert!(col.hits.iter().all(|h| !h.path.starts_with(ws.join("ccxt-rs"))));

        // 2. `git grep` fallback respects `.gitignore`, skips nested `.git`, and searches untracked files.
        let git_ok = hidden_command(resolve_tool("git"))
            .arg("-C").arg(&dir).args(["init", "-q"]).status().is_ok_and(|s| s.success());
        if git_ok {
            let _ = hidden_command(resolve_tool("git"))
                .arg("-C").arg(dir.join("ccxt-rs")).args(["init", "-q"]).status();
            let mut gcol = new_collection(&svc, Some(&dir), Instant::now() + SEARCH_TIMEOUT, 20);
            run_git_grep("OwnedCycleLedger", &[ws.clone()], &mut gcol).unwrap();
            assert_eq!(gcol.hits.len(), 1, "expected only src/ledger.rs, got {:?}", gcol.hits.len());
            assert_eq!(gcol.hits[0].path, ws.join("src/ledger.rs"));
            assert!(!gcol.scan_truncated);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
