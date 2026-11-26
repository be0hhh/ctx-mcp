use super::{search_snippet, search_time_left, SearchCollection, SearchError, SearchHit};
use crate::base::simd::search_lines_literals;
use crate::engine::is_searchable_source_file;
use crate::store::should_skip_dir;
use std::fs;
use std::io::{self, BufRead, BufReader, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

const RG_RECORD_LIMIT: usize = 16 * 1024;
const RG_DIAGNOSTIC_LIMIT: usize = 4 * 1024;
const FALLBACK_SEARCH_FILE_LIMIT: usize = 3_000;

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

fn resolve_rg_binary() -> &'static Path {
    static RG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    RG_PATH
        .get_or_init(|| {
            let exe = if cfg!(windows) { "rg.exe" } else { "rg" };
            if let Some(path_var) = std::env::var_os("PATH") {
                for dir in std::env::split_paths(&path_var) {
                    let cand = dir.join(exe);
                    if cand.is_file() {
                        return cand;
                    }
                }
            }
            // Desktop GUI apps (macOS / Linux / Windows) often spawn MCP & hook processes
            // with a minimal system PATH omitting Homebrew, Cargo, WinGet, or ~/.local/bin.
            let mut extra_dirs: Vec<PathBuf> = Vec::new();
            #[cfg(unix)]
            {
                for sys_dir in [
                    "/opt/homebrew/bin",
                    "/usr/local/bin",
                    "/home/linuxbrew/.linuxbrew/bin",
                    "/usr/bin",
                    "/bin",
                ] {
                    extra_dirs.push(PathBuf::from(sys_dir));
                }
            }
            if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
                if !home.trim().is_empty() {
                    let h = PathBuf::from(home);
                    extra_dirs.push(h.join(".cargo").join("bin"));
                    extra_dirs.push(h.join(".local").join("bin"));
                    #[cfg(windows)]
                    {
                        extra_dirs.push(h.join("scoop").join("shims"));
                    }
                }
            }
            #[cfg(windows)]
            {
                if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
                    if !local_app.trim().is_empty() {
                        let la = PathBuf::from(local_app);
                        extra_dirs.push(la.join("Microsoft").join("WinGet").join("Links"));
                        extra_dirs.push(la.join("Programs").join("ripgrep"));
                    }
                }
                if let Ok(pf) = std::env::var("ProgramFiles") {
                    if !pf.trim().is_empty() {
                        extra_dirs.push(PathBuf::from(pf).join("ripgrep"));
                    }
                }
            }
            for dir in extra_dirs {
                let cand = dir.join(exe);
                if cand.is_file() {
                    return cand;
                }
            }
            PathBuf::from(exe)
        })
        .as_path()
}

fn run_rg_once(
    query: &str,
    roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
    fixed_strings: bool,
) -> Result<(), RgError> {
    search_time_left(collection.deadline).map_err(|_| RgError::Timeout)?;
    let mut cmd = Command::new(resolve_rg_binary());
    cmd.arg("--no-config")
        .arg("--threads=1")
        .arg("--with-filename")
        .arg("--null")
        .arg("--line-number")
        .arg("--no-heading")
        .arg("--color=never")
        .arg("--line-buffered")
        .arg("--smart-case")
        .arg("--max-count=25")
        .arg("--glob=!**/.git/**")
        .arg("--glob=!**/build*/**")
        .arg("--glob=!**/node_modules/**")
        .arg("--glob=!**/target/**");
    if fixed_strings {
        cmd.arg("--fixed-strings");
    }
    cmd.arg("--").arg(query);
    for r in roots {
        cmd.arg(r);
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
        .map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                RgError::Missing
            } else {
                RgError::Process(format!("cannot run rg: {}", error))
            }
        })?;
    collect_rg_output(SearchProcess(child), collection, fixed_strings)
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
) -> Result<(), RgError> {
    let stdout = process.0.stdout.take().expect("piped rg stdout");
    let stderr = process.0.stderr.take().expect("piped rg stderr");
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
                let Some((path, line, snippet)) = parse_grep_line(&record) else {
                    continue;
                };
                let Ok((path, workspace)) =
                    collection.svc.allowlist.admit_file(&path, collection.cwd)
                else {
                    continue;
                };
                search_time_left(deadline).map_err(|_| RgError::Timeout)?;
                collection.hits.push(SearchHit {
                    path,
                    workspace,
                    line,
                    snippet,
                });
                if collection.hits.len() == collection.cap {
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
    check_rg_status(status, &diagnostic.unwrap_or_default(), fixed_strings)
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
            run_rg_once(query, roots, collection, true)
        }
        Err(RgError::RegexSyntax(_)) => {
            collection.hits.clear();
            run_rg_once(query, roots, collection, true)
        }
        result => result,
    };
    match result {
        Ok(()) => Ok(()),
        Err(RgError::Missing) => search_without_rg(query, roots, collection),
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
) -> Result<(), SearchError> {
    let mut files_left = FALLBACK_SEARCH_FILE_LIMIT;
    let mut roots = roots.iter().cloned();
    let mut dirs: Vec<fs::ReadDir> = Vec::new();
    loop {
        search_time_left(deadline)?;
        let (path, explicit) = match dirs.last_mut() {
            Some(dir) => match dir.next() {
                Some(Ok(entry)) => (entry.path(), false),
                Some(Err(_)) => continue,
                None => {
                    dirs.pop();
                    continue;
                }
            },
            None => match roots.next() {
                Some(path) => (path, true),
                None => return Ok(()),
            },
        };
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            if explicit || !should_skip_dir(name) {
                if let Ok(entries) = fs::read_dir(&path) {
                    dirs.push(entries);
                }
            }
        } else if is_searchable_source_file(&path, &meta) {
            files_left -= 1;
            if visit(&path)? || files_left == 0 {
                return search_time_left(deadline).map(|_| ());
            }
        }
    }
}

fn search_without_rg(
    query: &str,
    roots: &[PathBuf],
    collection: &mut SearchCollection<'_>,
) -> Result<(), SearchError> {
    let deadline = collection.deadline;
    visit_fallback_files(roots, deadline, |path| {
        let Ok((path, workspace)) = collection.svc.allowlist.admit_file(path, collection.cwd)
        else {
            return Ok(false);
        };
        let Ok(entry) = collection.svc.store.get_full_entry(&path, Some(&workspace)) else {
            return Ok(false);
        };
        let Some(text) = entry.content.as_deref() else {
            return Ok(false);
        };
        let remaining = collection.cap.saturating_sub(collection.hits.len());
        if remaining == 0 {
            return Ok(true);
        }
        let line_nums = search_lines_literals(text, &entry.line_offsets, &[query], false, remaining);
        for ln in line_nums {
            collection.hits.push(SearchHit {
                path: path.clone(),
                workspace: workspace.clone(),
                line: ln as usize,
                snippet: search_snippet(entry.line_slice(ln)),
            });
            if collection.hits.len() == collection.cap {
                return Ok(true);
            }
        }
        Ok(false)
    })
}

fn parse_grep_line(record: &[u8]) -> Option<(PathBuf, usize, String)> {
    let mut fields = record.splitn(2, |&byte| byte == 0);
    let path = fields.next()?;
    let mut fields = fields.next()?.splitn(2, |&byte| byte == b':');
    let number = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
    let text = fields.next()?;
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

    #[test]
    fn rg_distinguishes_no_matches_regex_syntax_and_process_errors() {
        assert!(check_rg_status(exited(1), b"rg: No files were searched", false).is_ok());
        let syntax_error = b"regex parse error:\nerror: unclosed character class";
        assert!(matches!(
            check_rg_status(exited(2), syntax_error, false),
            Err(RgError::RegexSyntax(_))
        ));
        assert!(matches!(
            check_rg_status(exited(2), syntax_error, true),
            Err(RgError::Process(_))
        ));
        assert!(matches!(
            check_rg_status(exited(2), b"rg: Permission denied", false),
            Err(RgError::Process(message)) if message.contains("Permission denied")
        ));
    }

    #[test]
    fn rg_match_has_an_unambiguous_path_separator() {
        let hit = parse_grep_line(b"a:b.rs\x0017:example: value").unwrap();
        assert_eq!(
            hit,
            (PathBuf::from("a:b.rs"), 17, "example: value".to_string())
        );
    }

    #[test]
    fn rg_oversized_record_and_stderr_are_drained_with_bounded_prefixes() {
        let mut data = b"a\nb.rs\0".to_vec();
        data.extend_from_slice(b"17:");
        data.extend(std::iter::repeat(b'x').take(RG_RECORD_LIMIT * 2));
        data.extend_from_slice(b"\nnext.rs\0");
        data.extend_from_slice(b"18:next match\n");
        let mut reader = BufReader::with_capacity(7, io::Cursor::new(&data));
        let deadline = Instant::now() + SEARCH_TIMEOUT;
        let first = read_rg_record(&mut reader, deadline).unwrap().unwrap();
        assert_eq!(first.len(), RG_RECORD_LIMIT);
        assert_eq!(
            parse_grep_line(&first),
            Some((
                PathBuf::from("a\nb.rs"),
                17,
                "x".repeat(SEARCH_SNIPPET_CHARS)
            ))
        );
        let second = read_rg_record(&mut reader, deadline).unwrap().unwrap();
        assert_eq!(
            parse_grep_line(&second),
            Some((PathBuf::from("next.rs"), 18, "next match".to_string()))
        );
        assert!(read_rg_record(&mut reader, deadline).unwrap().is_none());

        let mut stderr = io::Cursor::new(&data);
        let diagnostic = drain_rg_stderr(&mut stderr, deadline).unwrap();
        assert_eq!(diagnostic, data[..RG_DIAGNOSTIC_LIMIT]);
        assert_eq!(stderr.position(), data.len() as u64);
    }

    #[test]
    fn fallback_uses_one_file_budget_for_directory_and_explicit_roots() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-search-files-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&dir).unwrap();
        let in_directory = dir.join("first.txt");
        fs::write(&in_directory, "needle\n").unwrap();
        let mut roots = vec![dir.clone()];
        roots.extend(std::iter::repeat(in_directory.clone()).take(FALLBACK_SEARCH_FILE_LIMIT));

        let deadline = Instant::now() + SEARCH_TIMEOUT;
        let mut count = 0;
        visit_fallback_files(&roots, deadline, |path| {
            assert_eq!(path, in_directory.as_path());
            count += 1;
            Ok(false)
        })
        .unwrap();

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        let workspace = svc.allowlist.register_hint(&dir, true).unwrap();
        let mut collection = SearchCollection {
            svc: &svc,
            cwd: Some(&dir),
            deadline,
            cap: 1,
            hits: Vec::new(),
        };
        search_without_rg("NEEDLE", &roots, &mut collection).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(count, FALLBACK_SEARCH_FILE_LIMIT);
        let [hit] = collection.hits.as_slice() else {
            panic!("expected one fallback match");
        };
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
            "ctx-search-rg-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&dir).unwrap();
        let sensitive = dir.join(".env");
        let source = dir.join("match.rs");
        fs::write(&sensitive, "needle").unwrap();
        fs::write(&source, "needle").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        let workspace = svc.allowlist.register_hint(&dir, true).unwrap();
        let child = Command::new("sh")
            .args([
                "-c",
                r#"printf '%s\000%d:needle\n' "$1" 1 "$2" 1; exec sleep 30"#,
                "rg-test",
            ])
            .arg(&sensitive)
            .arg(&source)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut collection = SearchCollection {
            svc: &svc,
            cwd: Some(&dir),
            deadline: Instant::now() + SEARCH_TIMEOUT,
            cap: 1,
            hits: Vec::new(),
        };
        let result = collect_rg_output(SearchProcess(child), &mut collection, false);
        fs::remove_dir_all(&dir).unwrap();
        assert!(result.is_ok());
        let [hit] = collection.hits.as_slice() else {
            panic!("expected one admitted rg match");
        };
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
        let mut collection = SearchCollection {
            svc: &svc,
            cwd: None,
            deadline: Instant::now() + Duration::from_millis(25),
            cap: 1,
            hits: Vec::new(),
        };
        assert!(matches!(
            collect_rg_output(SearchProcess(child), &mut collection, false),
            Err(RgError::Timeout)
        ));
    }
}
