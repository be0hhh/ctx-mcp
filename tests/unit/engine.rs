use super::*;

#[test]
fn literal_batch_completes_with_all_child_slots_reserved() {
    let workspace = std::env::temp_dir().join(format!(
        "ctx-search-ram-slots-{}-{}", std::process::id(), crate::store::now_ms_u64(),
    ));
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("fixture.cpp"), "int simple_needle();\n").unwrap();
    let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
    svc.allowlist.register_hint(&workspace, true).unwrap();
    let permits: Vec<_> = (0..crate::protocol::MAX_CONCURRENT_SUBPROCS)
        .map(|_| svc.subproc_sem.acquire(Duration::from_secs(1)).unwrap())
        .collect();
    let term = Json::Str("fixture.cpp:simple_needle".into());
    let options = SearchOptions::from_request(&Json::Null, 1);
    let result = op_search_batch(&svc, &[term.clone(), term], options, Some(&workspace));
    fs::remove_dir_all(&workspace).unwrap();
    assert_eq!(result.unwrap().matches("fixture.cpp:1: int simple_needle();").count(), 2);
    assert_eq!(svc.subproc_sem.active_count(), permits.len());
}
use std::process::ExitStatus;

#[test]
fn collected_search_reuses_the_callers_deadline() {
    let service = BrokerService::new_ephemeral_inproc(PathBuf::new());
    let expired = Instant::now() - SEARCH_TIMEOUT;
    assert!(matches!(
        collect_search_hits(&service, "sample", &[], 1, None, expired),
        Err(SearchError::Timeout)
    ));
}

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
        Some((PathBuf::from("a\nb.rs"), 17, "x".repeat(SEARCH_SNIPPET_CHARS)))
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

#[test]
fn agy_inline_cap_skips_session_dedup_when_truncated_and_records_when_inline() {
    let workspace = std::env::temp_dir().join(format!(
        "ctx-agy-dedup-{}-{}",
        std::process::id(),
        crate::store::now_ms_u64()
    ));
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("small.cpp"), "int small_ok = 1;\n").unwrap();
    let big_body = (1..=320).map(|i| format!("int big_line_{i:03} = {i}; // padding_0123456789_abcdef\n")).collect::<String>();
    fs::write(workspace.join("large.cpp"), &big_body).unwrap();
    let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
    svc.allowlist.register_hint(&workspace, true).unwrap();

    // 1. Oversized AGY read (> AGY_MCP_INLINE_CAP) must NOT poison SessionState with ALREADY IN CONTEXT
    let oversized = op_read_for_host(
        &svc,
        &["small.cpp".into(), "large.cpp".into()],
        16_384,
        false,
        Some("agy-sess-1"),
        Some(&workspace),
        Some(AGY_MCP_INLINE_CAP),
    )
    .unwrap();
    assert!(oversized.len() > AGY_MCP_INLINE_CAP);

    let re_read = op_read_for_host(
        &svc,
        &["small.cpp".into()],
        AGY_MCP_DEFAULT_MAX_BYTES,
        false,
        Some("agy-sess-1"),
        Some(&workspace),
        Some(AGY_MCP_INLINE_CAP),
    )
    .unwrap();
    assert!(re_read.contains("small_ok = 1;"));
    assert!(!re_read.contains("ALREADY IN CONTEXT"));

    // 2. Now that `small.cpp` fit inline (<= AGY_MCP_INLINE_CAP), the next identical read deduplicates cleanly
    let dedup = op_read_for_host(
        &svc,
        &["small.cpp".into()],
        AGY_MCP_DEFAULT_MAX_BYTES,
        false,
        Some("agy-sess-1"),
        Some(&workspace),
        Some(AGY_MCP_INLINE_CAP),
    )
    .unwrap();
    assert!(dedup.contains("ALREADY IN CONTEXT"));

    // 3. Default AGY cap note recommends parallel native read_file
    let capped = op_read_for_host(
        &svc,
        &["large.cpp".into()],
        AGY_MCP_DEFAULT_MAX_BYTES,
        true,
        Some("agy-sess-2"),
        Some(&workspace),
        Some(AGY_MCP_INLINE_CAP),
    )
    .unwrap();
    assert!(capped.len() <= AGY_MCP_INLINE_CAP);
    assert!(capped.contains("read_file"));

    fs::remove_dir_all(&workspace).unwrap();
}
