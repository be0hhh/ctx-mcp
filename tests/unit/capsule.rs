use super::*;

fn ctx(host: &'static str, session: &str, agent: Option<&str>, root: &str) -> HostContext {
    HostContext {
        host, session: session.into(), agent: agent.map(str::to_owned),
        workspace: PathBuf::from(root), codex_origin: None,
    }
}

#[test]
fn same_role_fanout_waits_for_its_exact_receipt() {
    let registry = CapsuleRegistry { capacity: 512, state: Mutex::default() };
    let parent = ctx("codex", "parent", None, "/test/project");
    let mut launches = Vec::new();
    for i in 0..200 {
        let call = format!("call-{i}");
        let brief = format!("Researcher launch {i}");
        let assignment = registry.prepare(&parent, WorkspaceMode::Inherit, &brief, Some(&call), 0).unwrap();
        launches.push((call, brief, key_in_assignment(&assignment).unwrap().to_owned()));
    }
    let early = ctx("codex", "parent", Some("child-0"), "/test/project");
    assert_eq!(registry.claim(&early, &launches[0].2), Err(ClaimError::Pending));
    std::thread::scope(|scope| {
        for (i, (call, brief, key)) in launches.iter().enumerate().rev() {
            let registry = &registry;
            let parent = &parent;
            scope.spawn(move || {
                let agent = format!("child-{i}");
                registry.bind_receipt(parent, call, Recipient::Agent(agent.clone()));
                let sibling = ctx("codex", "parent", Some("sibling-with-forked-history"), "/test/project");
                assert_eq!(registry.claim(&sibling, key), Err(ClaimError::Unavailable));
                let child = ctx("codex", "parent", Some(&agent), "/test/project");
                assert_eq!(registry.claim(&child, key).as_deref(), Ok(brief.as_str()));
                assert_eq!(registry.claim(&child, key), Err(ClaimError::Unavailable));
            });
        }
    });
    assert_eq!(registry.status().get_i64("issued"), Some(200));
    assert_eq!(registry.status().get_i64("pending"), Some(0));
}

#[test]
fn capacity_preserves_queued_launches_and_expiry_is_observable() {
    let registry = CapsuleRegistry { capacity: 500, state: Mutex::default() };
    let parent = ctx("agy", "parent", Some("parent"), "/test/project");
    for i in 0..500 {
        registry.prepare(&parent, WorkspaceMode::Inherit, "same role", Some("batch"), i).unwrap();
    }
    assert!(registry.prepare(&parent, WorkspaceMode::Inherit, "overflow", Some("extra"), 0).is_err());
    let status = registry.status();
    assert_eq!(status.get_i64("pending"), Some(500));
    assert_eq!(status.get_i64("full"), Some(1));
    assert_eq!(status.get_i64("peak"), Some(500));
    for value in registry.state.lock().unwrap().entries.values_mut() {
        value.expires = Instant::now();
    }
    assert_eq!(registry.status().get_i64("expired"), Some(500));
}

#[test]
fn codex_path_receipt_requires_its_native_parent_and_workspace() {
    let registry = CapsuleRegistry { capacity: 512, state: Mutex::default() };
    for depth in 1..=5 {
        let base = format!("nested-{}", depth - 1);
        let id = format!("nested-{depth}");
        let path = format!("/root{}", "/task".repeat(depth));
        let parent = ctx("codex", "session", Some(&base), "/test/project");
        let assignment = registry.prepare(&parent, WorkspaceMode::Inherit, "nested brief", Some("one"), 0).unwrap();
        let key = key_in_assignment(&assignment).unwrap();
        registry.bind_receipt(&parent, "one", Recipient::CodexPath(path.clone()));
        let mut other = ctx("codex", "session", Some(&id), "/test/independent");
        other.codex_origin = Some((base.clone(), path.clone()));
        assert_eq!(registry.claim(&other, key), Err(ClaimError::Unavailable));
        other.workspace = parent.workspace.clone();
        other.codex_origin = Some(("unrelated-parent".into(), path.clone()));
        assert_eq!(registry.claim(&other, key), Err(ClaimError::Unavailable));
        other.codex_origin = Some((base, path));
        assert_eq!(registry.claim(&other, key).as_deref(), Ok("nested brief"));
    }
}

#[test]
fn branch_requires_the_worktree_backlink() {
    let root = std::env::temp_dir().join(format!("ctx-worktree-{}", generate_csprng_token().unwrap()));
    let repository = root.join("repository");
    let child = root.join("child");
    let other = root.join("other");
    let admin = repository.join(".git/worktrees/child");
    fs::create_dir_all(&admin).unwrap();
    fs::create_dir_all(&child).unwrap();
    fs::create_dir_all(&other).unwrap();
    for worktree in [&child, &other] {
        fs::write(worktree.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
    }
    fs::write(admin.join("commondir"), "../..\n").unwrap();
    fs::write(admin.join("gitdir"), child.join(".git").to_string_lossy().as_bytes()).unwrap();
    assert!(linked_worktree(&repository, &child).is_some());
    assert!(linked_worktree(&repository, &other).is_none());
    fs::remove_dir_all(root).unwrap();
}
