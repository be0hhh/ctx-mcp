use super::*;

#[test]
fn reader_rechecks_the_file_after_another_loader_finishes() {
    let dir = std::env::temp_dir().join(format!("ctx-cache-wait-{}-{}", std::process::id(), now_ms()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("fixture.cpp");
    fs::write(&path, "int cached;\n").unwrap();
    let store = RamStore::new(dir.join("snapshot"));
    let cached = store.get_full_entry(&path, Some(&dir)).unwrap();
    let key = Arc::clone(&cached.norm_path);
    let slot = Arc::new(InflightSlot { done: Mutex::new(false), cv: Condvar::new() });
    store.inflight.lock().unwrap().insert(Arc::clone(&key), Arc::clone(&slot));
    let owner = InflightGuard { map: &store.inflight, key, slot: Arc::clone(&slot) };
    fs::write(&path, "int edited_once;\n").unwrap();

    std::thread::scope(|scope| {
        let read = scope.spawn(|| store.get_full_entry(&path, Some(&dir)).unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while Arc::strong_count(&slot) < 4 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let joined_load = Arc::strong_count(&slot) >= 4;
        fs::write(&path, "int edited_a_second_time;\n").unwrap();
        drop(owner);
        assert!(joined_load, "reader did not enter the existing load");
        let loaded = read.join().unwrap();
        assert_eq!(loaded.content.as_deref(), Some("int edited_a_second_time;\n"));
        assert_eq!(cached.content.as_deref(), Some("int cached;\n"));
    });
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_changed_file_stamp_refuses_publication() {
    let dir = std::env::temp_dir().join(format!("ctx-cache-stamp-{}-{}", std::process::id(), now_ms()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("fixture.cpp");
    fs::write(&path, "int before;\n").unwrap();
    let store = RamStore::new(dir.join("snapshot"));
    let old_stamp = file_stat(&path).unwrap();
    let key = store.intern_path(&norm_key_from_canon(&path));
    fs::write(&path, "int after_first_write;\n").unwrap();
    assert!(store.load_full_entry(&path, Some(&dir), old_stamp, key, None).unwrap().is_none());
    assert_eq!(store.cached_file_count(), 0);
    assert_eq!(store.get_outline_entry(&path, Some(&dir)).unwrap().content.as_deref(), Some("int after_first_write;\n"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn shorthand_root_resolves_nested_dirs_stem_tokens_and_compact_segments() {
    let dir = std::env::temp_dir().join(format!("ctx-root-resolve-{}-{}", std::process::id(), now_ms()));
    fs::create_dir_all(dir.join("graph/resolver")).unwrap();
    let resolve = dir.join("graph/resolver/resolve_graph.py");
    let scanner = dir.join("graph/resolver/manifest_scanner.py");
    fs::write(&resolve, "def resolve_graph():\n    return scan_manifests()\n").unwrap();
    fs::write(&scanner, "def scan_manifests():\n    return []\n").unwrap();

    let store = RamStore::new(dir.join("snapshot"));
    // Tier 3: nested directory segment `resolver`
    let by_dir = store.find_workspace_paths("resolver", &dir, 16);
    assert_eq!(by_dir.len(), 2);
    // Tier 4a: stem token `manifest`
    let by_token = store.find_workspace_paths("manifest", &dir, 16);
    assert_eq!(by_token.len(), 1);
    assert!(by_token[0].ends_with("manifest_scanner.py"));
    // Tier 4b: compact consecutive directory segments `graphresolver`
    let by_compact = store.find_workspace_paths("graphresolver", &dir, 16);
    assert_eq!(by_compact.len(), 2);
    // Generic stem still refused on fallback
    assert!(store.find_workspace_paths("main", &dir, 16).is_empty());

    fs::remove_dir_all(dir).unwrap();
}
