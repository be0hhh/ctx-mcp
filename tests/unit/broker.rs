use super::*;

struct TestStateDir(PathBuf);

impl TestStateDir {
    fn new() -> Self {
        let suffix = crate::security::generate_csprng_token().unwrap();
        let path = std::env::temp_dir().join(format!("ctx-memo-test-{suffix}"));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestStateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn changed_snapshot_refuses_put_and_clear_without_mutating_memory() {
    let temp = TestStateDir::new();
    let path = temp.0.join("memos.json");
    let broker = ContextBroker::new(Some(path.clone()));
    broker.put_memo("workspace", "memo", "original", None, None, vec![]).unwrap();

    let corrupt = b"{\"version\":2,\"workspaces\":";
    fs::write(&path, corrupt).unwrap();
    assert!(broker.put_memo("workspace", "memo", "replacement", None, None, vec![]).is_err());
    assert!(broker.clear_memos("workspace", Some("memo")).is_err());
    assert!(broker.clear_all().is_err());
    assert_eq!(broker.memo_entries("workspace").unwrap()[0].summary, "original");

    let restarted = ContextBroker::new(Some(path.clone()));
    assert!(restarted.clear_all().is_err());
    assert_eq!(fs::read(path).unwrap(), corrupt);
}

#[test]
fn legacy_snapshot_author_is_unverified_and_unlinked_memos_expire() {
    let raw = r#"{
        "version":1,"workspaces":{"workspace":[{
            "topic":"memo","summary":"body","author":"claimed-author",
            "updated_ms":"100","linked_files":[]
        }]}
    }"#;
    let entries = decode_memos(&json::parse(raw).unwrap()).unwrap();
    let entry = &entries["workspace"][0];
    assert_eq!(entry.author, "unknown");
    assert_eq!(entry.summary, "body");
    assert_eq!(entry.kind.as_str(), "observation");
    assert!(entry.is_visible(100 + UNLINKED_MEMO_TTL_MS - 1));
    assert!(!entry.is_visible(100 + UNLINKED_MEMO_TTL_MS));
}

#[test]
fn finding_requires_a_link() {
    let broker = ContextBroker::default();
    assert!(broker.put_memo("workspace", "memo", "body", Some("finding"), None, vec![]).is_err());
    assert_eq!(broker.memo_count(), 0);
}
