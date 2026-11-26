//! Workspace memo persistence (`v3` schema with backward-compatible `v1`/`v2` migration)
//! and the shared Capsule registry.

pub mod capsule;
pub mod change_feed;
pub mod pack;
pub mod secret;

pub use capsule::{
    key_in_assignment, CapsuleRegistry, ClaimError, HostContext, Recipient, WorkspaceMode,
};
pub use pack::PackStore;
pub use secret::contains_known_secret;

use crate::base::json::{self, Json, JsonKey};
use crate::base::security::{admit_file_in_workspace, is_sensitive_path, write_private_0600};
use crate::base::simd::{fast_hash64, FastHashMap};
use crate::store::{now_ms, RamStore};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

const MAX_MEMO_WORKSPACES: usize = 64;
const MAX_MEMOS_PER_WORKSPACE: usize = 256;
const MAX_MEMO_SUMMARY_BYTES: usize = 4096;
const MAX_MEMO_TOPIC_BYTES: usize = 128;
const MAX_MEMO_AUTHOR_BYTES: usize = 256;
const MEMO_AUTHOR_UNKNOWN: &str = "unknown";
const UNLINKED_MEMO_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct MemoFileLink {
    pub abs_path: PathBuf,
    pub rel_path: String,
    pub hash64_at_put: Option<u64>,
}

#[derive(Clone, Copy)]
enum MemoKind {
    Finding,
    Observation,
}

impl MemoKind {
    fn infer(has_links: bool) -> Self {
        if has_links {
            Self::Finding
        } else {
            Self::Observation
        }
    }

    fn parse(kind: &str) -> Option<Self> {
        match kind {
            "finding" => Some(Self::Finding),
            "observation" => Some(Self::Observation),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Observation => "observation",
        }
    }
}

struct MemoEntry {
    topic: String,
    summary: String,
    kind: MemoKind,
    author: String,
    updated_ms: u64,
    linked_files: Vec<MemoFileLink>,
}

type MemoMap = FastHashMap<String, Vec<Arc<MemoEntry>>>;

struct MemoBoard {
    entries: MemoMap,
    snapshot_hash: Result<Option<u64>, String>,
}

impl MemoBoard {
    fn load(path: Option<&Path>) -> Self {
        match path.map(load_memos_from_disk).transpose() {
            Ok(Some(board)) => board,
            Ok(None) => Self {
                entries: MemoMap::default(),
                snapshot_hash: Ok(None),
            },
            Err(error) => Self {
                entries: MemoMap::default(),
                snapshot_hash: Err(error),
            },
        }
    }
}

pub struct ContextBroker {
    pub capsules: CapsuleRegistry,
    pub changes: change_feed::ChangeFeed,
    pub packs: PackStore,
    memos: RwLock<MemoBoard>,
    memo_path: Option<PathBuf>,
}

impl Default for ContextBroker {
    fn default() -> Self {
        Self::new(None)
    }
}

impl ContextBroker {
    pub fn new(memo_path: Option<PathBuf>) -> Self {
        let loaded = MemoBoard::load(memo_path.as_deref());
        Self {
            capsules: CapsuleRegistry::default(),
            changes: change_feed::ChangeFeed::new(),
            packs: PackStore::default(),
            memos: RwLock::new(loaded),
            memo_path,
        }
    }

    pub fn clear_all(&self) -> Result<(), String> {
        let mut board = self
            .memos
            .write()
            .map_err(|_| "memo board lock poisoned".to_string())?;
        self.commit_memos(&mut board, MemoMap::default())?;
        self.capsules.clear();
        self.changes.clear_all();
        self.packs.clear_all();
        Ok(())
    }

    pub fn memo_count(&self) -> usize {
        let now = now_ms();
        self.memos
            .read()
            .map(|g| {
                g.entries
                    .values()
                    .flatten()
                    .filter(|m| m.is_visible(now))
                    .count()
            })
            .unwrap_or(0)
    }

    // --- Shared Workspace MemoBoard (`ctx_memo`) ---

    fn commit_memos(&self, board: &mut MemoBoard, next: MemoMap) -> Result<(), String> {
        if let Some(path) = &self.memo_path {
            let expected_hash = board.snapshot_hash.as_ref().map_err(Clone::clone)?;
            let observed = read_memo_snapshot(path)?;
            if observed.as_ref().map(|bytes| fast_hash64(bytes)) != *expected_hash {
                return Err("memo snapshot changed since load; refusing to overwrite it".to_string());
            }
            let encoded = encode_memos(&next);
            write_private_0600(path, encoded.as_bytes())?;
            board.snapshot_hash = Ok(Some(fast_hash64(encoded.as_bytes())));
        }
        board.entries = next;
        Ok(())
    }

    pub fn put_memo(
        &self,
        workspace_norm: &str,
        topic: &str,
        summary: &str,
        kind: Option<&str>,
        trusted_author: Option<&str>,
        linked_files: Vec<MemoFileLink>,
    ) -> Result<String, String> {
        let topic = topic.trim();
        if topic.is_empty()
            || topic.len() > MAX_MEMO_TOPIC_BYTES
            || topic.chars().any(char::is_control)
        {
            return Err(format!(
                "memo topic must be a single line of 1–{MAX_MEMO_TOPIC_BYTES} bytes"
            ));
        }
        let summary = summary.trim();
        if summary.is_empty() || summary.len() > MAX_MEMO_SUMMARY_BYTES {
            return Err(format!(
                "memo summary must be 1–{MAX_MEMO_SUMMARY_BYTES} bytes"
            ));
        }
        if contains_known_secret(topic) || contains_known_secret(summary) {
            return Err("REFUSED: memo contains known secret material".to_string());
        }
        let linked_count = linked_files.len();
        let kind = match kind {
            Some(kind) => MemoKind::parse(kind.trim())
                .ok_or_else(|| "memo kind must be finding or observation".to_string())?,
            None => MemoKind::infer(linked_count != 0),
        };
        if matches!(kind, MemoKind::Finding) && linked_count == 0 {
            return Err("memo finding requires at least one linked source file".to_string());
        }
        let now = now_ms();
        let entry = Arc::new(MemoEntry {
            topic: topic.to_string(),
            summary: summary.to_string(),
            kind,
            author: trusted_author
                .and_then(valid_memo_author)
                .unwrap_or(MEMO_AUTHOR_UNKNOWN)
                .to_string(),
            updated_ms: now,
            linked_files,
        });

        let mut board = self
            .memos
            .write()
            .map_err(|_| "memo board lock poisoned".to_string())?;
        let mut next = board.entries.clone();
        if !next.contains_key(workspace_norm) && next.len() >= MAX_MEMO_WORKSPACES {
            if let Some(oldest_ws) = next
                .iter()
                .min_by_key(|(_, list)| list.iter().map(|m| m.updated_ms).max().unwrap_or(0))
                .map(|(k, _)| k.clone())
            {
                next.remove(&oldest_ws);
            }
        }
        let list = next.entry(workspace_norm.to_string()).or_default();
        list.retain(|m| m.is_visible(now) && m.topic != topic);
        if list.len() >= MAX_MEMOS_PER_WORKSPACE {
            list.remove(0);
        }
        list.push(entry);
        self.commit_memos(&mut board, next)?;
        Ok(format!("Saved memo with {linked_count} linked file(s)."))
    }

    pub fn clear_memos(&self, workspace_norm: &str, topic: Option<&str>) -> Result<String, String> {
        let mut board = self
            .memos
            .write()
            .map_err(|_| "memo board lock poisoned".to_string())?;
        let mut next = board.entries.clone();
        let removed = if let Some(topic) = topic {
            next.get_mut(workspace_norm).map_or(0, |list| {
                let before = list.len();
                list.retain(|m| m.topic != topic);
                before - list.len()
            })
        } else {
            next.remove(workspace_norm).map_or(0, |list| list.len())
        };
        self.commit_memos(&mut board, next)?;
        Ok(format!("Cleared {removed} memo(s)."))
    }

    fn memo_entries(&self, workspace_norm: &str) -> Result<Vec<Arc<MemoEntry>>, String> {
        let board = self
            .memos
            .read()
            .map_err(|_| "memo board lock poisoned".to_string())?;
        board.snapshot_hash.as_ref().map_err(Clone::clone)?;
        let now = now_ms();
        let mut entries = board
            .entries
            .get(workspace_norm)
            .into_iter()
            .flatten()
            .filter(|m| m.is_visible(now))
            .cloned()
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| b.updated_ms.cmp(&a.updated_ms));
        Ok(entries)
    }

    pub fn list_memos(
        &self,
        workspace_norm: &str,
        ws_root: &Path,
        topic_filter: &str,
        store: &RamStore,
    ) -> Result<Vec<Json>, String> {
        let filter = topic_filter.trim().to_ascii_lowercase();
        Ok(self
            .memo_entries(workspace_norm)?
            .iter()
            .filter(|m| m.topic.to_ascii_lowercase().contains(&filter))
            .map(|m| Json::obj(m.metadata(Some(ws_root), store)))
            .collect())
    }

    pub fn get_memo(
        &self,
        workspace_norm: &str,
        ws_root: &Path,
        topic: &str,
        store: &RamStore,
    ) -> Result<Json, String> {
        let topic = topic.trim();
        if topic.is_empty() {
            return Err("memo get requires an exact topic".to_string());
        }
        let entry = self
            .memo_entries(workspace_norm)?
            .into_iter()
            .find(|m| m.topic == topic)
            .ok_or_else(|| "memo topic not found".to_string())?;
        if contains_known_secret(&entry.summary) {
            return Err("REFUSED: memo contains known secret material".to_string());
        }
        let mut fields = entry.metadata(Some(ws_root), store);
        fields.push(("summary", Json::Str(entry.summary.clone())));
        fields.push(("untrusted", Json::Bool(true)));
        Ok(Json::obj(fields))
    }

    pub fn startup_memo_digest(
        &self,
        workspace_norm: &str,
        ws_root: Option<&Path>,
        brief_text: &str,
        candidate_files: &[PathBuf],
        store: &RamStore,
        max_bytes: usize,
    ) -> String {
        let Ok(entries) = self.memo_entries(workspace_norm) else {
            return String::new();
        };
        let brief_low = brief_text.to_ascii_lowercase();
        let total = entries.len();
        let mut out = String::new();
        for m in entries {
            let topic_match = brief_low.contains(&m.topic.to_ascii_lowercase());
            let file_match = m
                .linked_files
                .iter()
                .any(|link| candidate_files.contains(&link.abs_path));
            if total > 3 && !topic_match && !file_match {
                continue;
            }
            let line = Json::obj(m.metadata(ws_root, store)).to_json_string();
            if out.len() + line.len() + 3 <= max_bytes {
                out.push_str("- ");
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }
}

impl MemoEntry {
    fn is_visible(&self, now: u64) -> bool {
        (!self.linked_files.is_empty()
            || now.saturating_sub(self.updated_ms) < UNLINKED_MEMO_TTL_MS)
            && !contains_known_secret(&self.topic)
    }

    fn metadata(&self, ws_root: Option<&Path>, store: &RamStore) -> Vec<(&'static str, Json)> {
        let mut any_stale = false;
        let links = self
            .linked_files
            .iter()
            .map(|link| {
                let (label, stale) = link.status(ws_root, store);
                any_stale |= stale;
                Json::obj(vec![
                    ("path", Json::Str(label)),
                    ("stale", Json::Bool(stale)),
                ])
            })
            .collect();
        let status = if self.linked_files.is_empty() {
            "unlinked"
        } else if any_stale {
            "stale"
        } else {
            "fresh"
        };
        vec![
            ("topic", Json::Str(self.topic.clone())),
            ("kind", Json::Str(self.kind.as_str().to_string())),
            ("author", Json::Str(self.author.clone())),
            ("updated_ms", Json::Str(self.updated_ms.to_string())),
            ("status", Json::Str(status.to_string())),
            ("linked_files", Json::Arr(links)),
        ]
    }
}

impl MemoFileLink {
    fn status(&self, ws_root: Option<&Path>, store: &RamStore) -> (String, bool) {
        let Some(root) = ws_root else {
            return ("[unavailable]".to_string(), true);
        };
        let Ok(rel) = self.abs_path.strip_prefix(root) else {
            return ("[unavailable]".to_string(), true);
        };
        let Some(label) = rel.to_str().filter(|s| !contains_known_secret(s)) else {
            return ("[unavailable]".to_string(), true);
        };
        if rel.as_os_str().is_empty()
            || !rel
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
            || is_sensitive_path(&self.abs_path)
        {
            return ("[unavailable]".to_string(), true);
        }
        let hash = admit_file_in_workspace(&self.abs_path, root)
            .ok()
            .filter(|canon| canon == &self.abs_path)
            .and_then(|canon| store.current_file_hash64(&canon, Some(root)));
        let stale = self.hash64_at_put.is_none() || hash != self.hash64_at_put;
        (label.to_string(), stale)
    }
}

fn valid_memo_author(author: &str) -> Option<&str> {
    let author = author.trim();
    (!author.is_empty()
        && author.len() <= MAX_MEMO_AUTHOR_BYTES
        && !author.chars().any(char::is_control)
        && !contains_known_secret(author))
    .then_some(author)
}

fn encode_memos(map: &MemoMap) -> String {
    let workspaces: Vec<(JsonKey, Json)> = map
        .iter()
        .map(|(ws_key, entries)| {
            let rows = entries
                .iter()
                .map(|m| {
                    let links = m
                        .linked_files
                        .iter()
                        .map(|l| {
                            let hash_val = match l.hash64_at_put {
                                Some(h) => Json::Str(format!("{:016x}", h)),
                                None => Json::Null,
                            };
                            Json::obj(vec![
                                (
                                    "abs_path",
                                    Json::Str(l.abs_path.to_string_lossy().into_owned()),
                                ),
                                ("rel_path", Json::Str(l.rel_path.clone())),
                                ("hash64", hash_val),
                            ])
                        })
                        .collect();
                    Json::obj(vec![
                        ("topic", Json::Str(m.topic.clone())),
                        ("summary", Json::Str(m.summary.clone())),
                        ("kind", Json::Str(m.kind.as_str().to_string())),
                        ("author", Json::Str(m.author.clone())),
                        ("updated_ms", Json::Str(m.updated_ms.to_string())),
                        ("linked_files", Json::Arr(links)),
                    ])
                })
                .collect();
            (JsonKey::Owned(ws_key.clone()), Json::Arr(rows))
        })
        .collect();
    Json::obj(vec![
        ("version", Json::Int(3)),
        ("workspaces", Json::Obj(workspaces)),
    ])
    .to_json_string()
}

fn read_memo_snapshot(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read memo snapshot metadata: {e}")),
        Ok(meta) if !meta.is_file() => {
            return Err("memo snapshot is not a regular file".to_string())
        }
        Ok(_) => {}
    }
    fs::read(path)
        .map(Some)
        .map_err(|e| format!("read memo snapshot: {e}"))
}

fn load_memos_from_disk(path: &Path) -> Result<MemoBoard, String> {
    let Some(raw) = read_memo_snapshot(path)? else {
        return Ok(MemoBoard {
            entries: MemoMap::default(),
            snapshot_hash: Ok(None),
        });
    };
    let entries = std::str::from_utf8(&raw)
        .ok()
        .and_then(|text| json::parse(text).ok())
        .and_then(|doc| decode_memos(&doc))
        .ok_or_else(|| "invalid memo snapshot; refusing to overwrite it".to_string())?;
    Ok(MemoBoard {
        entries,
        snapshot_hash: Ok(Some(fast_hash64(&raw))),
    })
}

fn decode_memos(doc: &Json) -> Option<MemoMap> {
    let version = doc.get_i64("version")?;
    if !matches!(version, 1 | 2 | 3) {
        return None;
    }
    let mut result = MemoMap::default();
    for (ws_key, val) in doc.get("workspaces")?.as_obj()? {
        let rows = val.as_arr()?;
        if rows.len() > MAX_MEMOS_PER_WORKSPACE || ws_key.is_empty() {
            return None;
        }
        let entries = rows
            .iter()
            .map(|row| decode_memo_entry(row, version).map(Arc::new))
            .collect::<Option<Vec<_>>>()?;
        if result.insert(ws_key.as_ref().to_owned(), entries).is_some() {
            return None;
        }
    }
    Some(result)
}

fn decode_memo_entry(row: &Json, version: i64) -> Option<MemoEntry> {
    let topic = row.get_str("topic").filter(|s| !s.is_empty())?.to_string();
    let summary = row
        .get_str("summary")
        .filter(|s| !s.is_empty())?
        .to_string();
    let author = row.get_str("author")?;
    let updated_ms = row.get_str("updated_ms")?.parse().ok()?;
    let linked_files = row
        .get("linked_files")?
        .as_arr()?
        .iter()
        .map(|link| {
            let abs_path = PathBuf::from(link.get_str("abs_path")?);
            if !abs_path.is_absolute() {
                return None;
            }
            let rel_path = link.get_str("rel_path")?.to_string();
            let hash64_at_put = if version == 3 {
                match link.get("hash64")? {
                    Json::Null => None,
                    Json::Str(hex)
                        if hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()) =>
                    {
                        Some(u64::from_str_radix(hex, 16).ok()?)
                    }
                    _ => return None,
                }
            } else {
                // Legacy v1/v2 snapshots stored FNV-1a hashes; validate format and mark stale.
                let legacy_hex = link.get_str("fnv64")?;
                let _ = u64::from_str_radix(legacy_hex, 16).ok()?;
                None
            };
            Some(MemoFileLink {
                abs_path,
                rel_path,
                hash64_at_put,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let has_v2_fields = version >= 2;
    let kind = if has_v2_fields {
        MemoKind::parse(row.get_str("kind")?)?
    } else {
        MemoKind::infer(!linked_files.is_empty())
    };
    if matches!(kind, MemoKind::Finding) && linked_files.is_empty() {
        return None;
    }
    Some(MemoEntry {
        topic,
        summary,
        kind,
        author: has_v2_fields
            .then(|| valid_memo_author(author))
            .flatten()
            .unwrap_or(MEMO_AUTHOR_UNKNOWN)
            .to_string(),
        updated_ms,
        linked_files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestStateDir(PathBuf);

    impl TestStateDir {
        fn new() -> Self {
            let suffix = crate::base::security::generate_csprng_token().unwrap();
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
        broker
            .put_memo("workspace", "memo", "original", None, None, vec![])
            .unwrap();

        let corrupt = b"{\"version\":3,\"workspaces\":";
        fs::write(&path, corrupt).unwrap();
        assert!(broker
            .put_memo("workspace", "memo", "replacement", None, None, vec![])
            .is_err());
        assert!(broker.clear_memos("workspace", Some("memo")).is_err());
        assert!(broker.clear_all().is_err());
        assert_eq!(
            broker.memo_entries("workspace").unwrap()[0].summary,
            "original"
        );

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
        assert!(broker
            .put_memo("workspace", "memo", "body", Some("finding"), None, vec![])
            .is_err());
        assert_eq!(broker.memo_count(), 0);
    }

    #[test]
    fn v2_memos_migrate_to_v3_and_reload_cleanly() {
        let temp = TestStateDir::new();
        let root = fs::canonicalize(&temp.0).unwrap();
        let file = root.join("sample.rs");
        fs::write(&file, "pub fn answer() -> u32 { 42 }\n").unwrap();

        let memo_path = root.join("memos.json");
        let v2_doc = Json::obj(vec![
            ("version", Json::Int(2)),
            (
                "workspaces",
                Json::Obj(vec![(
                    JsonKey::Borrowed("ws"),
                    Json::Arr(vec![Json::obj(vec![
                        ("topic", Json::Str("legacy-finding".into())),
                        ("summary", Json::Str("from v2 snapshot".into())),
                        ("kind", Json::Str("finding".into())),
                        ("author", Json::Str("worker-legacy".into())),
                        ("updated_ms", Json::Str(now_ms().to_string())),
                        (
                            "linked_files",
                            Json::Arr(vec![Json::obj(vec![
                                ("abs_path", Json::Str(file.to_string_lossy().into_owned())),
                                ("rel_path", Json::Str("sample.rs".into())),
                                ("fnv64", Json::Str("0123456789abcdef".into())),
                            ])]),
                        ),
                    ])]),
                )]),
            ),
        ]);
        fs::write(&memo_path, v2_doc.to_json_string()).unwrap();

        let store = RamStore::new(root.join("snapshot.bin"));
        let broker = ContextBroker::new(Some(memo_path.clone()));
        let listed = broker.list_memos("ws", &root, "", &store).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].get_str("topic"), Some("legacy-finding"));
        assert_eq!(listed[0].get_str("author"), Some("worker-legacy"));
        assert_eq!(listed[0].get_str("status"), Some("stale"));

        let current_hash = store.current_file_hash64(&file, Some(&root));
        assert!(current_hash.is_some());
        broker
            .put_memo(
                "ws",
                "v3-finding",
                "fresh finding",
                Some("finding"),
                Some("worker-v3"),
                vec![MemoFileLink {
                    abs_path: file.clone(),
                    rel_path: "sample.rs".into(),
                    hash64_at_put: current_hash,
                }],
            )
            .unwrap();

        let persisted = json::parse(&fs::read_to_string(&memo_path).unwrap()).unwrap();
        assert_eq!(persisted.get_i64("version"), Some(3));

        let restarted = ContextBroker::new(Some(memo_path));
        let reloaded = restarted.list_memos("ws", &root, "", &store).unwrap();
        assert_eq!(reloaded.len(), 2);
        let legacy = reloaded
            .iter()
            .find(|m| m.get_str("topic") == Some("legacy-finding"))
            .unwrap();
        let fresh = reloaded
            .iter()
            .find(|m| m.get_str("topic") == Some("v3-finding"))
            .unwrap();
        assert_eq!(legacy.get_str("status"), Some("stale"));
        assert_eq!(fresh.get_str("status"), Some("fresh"));
    }
}
