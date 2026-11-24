// Workspace memo persistence and the shared Capsule registry.

use crate::capsule::CapsuleRegistry;
use crate::json::{self, Json};
use crate::security::{admit_file_in_workspace, is_sensitive_path, write_private_0600};
use crate::store::{fnv1a_64, now_ms, RamStore};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

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
    pub fnv64_at_put: u64,
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

type MemoMap = HashMap<String, Vec<Arc<MemoEntry>>>;

struct MemoBoard {
    entries: MemoMap,
    snapshot_hash: Result<Option<u64>, String>,
}

impl MemoBoard {
    fn load(path: Option<&Path>) -> Self {
        match path.map(load_memos_from_disk).transpose() {
            Ok(Some(board)) => board,
            Ok(None) => Self {
                entries: MemoMap::new(),
                snapshot_hash: Ok(None),
            },
            Err(error) => Self {
                entries: MemoMap::new(),
                snapshot_hash: Err(error),
            },
        }
    }
}

pub struct ContextBroker {
    pub capsules: CapsuleRegistry,
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
            memos: RwLock::new(loaded),
            memo_path,
        }
    }

    pub fn clear_all(&self) -> Result<(), String> {
        let mut board = self
            .memos
            .write()
            .map_err(|_| "memo board lock poisoned".to_string())?;
        self.commit_memos(&mut board, MemoMap::new())?;
        self.capsules.clear();
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
            if observed.as_ref().map(|bytes| fnv1a_64(bytes)) != *expected_hash {
                return Err("memo snapshot changed since load; refusing to overwrite it".to_string());
            }
            let encoded = encode_memos(&next);
            write_private_0600(path, encoded.as_bytes())?;
            board.snapshot_hash = Ok(Some(fnv1a_64(encoded.as_bytes())));
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
        if topic.is_empty() || topic.len() > MAX_MEMO_TOPIC_BYTES || topic.chars().any(char::is_control) {
            return Err(format!("memo topic must be a single line of 1–{MAX_MEMO_TOPIC_BYTES} bytes"));
        }
        let summary = summary.trim();
        if summary.is_empty() || summary.len() > MAX_MEMO_SUMMARY_BYTES {
            return Err(format!("memo summary must be 1–{MAX_MEMO_SUMMARY_BYTES} bytes"));
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
            let file_match = m.linked_files.iter().any(|link| candidate_files.contains(&link.abs_path));
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
        (!self.linked_files.is_empty() || now.saturating_sub(self.updated_ms) < UNLINKED_MEMO_TTL_MS)
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
            || !rel.components().all(|part| matches!(part, std::path::Component::Normal(_)))
            || is_sensitive_path(&self.abs_path)
        {
            return ("[unavailable]".to_string(), true);
        }
        let hash = admit_file_in_workspace(&self.abs_path, root)
            .ok()
            .filter(|canon| canon == &self.abs_path)
            .and_then(|canon| store.current_file_fnv64(&canon, Some(root)));
        (label.to_string(), hash != Some(self.fnv64_at_put))
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

pub(crate) fn contains_known_secret(text: &str) -> bool {
    if text.lines().any(|line| {
        let line = line.trim();
        line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----")
    }) {
        return true;
    }
    const PREFIXES: &[(&str, usize)] = &[
        ("github_pat_", 20),
        ("ghp_", 20),
        ("gho_", 20),
        ("ghu_", 20),
        ("ghs_", 20),
        ("ghr_", 20),
        ("sk-live-", 16),
        ("sk_live_", 16),
        ("sk-proj-", 16),
        ("sk-", 20),
        ("xoxb-", 16),
        ("xoxp-", 16),
        ("xapp-", 16),
        ("glpat-", 16),
    ];
    let tokens = text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')));
    let has_prefixed_secret = tokens.clone().any(|token| {
        PREFIXES.iter().any(|(prefix, min_suffix)| {
            token.strip_prefix(*prefix).is_some_and(|suffix| suffix.len() >= *min_suffix)
        }) || ((token.starts_with("AKIA") || token.starts_with("ASIA"))
            && token.len() == 20
            && token.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()))
    });
    has_prefixed_secret || tokens
        .filter(|token| !token.is_empty())
        .scan(false, |after_bearer, token| {
            let found = *after_bearer && token.len() >= 24;
            *after_bearer = token.eq_ignore_ascii_case("bearer");
            Some(found)
        })
        .any(|found| found)
}

fn encode_memos(map: &MemoMap) -> String {
    let workspaces = map
        .iter()
        .map(|(ws_key, entries)| {
            let rows = entries
                .iter()
                .map(|m| {
                    let links = m
                        .linked_files
                        .iter()
                        .map(|l| Json::obj(vec![
                            ("abs_path", Json::Str(l.abs_path.to_string_lossy().into_owned())),
                            ("rel_path", Json::Str(l.rel_path.clone())),
                            ("fnv64", Json::Str(format!("{:016x}", l.fnv64_at_put))),
                        ]))
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
            (ws_key.clone(), Json::Arr(rows))
        })
        .collect();
    Json::obj(vec![("version", Json::Int(2)), ("workspaces", Json::Obj(workspaces))]).to_json_string()
}

fn read_memo_snapshot(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read memo snapshot metadata: {e}")),
        Ok(meta) if !meta.is_file() => return Err("memo snapshot is not a regular file".to_string()),
        Ok(_) => {}
    }
    fs::read(path)
        .map(Some)
        .map_err(|e| format!("read memo snapshot: {e}"))
}

fn load_memos_from_disk(path: &Path) -> Result<MemoBoard, String> {
    let Some(raw) = read_memo_snapshot(path)? else {
        return Ok(MemoBoard {
            entries: MemoMap::new(),
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
        snapshot_hash: Ok(Some(fnv1a_64(&raw))),
    })
}

fn decode_memos(doc: &Json) -> Option<MemoMap> {
    let version = doc.get_i64("version")?;
    if !matches!(version, 1 | 2) {
        return None;
    }
    let mut result = MemoMap::new();
    for (ws_key, val) in doc.get("workspaces")?.as_obj()? {
        let rows = val.as_arr()?;
        if rows.len() > MAX_MEMOS_PER_WORKSPACE || ws_key.is_empty() {
            return None;
        }
        let entries = rows
            .iter()
            .map(|row| decode_memo_entry(row, version == 2).map(Arc::new))
            .collect::<Option<Vec<_>>>()?;
        if result.insert(ws_key.clone(), entries).is_some() {
            return None;
        }
    }
    Some(result)
}

fn decode_memo_entry(row: &Json, v2: bool) -> Option<MemoEntry> {
    let topic = row.get_str("topic").filter(|s| !s.is_empty())?.to_string();
    let summary = row.get_str("summary").filter(|s| !s.is_empty())?.to_string();
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
            Some(MemoFileLink {
                abs_path,
                rel_path: link.get_str("rel_path")?.to_string(),
                fnv64_at_put: u64::from_str_radix(link.get_str("fnv64")?, 16).ok()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let kind = if v2 {
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
        author: v2
            .then(|| valid_memo_author(author))
            .flatten()
            .unwrap_or(MEMO_AUTHOR_UNKNOWN)
            .to_string(),
        updated_ms,
        linked_files,
    })
}
