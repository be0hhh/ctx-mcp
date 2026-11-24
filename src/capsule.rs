//! Address launch data by a host receipt or the child's direct inbound assignment.

use crate::json::Json;
use crate::security::generate_csprng_token;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(600);
const MCP_TICKET_TTL: Duration = Duration::from_secs(30);
const MAX_BRIEF_BYTES: usize = 64 * 1024;
const KEY_PREFIX: &str = "CTX_CAPSULE_KEY=";
const CLAIM_HINT: &str = "Call MCP tool agent_ctx ctx_capsule (not shell ctx) with action=\"claim\" and key set to the value below as your first tool call. If the launch receipt is pending, retry once. If delivery is unavailable, use the assignment above.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceMode {
    Inherit,
    Branch,
    Share,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClaimError {
    Pending,
    Unavailable,
}

impl WorkspaceMode {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "inherit" => Ok(Self::Inherit),
            "branch" => Ok(Self::Branch),
            "share" => Ok(Self::Share),
            _ => Err("unsupported workspace mode"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HostContext {
    pub host: &'static str,
    pub session: String,
    pub agent: Option<String>,
    pub workspace: PathBuf,
    pub codex_origin: Option<(String, String)>,
}

impl HostContext {
    pub fn identity(&self) -> Option<String> {
        self.agent.as_ref().map(|id| format!("{}:{}:{}", self.host, self.session, id))
    }

    fn same_launch_parent(&self, other: &Self) -> bool {
        self.host == other.host && self.session == other.session
            && self.agent == other.agent && self.workspace == other.workspace
    }
}

struct Entry {
    parent: HostContext,
    mode: WorkspaceMode,
    brief: String,
    call_id: Option<String>,
    index: usize,
    recipient: Option<Recipient>,
    expires: Instant,
}

pub enum Recipient {
    Agent(String),
    CodexPath(String),
}

#[derive(Default)]
struct RegistryState {
    entries: HashMap<String, Entry>,
    tickets: HashMap<String, (Instant, HostContext, String)>,
    peak: usize,
    full: u64,
    expired: u64,
    issued: u64,
    refused: u64,
}

pub struct CapsuleRegistry {
    capacity: usize,
    state: Mutex<RegistryState>,
}

impl Default for CapsuleRegistry {
    fn default() -> Self {
        let capacity = std::env::var("AGENT_CTX_CAPSULE_CAPACITY")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| (1..=4096).contains(value))
            .unwrap_or(512);
        Self { capacity, state: Mutex::new(RegistryState::default()) }
    }
}

impl RegistryState {
    fn prune(&mut self, now: Instant) {
        let pending = self.entries.len();
        self.entries.retain(|_, entry| entry.expires > now);
        self.expired += (pending - self.entries.len()) as u64;
        self.tickets.retain(|_, (expires, _, _)| *expires > now);
    }
}

impl CapsuleRegistry {
    pub fn prepare(
        &self,
        parent: &HostContext,
        mode: WorkspaceMode,
        brief: &str,
        call_id: Option<&str>,
        index: usize,
    ) -> Result<String, String> {
        if brief.trim().is_empty() || brief.len() > MAX_BRIEF_BYTES || key_in_assignment(brief).is_some() {
            return Err("invalid capsule assignment".into());
        }
        let now = Instant::now();
        let mut state = self.state.lock().map_err(|_| "capsule registry unavailable")?;
        state.prune(now);
        if let Some(call_id) = call_id {
            if let Some((key, entry)) = state.entries.iter().find(|(_, entry)| {
                entry.call_id.as_deref() == Some(call_id) && entry.index == index
                    && entry.parent.same_launch_parent(parent)
            }) {
                if entry.brief != brief || entry.mode != mode {
                    return Err("conflicting capsule launch receipt".into());
                }
                return Ok(assignment(brief, key));
            }
        }
        if state.entries.len() >= self.capacity {
            state.full += 1;
            return Err("capsule registry full; using the original assignment".into());
        }
        let key = generate_csprng_token()?;
        if state.entries.contains_key(&key) {
            return Err("capsule key collision".into());
        }
        state.entries.insert(key.clone(), Entry {
            parent: parent.clone(), mode, brief: brief.into(), call_id: call_id.map(str::to_owned),
            index, recipient: None, expires: now + TTL,
        });
        state.peak = state.peak.max(state.entries.len());
        Ok(assignment(brief, &key))
    }

    pub fn record_launch(&self, parent: &HostContext, key: &str, call_id: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.prune(Instant::now());
            if state.entries.values().any(|entry| {
                entry.call_id.as_deref() == Some(call_id) && entry.parent.same_launch_parent(parent)
            }) {
                return;
            }
            if let Some(entry) = state.entries.get_mut(key) {
                if entry.parent.same_launch_parent(parent) && entry.call_id.is_none() {
                    entry.call_id = Some(call_id.into());
                }
            }
        }
    }

    pub fn bind_receipt(&self, parent: &HostContext, call_id: &str, recipient: Recipient) {
        if let Ok(mut state) = self.state.lock() {
            state.prune(Instant::now());
            // Codex and Claude launch a single recipient per native call.
            if let Some(entry) = state.entries.values_mut().find(|entry| {
                entry.index == 0 && entry.call_id.as_deref() == Some(call_id)
                    && entry.parent.same_launch_parent(parent)
            }) {
                entry.recipient.get_or_insert(recipient);
            }
        }
    }

    pub fn bind_assignment(&self, child: &HostContext, sender: &str, initial_assignment: &str) {
        let (Some(key), Some(receiver)) = (key_in_assignment(initial_assignment), child.agent.as_ref()) else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            state.prune(Instant::now());
            if let Some(entry) = state.entries.get_mut(key) {
                if entry.call_id.is_some() && entry.parent.host == child.host && entry.parent.session == sender
                    && sender != receiver && workspace_matches(entry, &child.workspace)
                    && initial_assignment.trim_end().ends_with(assignment(&entry.brief, key).as_str())
                {
                    entry.recipient.get_or_insert_with(|| Recipient::Agent(receiver.clone()));
                }
            }
        }
    }

    pub fn claim(&self, child: &HostContext, key: &str) -> Result<String, ClaimError> {
        let mut state = self.state.lock().map_err(|_| ClaimError::Unavailable)?;
        state.prune(Instant::now());
        let candidate = state.entries.get(key).filter(|entry| {
            entry.parent.host == child.host
                && (child.host != "claude" || entry.parent.session == child.session)
                && child.agent.is_some()
                && workspace_matches(entry, &child.workspace)
        });
        match candidate {
            Some(entry) if entry.recipient.is_none() => return Err(ClaimError::Pending),
            Some(entry) if recipient_matches(entry, child) => {}
            _ => {
                state.refused += 1;
                return Err(ClaimError::Unavailable);
            }
        }
        let entry = state.entries.remove(key).expect("matched entry under registry lock");
        state.issued += 1;
        Ok(entry.brief)
    }

    pub fn issue_mcp_ticket(&self, context: HostContext, name: &str) -> Result<String, String> {
        let mut state = self.state.lock().map_err(|_| "ctx host context unavailable")?;
        let now = Instant::now();
        state.prune(now);
        if state.tickets.len() >= 4096 {
            return Err("ctx host context busy".into());
        }
        let token = generate_csprng_token()?;
        if state.tickets.contains_key(&token) {
            return Err("ctx host context key collision".into());
        }
        state.tickets.insert(token.clone(), (now + MCP_TICKET_TTL, context, name.into()));
        Ok(token)
    }

    pub fn take_mcp_ticket(&self, token: &str, operation: &str) -> Result<HostContext, String> {
        let mut state = self.state.lock().map_err(|_| "ctx host context unavailable")?;
        let now = Instant::now();
        let ticket = state.tickets.get(token).filter(|(expires, _, op)| *expires > now && op == operation);
        if ticket.is_none() {
            return Err("ctx host context expired or invalid".into());
        }
        Ok(state.tickets.remove(token).expect("matched context under registry lock").1)
    }

    pub fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = RegistryState::default();
        }
    }

    pub fn status(&self) -> Json {
        let Ok(mut state) = self.state.lock() else { return Json::obj(vec![]) };
        state.prune(Instant::now());
        Json::obj(vec![
            ("pending", Json::Int(state.entries.len() as i64)),
            ("capacity", Json::Int(self.capacity as i64)),
            ("peak", Json::Int(state.peak as i64)),
            ("full", Json::Int(state.full as i64)),
            ("expired", Json::Int(state.expired as i64)),
            ("issued", Json::Int(state.issued as i64)),
            ("refused", Json::Int(state.refused as i64)),
        ])
    }
}

fn recipient_matches(entry: &Entry, child: &HostContext) -> bool {
    match entry.recipient.as_ref() {
        Some(Recipient::Agent(receiver)) => child.agent.as_ref() == Some(receiver),
        Some(Recipient::CodexPath(receiver)) => child.codex_origin.as_ref().is_some_and(|(source, path)| {
            let expected_source = entry.parent.agent.as_ref().unwrap_or(&entry.parent.session);
            source == expected_source && path == receiver
        }),
        None => false,
    }
}

fn assignment(brief: &str, key: &str) -> String {
    format!("{brief}\n\n{CLAIM_HINT}\n{KEY_PREFIX}{key}")
}

pub fn key_in_assignment(brief: &str) -> Option<&str> {
    let (prefix, line) = brief.trim_end().rsplit_once('\n')?;
    let key = line.strip_prefix(KEY_PREFIX)?;
    (prefix.lines().last() == Some(CLAIM_HINT) && key.len() >= 32 && key.len() <= 128
        && key.bytes().all(|byte| byte.is_ascii_alphanumeric())).then_some(key)
}

fn git_admin(root: &Path) -> Option<PathBuf> {
    let marker = root.join(".git");
    if marker.is_dir() {
        return fs::canonicalize(marker).ok();
    }
    let pointer = fs::read_to_string(marker).ok()?;
    fs::canonicalize(root.join(pointer.trim().strip_prefix("gitdir: ")?)).ok()
}

fn git_common(admin: &Path) -> Option<PathBuf> {
    match fs::read_to_string(admin.join("commondir")) {
        Ok(pointer) => fs::canonicalize(admin.join(pointer.trim())).ok(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(admin.to_owned()),
        Err(_) => None,
    }
}

fn linked_worktree(parent: &Path, child: &Path) -> Option<()> {
    let common = git_common(&git_admin(parent)?)?;
    let admin = git_admin(child)?;
    if !admin.parent().is_some_and(|dir| dir == common.join("worktrees"))
        || git_common(&admin)? != common
    {
        return None;
    }
    let backlink = fs::read_to_string(admin.join("gitdir")).ok()?;
    let actual = fs::canonicalize(admin.join(backlink.trim())).ok()?;
    (actual == fs::canonicalize(child.join(".git")).ok()?).then_some(())
}

fn workspace_matches(entry: &Entry, child: &Path) -> bool {
    if entry.parent.workspace == child {
        return entry.mode != WorkspaceMode::Branch;
    }
    entry.mode != WorkspaceMode::Inherit && linked_worktree(&entry.parent.workspace, child).is_some()
}

#[cfg(test)]
mod tests {
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
}
