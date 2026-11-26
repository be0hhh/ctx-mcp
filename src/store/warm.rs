//! Bounded, cooldown-gated background file pre-warmer for daemon mode.
//! Discovers active files via short-timeout git queries and universal root manifests
//! without full-tree `stat()` storms, releasing locks and permits before file I/O.

use crate::base::security::{admit_file_in_workspace, is_sensitive_path_with_ws};
use crate::base::simd::FastHashMap;
use crate::rpc::BrokerService;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const WARM_COOLDOWN_SECS: u64 = 60;
pub const MAX_WARM_WORKSPACES: usize = 64;
pub const MAX_WARM_FILES: usize = 256;
pub const MAX_WARM_TOTAL_BYTES: usize = 32 << 20;

const GIT_TIMEOUT: Duration = Duration::from_millis(400);
const GIT_STDOUT_CAP: usize = 64 << 10;
const ROOT_FILES: &[&str] = &[
    "AGENTS.md", "CLAUDE.md", "README.md", "Cargo.toml", "CMakeLists.txt",
    "package.json", "go.mod", "pyproject.toml", "Makefile", "Dockerfile", ".gitignore",
];

pub struct PrewarmTracker {
    state: Mutex<FastHashMap<PathBuf, Instant>>,
    in_flight: AtomicBool,
}

impl Default for PrewarmTracker {
    fn default() -> Self { Self::new() }
}

impl PrewarmTracker {
    pub fn new() -> Self {
        Self { state: Mutex::new(FastHashMap::default()), in_flight: AtomicBool::new(false) }
    }

    pub fn try_begin(&self, ws_root: &Path) -> bool {
        if self.in_flight.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return false;
        }
        let (now, cooldown) = (Instant::now(), Duration::from_secs(WARM_COOLDOWN_SECS));
        let admitted = self.state.lock().map_or(false, |mut map| {
            map.retain(|_, ts| now.saturating_duration_since(*ts) < cooldown);
            if map.contains_key(ws_root) { return false; }
            if map.len() >= MAX_WARM_WORKSPACES {
                if let Some(oldest) = map.iter().min_by_key(|(_, ts)| **ts).map(|(k, _)| k.clone()) {
                    map.remove(&oldest);
                }
            }
            map.insert(ws_root.to_path_buf(), now);
            true
        });
        if !admitted { self.in_flight.store(false, Ordering::Release); }
        admitted
    }

    pub fn finish(&self) { self.in_flight.store(false, Ordering::Release); }
}

struct InFlightGuard { tracker: Arc<PrewarmTracker> }
impl Drop for InFlightGuard { fn drop(&mut self) { self.tracker.finish(); } }

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
}

fn hidden_git_cmd() -> Command {
    crate::base::platform::hidden_command(crate::base::platform::resolve_tool("git"))
}

fn read_capped(mut input: impl Read, cap: usize) -> io::Result<Vec<u8>> {
    let (mut out, mut buf) = (Vec::new(), [0u8; 4096]);
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 { return Ok(out); }
        let keep = n.min(cap.saturating_sub(out.len()));
        if keep > 0 { out.extend_from_slice(&buf[..keep]); }
    }
}

fn run_git_bounded(svc: &BrokerService, ws_root: &Path, args: &[&str]) -> Option<String> {
    let deadline = Instant::now() + GIT_TIMEOUT;
    let _permit = svc.subproc_sem.acquire_until(deadline).ok()??;
    let child = hidden_git_cmd()
        .arg("-C").arg(ws_root).arg("--no-pager").args(args)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().ok()?;
    let mut guard = ChildGuard(child);
    let stdout = guard.0.stdout.take()?;
    let (tx, rx) = mpsc::sync_channel::<io::Result<Vec<u8>>>(1);
    thread::Builder::new().name("ctx-prewarm-git".into())
        .spawn(move || { let _ = tx.send(read_capped(stdout, GIT_STDOUT_CAP)); }).ok()?;
    let bytes = rx.recv_timeout(deadline.checked_duration_since(Instant::now())?).ok()?.ok()?;
    let status = loop {
        match guard.0.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => thread::sleep(deadline.checked_duration_since(Instant::now())?.min(Duration::from_millis(5))),
            Err(_) => return None,
        }
    };
    status.success().then(|| String::from_utf8_lossy(&bytes).into_owned())
}

fn parse_porcelain_rel(line: &str) -> Option<&str> {
    let b = line.as_bytes();
    if b.len() < 4 || b[0] == b'D' || b[1] == b'D' { return None; }
    let rest = line[3..].trim();
    let cleaned = rest.split_once(" -> ").map_or(rest, |(_, rhs)| rhs.trim()).trim_matches('"');
    (!cleaned.is_empty()).then_some(cleaned)
}

fn push_candidate(ws_root: &Path, rel: &str, seen: &mut FastHashMap<PathBuf, ()>, out: &mut Vec<PathBuf>) {
    if out.len() >= (MAX_WARM_FILES << 1) || rel.is_empty() { return; }
    let cand = ws_root.join(rel);
    if seen.insert(cand.clone(), ()).is_none() { out.push(cand); }
}

pub fn spawn_background_prewarm(svc: Arc<BrokerService>, ws_root: PathBuf, tracker: Arc<PrewarmTracker>) {
    if !tracker.try_begin(&ws_root) { return; }
    let guard = InFlightGuard { tracker };
    let _ = thread::Builder::new().name("ctx-prewarm".into()).spawn(move || {
        let _guard = guard;
        if svc.shutting_down.load(Ordering::Relaxed) { return; }
        let mut seen: FastHashMap<PathBuf, ()> = FastHashMap::default();
        let mut candidates: Vec<PathBuf> = Vec::with_capacity(64);
        if ws_root.join(".git").exists() {
            if let Some(st) = run_git_bounded(&svc, &ws_root, &["status", "--porcelain"]) {
                for line in st.lines() {
                    if let Some(rel) = parse_porcelain_rel(line) {
                        push_candidate(&ws_root, rel, &mut seen, &mut candidates);
                    }
                }
            }
            if !svc.shutting_down.load(Ordering::Relaxed) {
                if let Some(log) = run_git_bounded(&svc, &ws_root, &["log", "-n", "20", "--name-only", "--pretty=format:"]) {
                    for line in log.lines() {
                        push_candidate(&ws_root, line.trim(), &mut seen, &mut candidates);
                    }
                }
            }
        }
        for &name in ROOT_FILES {
            if ws_root.join(name).is_file() {
                push_candidate(&ws_root, name, &mut seen, &mut candidates);
            }
        }
        let (mut loaded_files, mut loaded_bytes) = (0usize, 0usize);
        for cand in candidates {
            if svc.shutting_down.load(Ordering::Relaxed)
                || loaded_files >= MAX_WARM_FILES
                || loaded_bytes >= MAX_WARM_TOTAL_BYTES
            {
                break;
            }
            let Ok(canon) = admit_file_in_workspace(&cand, &ws_root) else { continue; };
            if is_sensitive_path_with_ws(&canon, Some(&ws_root), false)
                || super::is_multimodal_or_binary_ext(&canon)
            {
                continue;
            }
            let (used, budget) = svc.store.ram_usage_and_budget();
            if used.saturating_mul(4) >= budget.saturating_mul(3) { break; }
            if let Ok(entry) = svc.store.get_full_entry(&canon, Some(&ws_root)) {
                loaded_files += 1;
                loaded_bytes = loaded_bytes.saturating_add(entry.size_bytes as usize);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_enforces_cooldown_in_flight_and_workspace_cap() {
        let tracker = PrewarmTracker::new();
        let ws_a = PathBuf::from("/tmp/warm-ws-a");
        assert!(tracker.try_begin(&ws_a));
        assert!(!tracker.try_begin(&PathBuf::from("/tmp/warm-ws-b")));
        tracker.finish();
        assert!(!tracker.try_begin(&ws_a));
        if let Some(old) = Instant::now().checked_sub(Duration::from_secs(WARM_COOLDOWN_SECS + 1)) {
            tracker.state.lock().unwrap().insert(ws_a.clone(), old);
            assert!(tracker.try_begin(&ws_a));
            tracker.finish();
        }
        for i in 0..(MAX_WARM_WORKSPACES + 6) {
            let ws = PathBuf::from(format!("/tmp/warm-cap-{i}"));
            assert!(tracker.try_begin(&ws));
            tracker.finish();
        }
        assert!(tracker.state.lock().unwrap().len() <= MAX_WARM_WORKSPACES);
    }

    #[test]
    fn raii_guard_releases_in_flight_on_drop_and_panic() {
        let tracker = Arc::new(PrewarmTracker::new());
        assert!(tracker.try_begin(Path::new("/tmp/warm-raii-1")));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = InFlightGuard { tracker: Arc::clone(&tracker) };
            panic!("simulated prewarm panic");
        }));
        assert!(res.is_err());
        assert!(!tracker.in_flight.load(Ordering::Acquire));
        assert!(tracker.try_begin(Path::new("/tmp/warm-raii-2")));
        tracker.finish();
        assert_eq!(parse_porcelain_rel(" M src/lib.rs"), Some("src/lib.rs"));
        assert_eq!(parse_porcelain_rel("R  old.rs -> new.rs"), Some("new.rs"));
        assert_eq!(parse_porcelain_rel("D  deleted.rs"), None);
    }
}
