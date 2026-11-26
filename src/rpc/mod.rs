//! Concurrent localhost IPC (`127.0.0.1` + 256-bit OS CSPRNG token in `0600`
//! `daemon.json`):
//!   - Fixed 32-thread worker pool + bounded 512-connection queue returning fast `"busy"`
//!     on saturation without daemon spawn storms.
//!   - Starvation-free bounded keep-alive (`MAX_KEEPALIVE_WAITERS = 8` of 32 workers) with
//!     reusable per-worker read buffers and zero `stream.try_clone()` / `BufReader` churn.
//!   - `SubprocSemaphore` bounds external `rg` subprocesses.
//!   - Stateless-only `inproc` fallback when loopback sockets are blocked by sandboxes.

pub mod client;
pub mod daemon;

pub use client::{call_daemon_or_inproc, stop_daemon_for_install};
pub use daemon::run_daemon_forever;

use crate::base::json::{self, Json};
use crate::base::security::{ensure_private_dir, write_private_0600, WorkspaceAllowlist};
use crate::base::simd::CachePadded;
use crate::broker::{ClaimError, ContextBroker, WorkspaceMode};
use crate::engine::{
    cap_text, op_elf_audit, op_inspect, op_memo, op_outline, op_read_for_host, op_search,
    op_search_batch, op_status, op_symbols, parse_shorthand_search_spec, SearchError,
    SearchOptions, AGY_MCP_DEFAULT_MAX_BYTES, AGY_MCP_INLINE_CAP, DEFAULT_INSPECT_MAX_BYTES,
    DEFAULT_READ_MAX_BYTES,
};
use crate::hooks::handle_hook;
use crate::store::{now_ms_u64, resolve_input_path, runtime_dir, RamStore};
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

pub const MAX_CONCURRENT_SUBPROCS: usize = 16;

#[derive(Clone, Debug)]
pub struct DaemonInfo {
    pub port: u16,
    pub token: String,
    pub pid: u32,
}

pub struct SubprocSemaphore {
    active: Mutex<usize>,
    peak: AtomicU64,
    cv: Condvar,
    limit: usize,
}

pub struct SubprocPermit<'a> {
    sem: &'a SubprocSemaphore,
}

impl<'a> Drop for SubprocPermit<'a> {
    fn drop(&mut self) {
        if let Ok(mut g) = self.sem.active.lock() {
            *g = g.saturating_sub(1);
        }
        self.sem.cv.notify_one();
    }
}

impl SubprocSemaphore {
    pub fn new(limit: usize) -> Self {
        Self {
            active: Mutex::new(0),
            peak: AtomicU64::new(0),
            cv: Condvar::new(),
            limit: limit.max(1),
        }
    }

    pub fn active_count(&self) -> usize {
        self.active.lock().map(|g| *g).unwrap_or(0)
    }

    pub fn peak_count(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }

    /// Strictly bounded semaphore: never increments `active` above `limit` on timeout.
    #[cfg(test)]
    pub fn acquire(&self, max_wait: Duration) -> Result<SubprocPermit<'_>, String> {
        self.acquire_until(Instant::now() + max_wait)?
            .ok_or_else(|| format!("subprocess semaphore saturated (limit={})", self.limit))
    }

    pub fn acquire_until(&self, deadline: Instant) -> Result<Option<SubprocPermit<'_>>, String> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "subprocess semaphore lock poisoned".to_string())?;
        loop {
            let now = Instant::now();
            if now >= deadline {
                if *active < self.limit {
                    self.cv.notify_one();
                }
                return Ok(None);
            }
            if *active < self.limit {
                *active += 1;
                self.peak.fetch_max(*active as u64, Ordering::Relaxed);
                return Ok(Some(SubprocPermit { sem: self }));
            }
            (active, _) = self
                .cv
                .wait_timeout(active, deadline - now)
                .map_err(|_| "subprocess semaphore lock poisoned".to_string())?;
        }
    }
}

pub struct BrokerService {
    pub store: RamStore,
    pub broker: ContextBroker,
    pub allowlist: WorkspaceAllowlist,
    pub subproc_sem: SubprocSemaphore,
    pub last_active_ms: CachePadded<AtomicU64>,
    pub shutting_down: AtomicBool,
    pub is_daemon: bool,
}

impl BrokerService {
    fn with_mode(snapshot_path: PathBuf, is_daemon: bool) -> Self {
        let memo_path = snapshot_path.with_file_name("memos.json");
        Self {
            store: RamStore::new(snapshot_path),
            broker: ContextBroker::new(Some(memo_path)),
            allowlist: WorkspaceAllowlist::new(),
            subproc_sem: SubprocSemaphore::new(MAX_CONCURRENT_SUBPROCS),
            last_active_ms: CachePadded::new(AtomicU64::new(now_ms_u64())),
            shutting_down: AtomicBool::new(false),
            is_daemon,
        }
    }

    pub fn new(snapshot_path: PathBuf) -> Self {
        Self::with_mode(snapshot_path, true)
    }

    pub fn new_ephemeral_inproc(snapshot_path: PathBuf) -> Self {
        Self::with_mode(snapshot_path, false)
    }
}

pub fn daemon_info_path() -> PathBuf {
    runtime_dir().join("daemon.json")
}

pub fn read_daemon_info() -> Option<DaemonInfo> {
    let path = daemon_info_path();
    let txt = fs::read_to_string(path).ok()?;
    let parsed = json::parse(&txt).ok()?;
    let port = parsed.get_usize("port")? as u16;
    let token = parsed.get_str("token")?.to_string();
    let pid = parsed.get_usize("pid").unwrap_or(0) as u32;
    if port == 0 || token.len() < 32 {
        return None;
    }
    Some(DaemonInfo { port, token, pid })
}

fn write_daemon_info(port: u16, token: &str) -> Result<(), String> {
    let dir = runtime_dir();
    ensure_private_dir(&dir)?;
    let path = dir.join("daemon.json");
    let body = Json::obj(vec![
        ("port", Json::Int(port as i64)),
        ("token", Json::Str(token.to_string())),
        ("pid", Json::Int(std::process::id() as i64)),
    ])
    .to_json_string();
    write_private_0600(&path, body.as_bytes())
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum OpCode {
    Ping = 1,
    Status = 2,
    Clear = 3,
    SaveSnapshot = 4,
    Read = 5,
    Outline = 6,
    Inspect = 7,
    Symbols = 8,
    Search = 9,
    Memo = 10,
    Capsule = 11,
    ElfAudit = 12,
    Hook = 13,
}

impl OpCode {
    #[inline]
    fn parse(op: &str) -> Option<Self> {
        match op {
            "ping" => Some(Self::Ping),
            "status" => Some(Self::Status),
            "clear" => Some(Self::Clear),
            "save_snapshot" => Some(Self::SaveSnapshot),
            "read" => Some(Self::Read),
            "outline" => Some(Self::Outline),
            "inspect" => Some(Self::Inspect),
            "symbols" => Some(Self::Symbols),
            "search" => Some(Self::Search),
            "memo" => Some(Self::Memo),
            "capsule" => Some(Self::Capsule),
            "elf_audit" => Some(Self::ElfAudit),
            "hook" => Some(Self::Hook),
            _ => None,
        }
    }
}

pub fn execute_request(svc: &BrokerService, req: &Json) -> Json {
    let now = now_ms_u64();
    if now.saturating_sub(svc.last_active_ms.load(Ordering::Relaxed)) >= 1_000 {
        svc.last_active_ms.store(now, Ordering::Relaxed);
    }
    let op = req.get_str("op").unwrap_or("");
    let context = match req.get("ctx_context") {
        Some(Json::Str(ticket)) => match svc.broker.capsules.take_mcp_ticket(ticket, op) {
            Ok(context) => Some(context),
            Err(error) => return request_error("host_context", error),
        },
        Some(_) => return request_error("host_context", "invalid ctx host context".into()),
        None => None,
    };
    let cwd = context
        .as_ref()
        .map(|context| context.workspace.clone())
        .or_else(|| req.get_str("cwd").map(|s| resolve_input_path(s, None)));
    if let Some(ref c) = cwd {
        let explicit = context.is_none() && req.get_bool("explicit_root").unwrap_or(false);
        if let Some(ws_root) = svc.allowlist.register_hint(c, explicit) {
            if svc.is_daemon {
                svc.store.prewarm_workspace_index_async(&ws_root);
            }
        }
    }
    let scoped_session = context.as_ref().and_then(|context| context.identity());
    let session_key = scoped_session
        .as_deref()
        .or_else(|| req.get_str("session").filter(|s| !s.is_empty()));

    let Some(opcode) = OpCode::parse(op) else {
        return Json::obj(vec![
            ("ok", Json::Bool(false)),
            ("error", Json::Str(format!("unknown op: {}", op))),
        ]);
    };

    match opcode {
        OpCode::Ping => Json::obj(vec![("ok", Json::Bool(true))]),
        OpCode::Status => Json::obj(vec![("ok", Json::Bool(true)), ("status", op_status(svc))]),
        OpCode::Clear => {
            if let Err(error) = svc.broker.clear_all() {
                return request_error("memo_persist", error);
            }
            svc.store.clear_all();
            Json::obj(vec![
                ("ok", Json::Bool(true)),
                (
                    "text",
                    Json::Str("RAM cache, memos, and snapshot cleared.".to_string()),
                ),
            ])
        }
        OpCode::SaveSnapshot => match svc.store.save_snapshot() {
            Ok(()) => Json::obj(vec![("ok", Json::Bool(true))]),
            Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
        },
        OpCode::Read => {
            let paths = str_vec(req.get("paths"));
            let is_agy = context.as_ref().is_some_and(|c| c.host == "agy")
                || req.get_str("host") == Some("agy");
            let explicit_max = req.get_usize("max_bytes").filter(|&v| v > 0);
            let max_bytes = explicit_max.unwrap_or(if is_agy {
                AGY_MCP_DEFAULT_MAX_BYTES
            } else {
                DEFAULT_READ_MAX_BYTES
            });
            let force = req.get_bool("force").unwrap_or(false);
            let inline_cap = is_agy.then_some(AGY_MCP_INLINE_CAP);
            match op_read_for_host(
                svc,
                &paths,
                max_bytes,
                force,
                session_key,
                cwd.as_deref(),
                inline_cap,
            ) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Outline => {
            let paths = str_vec(req.get("paths"));
            let is_agy = context.as_ref().is_some_and(|c| c.host == "agy")
                || req.get_str("host") == Some("agy");
            let max_files = req.get_usize("max_files").unwrap_or(40);
            let max_bytes = req
                .get_usize("max_bytes")
                .filter(|&v| v > 0)
                .unwrap_or(if is_agy { AGY_MCP_DEFAULT_MAX_BYTES } else { 0 });
            match op_outline(svc, &paths, max_files, max_bytes, cwd.as_deref()) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Inspect => {
            let paths = str_vec(req.get("paths"));
            let is_agy = context.as_ref().is_some_and(|c| c.host == "agy")
                || req.get_str("host") == Some("agy");
            let max_files = req.get_usize("max_files").unwrap_or(80);
            let max_bytes = req
                .get_usize("max_bytes")
                .filter(|&v| v > 0)
                .unwrap_or(if is_agy {
                    DEFAULT_INSPECT_MAX_BYTES
                } else {
                    DEFAULT_READ_MAX_BYTES
                });
            let warn_lines = req.get_usize("warn_lines").unwrap_or(600);
            match op_inspect(svc, &paths, max_files, max_bytes, warn_lines, cwd.as_deref()) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Symbols => {
            let requests = str_vec(req.get("requests"));
            let is_agy = context.as_ref().is_some_and(|c| c.host == "agy")
                || req.get_str("host") == Some("agy");
            let max_bytes = req
                .get_usize("max_bytes")
                .filter(|&v| v > 0)
                .unwrap_or(if is_agy {
                    AGY_MCP_DEFAULT_MAX_BYTES
                } else {
                    DEFAULT_READ_MAX_BYTES
                });
            let compact = req.get_bool("compact").unwrap_or(false);
            match op_symbols(svc, &requests, max_bytes, compact, session_key, cwd.as_deref()) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Search => {
            let options = SearchOptions::from_request(
                req,
                if req.get("q").and_then(Json::as_arr).is_some() || req.get("queries").is_some() {
                    32
                } else {
                    40
                },
            );
            let result = search_request(svc, req, options, cwd.as_deref());
            match result {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(SearchError::Busy) => error_reply(
                    "search_busy",
                    &cap_text("all ctx search slots are busy", options.max_bytes),
                    true,
                ),
                Err(SearchError::Timeout) => error_reply(
                    "search_timeout",
                    &cap_text(
                        "ctx search timed out while collecting candidates",
                        options.max_bytes,
                    ),
                    false,
                ),
                Err(SearchError::Failed(error)) => {
                    error_reply("search_failed", &cap_text(&error, options.max_bytes), false)
                }
            }
        }
        OpCode::Memo => {
            let action = req.get_str("action").unwrap_or("list");
            let topic = req.get_str("topic").unwrap_or("");
            let summary = req.get_str("summary").unwrap_or("");
            let paths = str_vec(req.get("paths"));
            match op_memo(
                svc,
                action,
                topic,
                summary,
                req.get_str("kind"),
                scoped_session.as_deref(),
                &paths,
                cwd.as_deref(),
            ) {
                Ok(Json::Obj(mut fields)) => {
                    fields.push((Cow::Borrowed("ok"), Json::Bool(true)));
                    Json::Obj(fields)
                }
                Ok(_) => request_error("memo_response", "invalid memo response".into()),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Capsule => {
            let Some(context) = context.as_ref() else {
                return request_error(
                    "host_context",
                    "capsule requires an active host hook; use the original assignment if delivery is unavailable".into(),
                );
            };
            let action = req.get_str("action").unwrap_or_default();
            let result = match action {
                "prepare" => WorkspaceMode::parse(req.get_str("workspace").unwrap_or("inherit"))
                    .map_err(str::to_owned)
                    .and_then(|mode| {
                        svc.broker.capsules.prepare(
                            context,
                            mode,
                            req.get_str("assignment").unwrap_or_default(),
                            None,
                            0,
                        )
                    }),
                "claim" => match svc
                    .broker
                    .capsules
                    .claim(context, req.get_str("key").unwrap_or_default())
                {
                    Ok(text) => Ok(text),
                    Err(ClaimError::Pending) => {
                        return error_reply(
                            "capsule_pending",
                            "capsule launch receipt is pending; retry once with a fresh tool call",
                            true,
                        );
                    }
                    Err(ClaimError::Unavailable) => {
                        Err("capsule unavailable for this launch; use the original assignment".into())
                    }
                },
                _ => Err("capsule action must be prepare or claim".into()),
            };
            match result {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(error) => request_error("capsule_unavailable", error),
            }
        }
        OpCode::ElfAudit => {
            let elf = req.get_str("elf_path").unwrap_or("");
            let asm = req.get_str("asm_path");
            match op_elf_audit(svc, elf, asm, cwd.as_deref()) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Hook => {
            let flavor = req.get_str("flavor").unwrap_or("");
            let payload_str = req.get_str("payload").unwrap_or("{}");
            let reply = handle_hook(svc, flavor, payload_str);
            Json::obj(vec![("ok", Json::Bool(true)), ("hook_reply", reply)])
        }
    }
}

fn request_error(code: &str, error: String) -> Json {
    Json::obj(vec![
        ("ok", Json::Bool(false)),
        ("code", Json::Str(code.into())),
        ("error", Json::Str(error)),
    ])
}

fn error_reply(code: &str, message: &str, retryable: bool) -> Json {
    Json::obj(vec![
        ("ok", Json::Bool(false)),
        ("error", Json::Str(message.to_string())),
        ("code", Json::Str(code.to_string())),
        ("retryable", Json::Bool(retryable)),
    ])
}

fn search_request(
    svc: &BrokerService,
    req: &Json,
    options: SearchOptions,
    cwd: Option<&Path>,
) -> Result<String, SearchError> {
    let fail = |message: &str| Err(SearchError::Failed(message.into()));
    let query = req.get("query");
    let explicit_roots = req.get("roots");
    let q = req.get("q");
    let queries = req.get("queries");
    if q.is_some() && queries.is_some() {
        return fail("use q or queries, not both");
    }
    if let Some(items) = queries.or_else(|| q.filter(|value| value.as_arr().is_some())) {
        if query.is_some() || explicit_roots.is_some() {
            return fail("use queries or single-search fields");
        }
        let Some(items) = items.as_arr() else {
            return fail("queries must be an array");
        };
        return op_search_batch(svc, items, options, cwd);
    }

    let roots = str_vec(explicit_roots);
    if let Some(q) = q {
        if query.is_some() {
            return fail("use q or query, not both");
        }
        let Some(spec) = q.as_str() else {
            return fail("q must be a string or array of 1–4 'root:query' strings");
        };
        let (query, shorthand_roots) = parse_shorthand_search_spec(spec, false)?;
        if !roots.is_empty() && !shorthand_roots.is_empty() {
            return fail("roots already specified in q shorthand");
        }
        let roots = if shorthand_roots.is_empty() {
            &roots
        } else {
            &shorthand_roots
        };
        return op_search(svc, &query, roots, options, cwd);
    }
    op_search(svc, req.get_str("query").unwrap_or(""), &roots, options, cwd)
}

fn str_vec(val: Option<&Json>) -> Vec<String> {
    val.and_then(|v| v.as_arr())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

pub fn workspace_cwd_str(explicit: Option<&Path>) -> String {
    explicit
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::client::{
        changes_daemon_state, complete_attempt, run_inproc, try_send_with_reuse, SendOutcome,
    };
    use super::daemon::{handle_client_for_test, AcceptQueue};
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::thread;

    fn request(op: &str) -> Json {
        Json::obj(vec![("op", Json::Str(op.to_string()))])
    }

    #[test]
    fn subprocess_semaphore_releases_capacity_and_never_grants_after_deadline() {
        let sem = SubprocSemaphore::new(1);
        let permit = sem.acquire(Duration::from_secs(1)).unwrap();
        thread::scope(|scope| {
            let waiter = scope.spawn(|| sem.acquire(Duration::from_secs(1)));
            assert!(sem.acquire_until(Instant::now()).unwrap().is_none());
            assert_eq!(sem.active_count(), 1);
            drop(permit);
            assert!(waiter.join().unwrap().is_ok());
        });
        assert_eq!(sem.active_count(), 0);
        assert_eq!(sem.peak_count(), 1);
    }

    #[test]
    fn transport_never_degrades_search_to_inproc() {
        let search = request("search");
        assert_eq!(
            run_inproc(&search).get_str("code"),
            Some("daemon_unavailable")
        );

        let after_send = complete_attempt(SendOutcome::AfterSend, &search).unwrap();
        assert_eq!(after_send.get_str("code"), Some("daemon_transport"));
        assert_eq!(after_send.get_bool("retryable"), Some(false));

        let rejected = complete_attempt(SendOutcome::Busy, &search).unwrap();
        assert_eq!(rejected.get_str("code"), Some("daemon_busy"));
        assert_eq!(rejected.get_bool("retryable"), Some(true));
    }

    #[test]
    fn lost_confirmation_is_unknown_for_mutations_and_scoped_reads() {
        let memo = Json::obj(vec![
            ("op", Json::Str("memo".to_string())),
            ("action", Json::Str("put".to_string())),
        ]);
        let scoped = Json::obj(vec![
            ("op", Json::Str("read".to_string())),
            ("ctx_context", Json::Str("ticket".to_string())),
        ]);
        assert_eq!(
            run_inproc(&scoped).get_str("code"),
            Some("daemon_unavailable")
        );
        assert_eq!(
            run_inproc(&request("capsule")).get_str("code"),
            Some("daemon_unavailable")
        );
        for req in [request("capsule"), request("hook"), memo, scoped] {
            let lost = complete_attempt(SendOutcome::AfterSend, &req).unwrap();
            assert_eq!(lost.get_str("code"), Some("outcome_unknown"));
            assert_eq!(lost.get_bool("retryable"), Some(false));
        }

        let independent = complete_attempt(SendOutcome::AfterSend, &request("status")).unwrap();
        assert_eq!(independent.get_bool("degraded_inproc"), Some(true));
    }

    #[test]
    fn keepalive_roundtrip_reuses_single_connection_and_classifies_mutations() {
        assert!(!changes_daemon_state(&request("ping")));
        assert!(!changes_daemon_state(&request("status")));
        assert!(!changes_daemon_state(&request("search")));
        assert!(changes_daemon_state(&request("hook")));
        assert!(changes_daemon_state(&request("shutdown")));
        assert!(changes_daemon_state(&Json::obj(vec![
            ("op", Json::Str("memo".into())),
            ("action", Json::Str("put".into())),
        ])));

        let dir = std::env::temp_dir().join(format!(
            "ctx-rpc-ka-{}-{}",
            std::process::id(),
            now_ms_u64()
        ));
        fs::create_dir_all(&dir).unwrap();
        let svc = Arc::new(BrokerService::new_ephemeral_inproc(dir.join("snap.bin")));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let token = "0123456789abcdef0123456789abcdef".to_string();
        let queue = Arc::new(AcceptQueue::new_for_test());
        let waiters = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));

        let srv_svc = Arc::clone(&svc);
        let srv_tok = token.clone();
        let srv_q = Arc::clone(&queue);
        let srv_w = Arc::clone(&waiters);
        let srv_acc = Arc::clone(&accepted);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            srv_acc.fetch_add(1, Ordering::AcqRel);
            let mut buf = Vec::with_capacity(8192);
            handle_client_for_test(stream, &srv_svc, &srv_tok, &srv_q, &srv_w, &mut buf);
        });

        let info = DaemonInfo { port, token, pid: 1 };
        let (out1, conn1) = try_send_with_reuse(&info, None, &request("ping"));
        match out1 {
            SendOutcome::Reply(r) => assert_eq!(r.get_bool("ok"), Some(true)),
            _ => panic!("expected first keep-alive reply"),
        }
        let stream1 = conn1.expect("first reply should yield reusable keep-alive stream");

        let (out2, conn2) = try_send_with_reuse(&info, Some(stream1), &request("status"));
        match out2 {
            SendOutcome::Reply(r) => {
                assert_eq!(r.get_bool("ok"), Some(true));
                assert!(r.get("status").is_some());
            }
            _ => panic!("expected second keep-alive reply on reused stream"),
        }
        assert!(conn2.is_some());
        drop(conn2);
        server.join().unwrap();
        assert_eq!(accepted.load(Ordering::Acquire), 1);
        assert_eq!(waiters.load(Ordering::Acquire), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn keepalive_close_race_retries_once_on_fresh_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let token = "fedcba9876543210fedcba9876543210".to_string();

        let server = thread::spawn(move || {
            // Connection 1: serve request 1, then drop immediately after receiving request 2 bytes.
            let (mut s1, _) = listener.accept().unwrap();
            let mut tmp = [0u8; 512];
            let _ = s1.read(&mut tmp).unwrap();
            s1.write_all(b"{\"ok\":true,\"seq\":1}\n").unwrap();
            s1.flush().unwrap();
            let _ = s1.read(&mut tmp);
            drop(s1);

            // Connection 2: fresh retry succeeds cleanly.
            let (mut s2, _) = listener.accept().unwrap();
            let _ = s2.read(&mut tmp).unwrap();
            s2.write_all(b"{\"ok\":true,\"retried\":true}\n").unwrap();
            s2.flush().unwrap();
        });

        let info = DaemonInfo { port, token, pid: 1 };
        let (out1, conn1) = try_send_with_reuse(&info, None, &request("ping"));
        match out1 {
            SendOutcome::Reply(r) => assert_eq!(r.get_i64("seq"), Some(1)),
            _ => panic!("expected seq=1 reply"),
        }
        let reused = conn1.expect("expected reusable stream");
        let (out2, _conn2) = try_send_with_reuse(&info, Some(reused), &request("ping"));
        match out2 {
            SendOutcome::Reply(r) => {
                assert_eq!(r.get_bool("ok"), Some(true));
                assert_eq!(r.get_bool("retried"), Some(true));
            }
            _ => panic!("expected close-race recovery reply"),
        }
        server.join().unwrap();
    }
}
