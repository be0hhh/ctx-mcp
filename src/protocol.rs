//! Concurrent localhost IPC (`127.0.0.1` + 256-bit OS CSPRNG token in `0600`
//! `daemon.json`):
//!   - Fixed 32-thread worker pool + bounded 512-connection queue returning fast `"busy"`
//!     on saturation without daemon spawn storms.
//!   - `SubprocSemaphore(8)` bounding external `rg` / `CxetElfAudit.py` subprocesses.
//!   - Stateless-only `inproc` fallback when loopback sockets are blocked by sandboxes.

use crate::broker::ContextBroker;
use crate::engine::{
    op_elf_audit, op_inspect, op_memo, op_outline, op_read, op_search, op_search_batch,
    op_search_batch_with_defaults, op_status, op_symbols, DEFAULT_READ_MAX_BYTES,
};
use crate::hooks::{handle_hook, passthrough_raw};
use crate::json::{self, Json};
use crate::security::{
    ensure_private_dir, generate_csprng_token, write_private_0600, WorkspaceAllowlist,
};
use crate::simd::CachePadded;
use crate::store::{default_snapshot_path, now_ms_u64, runtime_dir, RamStore};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const IDLE_SHUTDOWN_MS: u64 = 4 * 60 * 60 * 1000; // 4 hours idle TTL
const WORKER_THREADS: usize = 32;
const MAX_ACCEPT_QUEUE: usize = 512;
pub const MAX_CONCURRENT_SUBPROCS: usize = 8;

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

    pub fn try_acquire(&self) -> Result<Option<SubprocPermit<'_>>, String> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "subprocess semaphore lock poisoned".to_string())?;
        if *active >= self.limit {
            return Ok(None);
        }
        *active += 1;
        self.peak.fetch_max(*active as u64, Ordering::Relaxed);
        Ok(Some(SubprocPermit { sem: self }))
    }

    /// Strictly bounded semaphore: never increments `active` above `limit` on timeout.
    pub fn acquire(&self, max_wait: Duration) -> Result<SubprocPermit<'_>, String> {
        let deadline = Instant::now() + max_wait;
        let mut g = self
            .active
            .lock()
            .map_err(|_| "subprocess semaphore lock poisoned".to_string())?;
        while *g >= self.limit {
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "subprocess semaphore saturated (limit={})",
                    self.limit
                ));
            }
            let remain = deadline - now;
            match self.cv.wait_timeout(g, remain) {
                Ok((next, timeout)) => {
                    g = next;
                    if *g >= self.limit && timeout.timed_out() {
                        return Err(format!(
                            "subprocess semaphore saturated (limit={})",
                            self.limit
                        ));
                    }
                }
                Err(_) => return Err("subprocess semaphore lock poisoned".to_string()),
            }
        }
        *g += 1;
        self.peak.fetch_max(*g as u64, Ordering::Relaxed);
        Ok(SubprocPermit { sem: self })
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
    pub fn new(snapshot_path: PathBuf) -> Self {
        let memo_path = snapshot_path.with_file_name("memos.json");
        Self {
            store: RamStore::new(snapshot_path),
            broker: ContextBroker::new(Some(memo_path)),
            allowlist: WorkspaceAllowlist::new(),
            subproc_sem: SubprocSemaphore::new(MAX_CONCURRENT_SUBPROCS),
            last_active_ms: CachePadded::new(AtomicU64::new(now_ms_u64())),
            shutting_down: AtomicBool::new(false),
            is_daemon: true,
        }
    }

    pub fn new_ephemeral_inproc(snapshot_path: PathBuf) -> Self {
        let memo_path = snapshot_path.with_file_name("memos.json");
        Self {
            store: RamStore::new(snapshot_path),
            broker: ContextBroker::new(Some(memo_path)),
            allowlist: WorkspaceAllowlist::new(),
            subproc_sem: SubprocSemaphore::new(MAX_CONCURRENT_SUBPROCS),
            last_active_ms: CachePadded::new(AtomicU64::new(now_ms_u64())),
            shutting_down: AtomicBool::new(false),
            is_daemon: false,
        }
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
        .or_else(|| req.get_str("cwd").map(|s| crate::store::resolve_input_path(s, None)));
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
            let max_bytes = req.get_usize("max_bytes").unwrap_or(DEFAULT_READ_MAX_BYTES);
            let force = req.get_bool("force").unwrap_or(false);
            match op_read(svc, &paths, max_bytes, force, session_key, cwd.as_deref()) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Outline => {
            let paths = str_vec(req.get("paths"));
            let max_files = req.get_usize("max_files").unwrap_or(40);
            let max_bytes = req.get_usize("max_bytes").unwrap_or(0);
            match op_outline(svc, &paths, max_files, max_bytes, cwd.as_deref()) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Inspect => {
            let paths = str_vec(req.get("paths"));
            let max_files = req.get_usize("max_files").unwrap_or(80);
            let max_bytes = req.get_usize("max_bytes").unwrap_or(DEFAULT_READ_MAX_BYTES);
            let warn_lines = req.get_usize("warn_lines").unwrap_or(600);
            match op_inspect(svc, &paths, max_files, max_bytes, warn_lines, cwd.as_deref()) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Symbols => {
            let requests = str_vec(req.get("requests"));
            let max_bytes = req.get_usize("max_bytes").unwrap_or(DEFAULT_READ_MAX_BYTES);
            let compact = req.get_bool("compact").unwrap_or(false);
            match op_symbols(svc, &requests, max_bytes, compact, session_key, cwd.as_deref()) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Search => {
            let has_single_fields = ["query", "roots", "max_results", "detail", "context_lines"]
                .iter()
                .any(|k| req.get(k).is_some());
            let result = if let Some(q_val) = req.get("q") {
                if req.get("queries").is_some() {
                    return error_reply("search_failed", "use q or queries, not both", false);
                }
                match q_val {
                    Json::Arr(items) => {
                        if req.get("query").is_some() || req.get("roots").is_some() {
                            return error_reply("search_failed", "use queries or single-search fields", false);
                        }
                        let def_max = req.get_usize("max_results").unwrap_or(32).max(32);
                        let def_ctx = req.get_usize("context_lines").unwrap_or(0).min(4);
                        op_search_batch_with_defaults(svc, items, def_max, def_ctx, cwd.as_deref())
                    }
                    Json::Str(spec) => {
                        if req.get("query").is_some() {
                            return error_reply("search_failed", "use q or query, not both", false);
                        }
                        match crate::engine::parse_shorthand_search_spec(spec, false) {
                            Ok((parsed_q, parsed_roots)) => {
                                let explicit_roots = str_vec(req.get("roots"));
                                let roots = if explicit_roots.is_empty() {
                                    parsed_roots
                                } else if parsed_roots.is_empty() {
                                    explicit_roots
                                } else {
                                    return error_reply(
                                        "search_failed",
                                        "roots already specified in q shorthand",
                                        false,
                                    );
                                };
                                let max_results = req.get_usize("max_results").unwrap_or(40);
                                let with_scopes = req.get_str("detail") == Some("scopes");
                                let context_lines = req.get_usize("context_lines").unwrap_or(0);
                                op_search(
                                    svc,
                                    &parsed_q,
                                    &roots,
                                    max_results,
                                    with_scopes,
                                    context_lines,
                                    cwd.as_deref(),
                                )
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => {
                        return error_reply(
                            "search_failed",
                            "q must be a string or array of 1–4 'root:query' strings",
                            false,
                        );
                    }
                }
            } else if let Some(batch) = req.get("queries") {
                if has_single_fields {
                    return error_reply("search_failed", "use queries or single-search fields", false);
                }
                let Some(queries) = batch.as_arr() else {
                    return error_reply("search_failed", "queries must be an array", false);
                };
                op_search_batch(svc, queries, cwd.as_deref())
            } else {
                let query = req.get_str("query").unwrap_or("");
                let roots = str_vec(req.get("roots"));
                let max_results = req.get_usize("max_results").unwrap_or(40);
                let with_scopes = req.get_str("detail") == Some("scopes");
                let context_lines = req.get_usize("context_lines").unwrap_or(0);
                op_search(svc, query, &roots, max_results, with_scopes, context_lines, cwd.as_deref())
            };
            match result {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(crate::engine::SearchError::Busy) => {
                    error_reply("search_busy", "all ctx search slots are busy", true)
                }
                Err(crate::engine::SearchError::Timeout) => {
                    error_reply("search_timeout", "ctx search timed out while collecting candidates", false)
                }
                Err(crate::engine::SearchError::Failed(e)) => {
                    error_reply("search_failed", &e, false)
                }
            }
        }
        OpCode::Memo => {
            let action = req.get_str("action").unwrap_or("list");
            let topic = req.get_str("topic").unwrap_or("");
            let summary = req.get_str("summary").unwrap_or("");
            let paths = str_vec(req.get("paths"));
            match op_memo(svc, action, topic, summary, req.get_str("kind"), scoped_session.as_deref(), &paths, cwd.as_deref()) {
                Ok(Json::Obj(mut fields)) => {
                    fields.push(("ok".into(), Json::Bool(true)));
                    Json::Obj(fields)
                }
                Ok(_) => request_error("memo_response", "invalid memo response".into()),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Capsule => {
            let Some(context) = context.as_ref() else {
                return request_error("host_context", "capsule requires an active host hook; use the original assignment if delivery is unavailable".into());
            };
            let action = req.get_str("action").unwrap_or_default();
            let result = match action {
                "prepare" => crate::capsule::WorkspaceMode::parse(req.get_str("workspace").unwrap_or("inherit"))
                    .map_err(str::to_owned)
                    .and_then(|mode| svc.broker.capsules.prepare(
                        context, mode, req.get_str("assignment").unwrap_or_default(), None, 0,
                    )),
                "claim" => match svc.broker.capsules.claim(context, req.get_str("key").unwrap_or_default()) {
                    Ok(text) => Ok(text),
                    Err(crate::capsule::ClaimError::Pending) => {
                        return error_reply(
                            "capsule_pending", "capsule launch receipt is pending; retry once with a fresh tool call", true,
                        );
                    }
                    Err(crate::capsule::ClaimError::Unavailable) => {
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

fn str_vec(val: Option<&Json>) -> Vec<String> {
    val.and_then(|v| v.as_arr())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

enum SendOutcome {
    Reply(Json),
    Busy,
    ConnRefused,
    BeforeSend,
    AfterSend,
}

fn error_reply(code: &str, message: &str, retryable: bool) -> Json {
    Json::obj(vec![
        ("ok", Json::Bool(false)),
        ("error", Json::Str(message.to_string())),
        ("code", Json::Str(code.to_string())),
        ("retryable", Json::Bool(retryable)),
    ])
}

fn changes_daemon_state(req: &Json) -> bool {
    if req.get("ctx_context").is_some() {
        return true;
    }
    match req.get_str("op") {
        Some("capsule" | "clear" | "hook" | "save_snapshot" | "shutdown") => true,
        Some("memo") => matches!(req.get_str("action"), Some("put" | "clear")),
        _ => false,
    }
}

fn requires_daemon(req: &Json) -> bool {
    req.get("ctx_context").is_some() || matches!(req.get_str("op"), Some("search" | "capsule"))
}

fn complete_attempt(outcome: SendOutcome, req: &Json) -> Option<Json> {
    match outcome {
        SendOutcome::Reply(reply) => Some(reply),
        SendOutcome::Busy => Some(error_reply(
            "daemon_busy",
            "ctx daemon accept queue is busy",
            true,
        )),
        SendOutcome::ConnRefused => None,
        SendOutcome::BeforeSend => Some(run_inproc(req)),
        SendOutcome::AfterSend if changes_daemon_state(req) => Some(error_reply(
            "outcome_unknown",
            "ctx daemon did not confirm the request outcome",
            false,
        )),
        SendOutcome::AfterSend if requires_daemon(req) => Some(error_reply(
            "daemon_transport",
            "ctx daemon connection ended before a valid response",
            false,
        )),
        SendOutcome::AfterSend => Some(run_inproc(req)),
    }
}

fn send_with_busy_backoff(info: &DaemonInfo, req: &Json) -> SendOutcome {
    let mut outcome = try_send(info, req);
    for wait_ms in [12, 25] {
        if !matches!(outcome, SendOutcome::Busy) {
            break;
        }
        thread::sleep(Duration::from_millis(wait_ms));
        outcome = try_send(info, req);
    }
    outcome
}

pub fn stop_daemon_for_install() -> Result<(), String> {
    let Some(info) = read_daemon_info() else { return Ok(()); };
    let request = Json::obj(vec![("op", Json::Str("shutdown".into()))]);
    match send_with_busy_backoff(&info, &request) {
        SendOutcome::Reply(reply) if reply.get_bool("ok") == Some(true) => Ok(()),
        SendOutcome::ConnRefused => Ok(()),
        SendOutcome::Busy => Err("ctx daemon is busy, retry install after active requests finish".into()),
        _ => Err("ctx daemon did not confirm shutdown before install".into()),
    }
}

pub fn call_daemon_or_inproc(req: Json) -> Json {
    if std::env::var("AGENT_CTX_INPROC").as_deref() == Ok("1") {
        return run_inproc(&req);
    }

    if let Some(info) = read_daemon_info() {
        if let Some(reply) = complete_attempt(send_with_busy_backoff(&info, &req), &req) {
            return reply;
        }
    }
    if req.get_str("op") == Some("shutdown") {
        return Json::obj(vec![("ok", Json::Bool(true))]);
    }

    let _ = spawn_background_daemon_once();
    for _ in 0..18 {
        thread::sleep(Duration::from_millis(18));
        if let Some(info) = read_daemon_info() {
            if let Some(reply) = complete_attempt(send_with_busy_backoff(&info, &req), &req) {
                return reply;
            }
        }
    }

    run_inproc(&req)
}

/// Honest stateless fallback: never fakes cross-process mutations (`memo put/clear`,
/// `clear`, `save_snapshot`, or stateful hooks) when the daemon is unreachable.
fn run_inproc(req: &Json) -> Json {
    if requires_daemon(req) {
        return error_reply(
            "daemon_unavailable",
            "this request requires a running ctx daemon",
            false,
        );
    }
    let op = req.get_str("op").unwrap_or("");
    match op {
        "hook" => {
            let flavor = req.get_str("flavor").unwrap_or("");
            let payload = req.get_str("payload").unwrap_or("");
            Json::obj(vec![
                ("ok", Json::Bool(true)),
                ("degraded_inproc", Json::Bool(true)),
                ("hook_reply", passthrough_raw(flavor, payload)),
            ])
        }
        "memo" => {
            let action = req.get_str("action").unwrap_or("list");
            if action == "put" || action == "clear" {
                return Json::obj(vec![
                    ("ok", Json::Bool(false)),
                    ("degraded_inproc", Json::Bool(true)),
                    (
                        "error",
                        Json::Str(
                            "ctx daemon unreachable: refusing stateful `memo` mutation in stateless in-process fallback"
                                .to_string(),
                        ),
                    ),
                ]);
            }
            let svc = BrokerService::new_ephemeral_inproc(default_snapshot_path());
            let mut res = execute_request(&svc, req);
            if let Json::Obj(ref mut items) = res {
                items.push(("degraded_inproc".to_string(), Json::Bool(true)));
            }
            res
        }
        "clear" | "save_snapshot" | "shutdown" => Json::obj(vec![
            ("ok", Json::Bool(false)),
            ("degraded_inproc", Json::Bool(true)),
            (
                "error",
                Json::Str(format!(
                    "ctx daemon unreachable: `{}` requires a running daemon",
                    op
                )),
            ),
        ]),
        "status" => {
            let svc = BrokerService::new_ephemeral_inproc(default_snapshot_path());
            let mut st = op_status(&svc);
            if let Json::Obj(ref mut fields) = st {
                fields.push(("mode".to_string(), Json::Str("inproc_degraded".to_string())));
            }
            Json::obj(vec![
                ("ok", Json::Bool(true)),
                ("degraded_inproc", Json::Bool(true)),
                ("status", st),
            ])
        }
        _ => {
            let svc = BrokerService::new_ephemeral_inproc(default_snapshot_path());
            let mut res = execute_request(&svc, req);
            if let Json::Obj(ref mut items) = res {
                items.push(("degraded_inproc".to_string(), Json::Bool(true)));
            }
            res
        }
    }
}

fn try_send(info: &DaemonInfo, req: &Json) -> SendOutcome {
    let addr = SocketAddr::from(([127, 0, 0, 1], info.port));
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => return SendOutcome::ConnRefused,
        Err(_) => return SendOutcome::BeforeSend,
    };
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut fields = match req {
        Json::Obj(items) => items.clone(),
        _ => Vec::new(),
    };
    fields.push(("token".to_string(), Json::Str(info.token.clone())));
    let mut line = Json::Obj(fields).to_json_string();
    line.push('\n');
    // Queue rejection can arrive before the server reads the request, even if our write fails.
    let write_ok = stream.write_all(line.as_bytes()).is_ok();

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    if reader.read_line(&mut resp_line).is_err() || resp_line.trim().is_empty() {
        return SendOutcome::AfterSend;
    }
    match json::parse(resp_line.trim()) {
        Ok(reply)
            if reply.get_bool("ok") == Some(false)
                && (reply.get_str("code") == Some("daemon_busy")
                    || (reply.get("code").is_none() && reply.get_str("error") == Some("busy"))) =>
        {
            SendOutcome::Busy
        }
        Ok(reply) if write_ok && reply.get_bool("ok").is_some() => SendOutcome::Reply(reply),
        _ => SendOutcome::AfterSend,
    }
}

/// Non-blocking single-spawner guard (`daemon.spawn.lock`) so 200 simultaneous clients
/// on a cold start launch only ONE `ctx daemon` process.
fn spawn_background_daemon_once() -> Result<(), String> {
    let dir = runtime_dir();
    ensure_private_dir(&dir)?;
    let lock_path = dir.join("daemon.spawn.lock");

    if let Ok(meta) = fs::metadata(&lock_path) {
        let age_ok = meta
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .map(|d| d < Duration::from_secs(8))
            .unwrap_or(false);
        if age_ok {
            return Ok(());
        }
        let _ = fs::remove_file(&lock_path);
    }

    let lock_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path);
    if lock_file.is_err() {
        return Ok(());
    }

    let exe = std::env::current_exe().map_err(|e| {
        let _ = fs::remove_file(&lock_path);
        e.to_string()
    })?;
    let mut cmd = Command::new(exe);
    cmd.arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let res = cmd.spawn().map(|_| ()).map_err(|e| e.to_string());
    if res.is_err() {
        let _ = fs::remove_file(&lock_path);
    }
    res
}

struct AcceptQueue {
    items: Mutex<VecDeque<TcpStream>>,
    cv: Condvar,
}

pub fn run_daemon_forever() -> Result<(), String> {
    if let Some(info) = read_daemon_info() {
        if !matches!(
            try_send(&info, &Json::obj(vec![("op", Json::Str("ping".to_string()))])),
            SendOutcome::ConnRefused
        ) {
            let _ = fs::remove_file(runtime_dir().join("daemon.spawn.lock"));
            return Ok(());
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn listen( sockfd: i32, backlog: i32) -> i32;
        }
        // Raise kernel accept backlog above Rust std's default 128 so 200+ simultaneous
        // agent bursts never hit the 200ms TCP SYN retransmit cliff.
        unsafe {
            let _ = listen(listener.as_raw_fd(), 1024);
        }
    }
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let token = generate_csprng_token()?;
    write_daemon_info(port, &token)?;
    let _ = fs::remove_file(runtime_dir().join("daemon.spawn.lock"));
    let _ = listener.set_nonblocking(false);

    let service = Arc::new(BrokerService::new(default_snapshot_path()));
    let queue = Arc::new(AcceptQueue {
        items: Mutex::new(VecDeque::with_capacity(MAX_ACCEPT_QUEUE)),
        cv: Condvar::new(),
    });

    // Spawn bounded pool of 32 worker threads
    for _ in 0..WORKER_THREADS {
        let q = Arc::clone(&queue);
        let svc = Arc::clone(&service);
        let tok = token.clone();
        thread::spawn(move || loop {
            let stream_opt = {
                let Ok(mut guard) = q.items.lock() else {
                    return;
                };
                while guard.is_empty() && !svc.shutting_down.load(Ordering::Relaxed) {
                    match q.cv.wait(guard) {
                        Ok(next) => guard = next,
                        Err(_) => return,
                    }
                }
                if svc.shutting_down.load(Ordering::Relaxed) && guard.is_empty() {
                    return;
                }
                guard.pop_front()
            };
            if let Some(stream) = stream_opt {
                let _ = handle_client(stream, &svc, &tok, &q);
            }
        });
    }

    // Background periodic metadata-only snapshot saver & 4h idle reaper
    let bg_svc = Arc::clone(&service);
    let info_file = daemon_info_path();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(30));
        let _ = bg_svc.store.save_snapshot_if_dirty(false);
        let idle = now_ms_u64().saturating_sub(bg_svc.last_active_ms.load(Ordering::Relaxed));
        if idle > IDLE_SHUTDOWN_MS {
            let _ = bg_svc.store.save_snapshot_if_dirty(true);
            let _ = fs::remove_file(&info_file);
            std::process::exit(0);
        }
    });

    for incoming in listener.incoming() {
        if service.shutting_down.load(Ordering::Relaxed) {
            break;
        }
        let Ok(stream) = incoming else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        let rejected = {
            if let Ok(mut guard) = queue.items.lock() {
                if guard.len() >= MAX_ACCEPT_QUEUE {
                    Some(stream)
                } else {
                    guard.push_back(stream);
                    None
                }
            } else {
                Some(stream)
            }
        };
        if let Some(mut busy_stream) = rejected {
            let _ = busy_stream.set_write_timeout(Some(Duration::from_millis(100)));
            let mut reply =
                error_reply("daemon_busy", "ctx daemon accept queue is busy", true).to_json_string();
            reply.push('\n');
            let _ = busy_stream.write_all(reply.as_bytes());
            let _ = busy_stream.flush();
        } else {
            queue.cv.notify_one();
        }
    }
    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    svc: &BrokerService,
    expected_token: &str,
    queue: &AcceptQueue,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if n == 0 || line.len() > (2 << 20) {
        return Ok(());
    }
    let req = json::parse(line.trim())?;
    if req.get_str("token") != Some(expected_token) {
        let err = Json::obj(vec![
            ("ok", Json::Bool(false)),
            ("error", Json::Str("unauthorized".to_string())),
        ]);
        let mut out = err.to_json_string();
        out.push('\n');
        let _ = stream.write_all(out.as_bytes());
        return Ok(());
    }

    if req.get_str("op") == Some("shutdown") {
        svc.shutting_down.store(true, Ordering::Relaxed);
        queue.cv.notify_all();
        let _ = svc.store.save_snapshot_if_dirty(true);
        let _ = fs::remove_file(daemon_info_path());
        let ok = Json::obj(vec![("ok", Json::Bool(true))]).to_json_string() + "\n";
        let _ = stream.write_all(ok.as_bytes());
        let _ = stream.flush();
        std::process::exit(0);
    }

    let reply = execute_request(svc, &req);
    let mut out = reply.to_json_string();
    out.push('\n');
    stream.write_all(out.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
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
mod transport_tests {
    use super::*;

    fn request(op: &str) -> Json {
        Json::obj(vec![("op", Json::Str(op.to_string()))])
    }

    #[test]
    fn search_saturation_returns_busy_without_running_search() {
        let svc = BrokerService::new_ephemeral_inproc(PathBuf::new());
        let mut permits: Vec<_> = (0..MAX_CONCURRENT_SUBPROCS)
            .map(|_| svc.subproc_sem.try_acquire().unwrap().unwrap())
            .collect();
        let search = Json::obj(vec![
            ("op", Json::Str("search".to_string())),
            ("query", Json::Str("needle".to_string())),
        ]);
        let busy = execute_request(&svc, &search);
        assert_eq!(busy.get_str("code"), Some("search_busy"));
        assert_eq!(busy.get_bool("retryable"), Some(true));
        assert_eq!(svc.subproc_sem.active_count(), MAX_CONCURRENT_SUBPROCS);

        drop(permits.pop());
        assert!(svc.subproc_sem.try_acquire().unwrap().is_some());
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
}
