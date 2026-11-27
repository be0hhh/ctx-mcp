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
use crate::edit::{impact::op_impact_with_git, op_edit_with_session, op_git};
use crate::engine::search::{
    cache::SearchCache, CLI_BATCH_SEARCH_BYTES, MAX_CLI_SEARCH_RESPONSE_BYTES,
    SEARCH_RESPONSE_BYTES,
};
use crate::engine::{
    cap_text, materialize_pack_for_workspace, op_elf_audit_with_baseline, op_inspect,
    op_memo_full, op_outline_with_options, op_read_for_host, op_search, op_search_batch, op_status,
    op_symbols_with_options, parse_shorthand_search_spec, SearchError, SearchOptions,
    AGY_MCP_DEFAULT_MAX_BYTES, AGY_MCP_INLINE_CAP, DEFAULT_READ_MAX_BYTES,
};
use crate::hooks::handle_hook;
use crate::store::{
    now_ms_u64, resolve_input_path, runtime_dir, shared_repo_key, spawn_background_prewarm,
    PrewarmTracker, RamStore,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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
    pub search_cache: SearchCache,
    pub write_locks: Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>,
    pub prewarm: Arc<PrewarmTracker>,
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
            search_cache: SearchCache::new(),
            write_locks: Mutex::new(HashMap::new()),
            prewarm: Arc::new(PrewarmTracker::default()),
            last_active_ms: CachePadded::new(AtomicU64::new(now_ms_u64())),
            shutting_down: AtomicBool::new(false),
            is_daemon,
        }
    }

    pub fn workspace_write_lock(&self, ws_root: &Path) -> Result<Arc<Mutex<()>>, String> {
        let mut guard = self
            .write_locks
            .lock()
            .map_err(|_| "workspace write lock map poisoned".to_string())?;
        if guard.len() >= 64 && !guard.contains_key(ws_root) {
            guard.retain(|_, lock| Arc::strong_count(lock) > 1);
        }
        Ok(Arc::clone(
            guard
                .entry(ws_root.to_path_buf())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        ))
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
    Impact = 14,
    Edit = 15,
    Git = 16,
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
            "impact" => Some(Self::Impact),
            "edit" => Some(Self::Edit),
            "git" => Some(Self::Git),
            _ => None,
        }
    }
}

pub fn execute_request(svc: &BrokerService, req: &Json) -> Json {
    execute_request_inner(svc, None, req)
}

pub fn execute_request_arc(svc: &Arc<BrokerService>, req: &Json) -> Json {
    execute_request_inner(svc.as_ref(), Some(svc), req)
}

fn execute_request_inner(
    svc: &BrokerService,
    daemon_arc: Option<&Arc<BrokerService>>,
    req: &Json,
) -> Json {
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
    let mut registered_ws: Option<PathBuf> = None;
    if let Some(ref c) = cwd {
        let explicit = context.is_none() && req.get_bool("explicit_root").unwrap_or(false);
        if let Some(ws_root) = svc.allowlist.register_hint(c, explicit) {
            if svc.is_daemon {
                svc.store.prewarm_workspace_index_async(&ws_root);
            }
            registered_ws = Some(ws_root);
        }
    }
    let mut scoped_session = context.as_ref().and_then(|context| context.identity());
    if scoped_session.is_none() {
        if let Some(tok) = req.get_str("cli_token").filter(|s| !s.is_empty()) {
            if let Some((lease_sess, lease_ws)) = svc.broker.capsules.verify_cli_lease(tok) {
                let cwd_matches = if let Some(ref c) = cwd {
                    match (fs::canonicalize(c), fs::canonicalize(&lease_ws)) {
                        (Ok(canon_cwd), Ok(canon_lease)) => {
                            if canon_cwd.starts_with(&canon_lease) {
                                true
                            } else if let Some(ref cwd_ws) = registered_ws {
                                let lease_root = svc
                                    .allowlist
                                    .register_hint(&canon_lease, false)
                                    .unwrap_or(canon_lease);
                                shared_repo_key(cwd_ws) == shared_repo_key(&lease_root)
                            } else {
                                false
                            }
                        }
                        _ => false,
                    }
                } else {
                    false
                };
                if cwd_matches {
                    scoped_session = Some(lease_sess);
                }
            }
        }
    }
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
        OpCode::Ping => {
            if let (Some(svc_arc), Some(ws_root)) = (daemon_arc, registered_ws) {
                if svc.is_daemon {
                    spawn_background_prewarm(
                        Arc::clone(svc_arc),
                        ws_root,
                        Arc::clone(&svc.prewarm),
                    );
                }
            }
            Json::obj(vec![("ok", Json::Bool(true))])
        }
        OpCode::Status => Json::obj(vec![("ok", Json::Bool(true)), ("status", op_status(svc))]),
        OpCode::Clear => {
            if let Err(error) = svc.broker.clear_all() {
                return request_error("memo_persist", error);
            }
            svc.store.clear_all();
            svc.search_cache.clear();
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
            let max_bytes = effective_max_bytes(req, is_agy, DEFAULT_READ_MAX_BYTES);
            let force = req.get_bool("force").unwrap_or(false);
            let hashes = req.get_bool("hashes").unwrap_or(false);
            let inline_cap = is_agy.then_some(AGY_MCP_INLINE_CAP);
            match op_read_for_host(
                svc,
                &paths,
                max_bytes,
                force,
                session_key,
                cwd.as_deref(),
                inline_cap,
                hashes,
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
            let max_bytes = effective_max_bytes(req, is_agy, 0);
            let max_symbols = req.get_usize("max_symbols").unwrap_or(0);
            match op_outline_with_options(svc, &paths, max_files, max_bytes, max_symbols, cwd.as_deref()) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Inspect => {
            let paths = str_vec(req.get("paths"));
            let is_agy = context.as_ref().is_some_and(|c| c.host == "agy")
                || req.get_str("host") == Some("agy");
            let max_files = req.get_usize("max_files").unwrap_or(80);
            let max_bytes = effective_max_bytes(req, is_agy, DEFAULT_READ_MAX_BYTES);
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
            let max_bytes = effective_max_bytes(req, is_agy, DEFAULT_READ_MAX_BYTES);
            let compact = req.get_bool("compact").unwrap_or(false);
            let hashes = req.get_bool("hashes").unwrap_or(false);
            let raw = req.get_bool("raw").unwrap_or(false);
            match op_symbols_with_options(
                svc,
                &requests,
                max_bytes,
                compact,
                session_key,
                cwd.as_deref(),
                hashes,
                raw,
            ) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Search => {
            let is_agy = context.as_ref().is_some_and(|c| c.host == "agy")
                || req.get_str("host") == Some("agy");
            let batch_len = req
                .get("q")
                .and_then(Json::as_arr)
                .or_else(|| req.get("queries").and_then(Json::as_arr))
                .map(|a| a.len());
            let default_results = if batch_len.is_some() { 32 } else { 40 };
            let (default_bytes, max_cap) = if is_agy {
                let def = if batch_len.is_some_and(|n| n >= 2) {
                    AGY_MCP_DEFAULT_MAX_BYTES
                } else {
                    SEARCH_RESPONSE_BYTES
                };
                (def, AGY_MCP_DEFAULT_MAX_BYTES)
            } else {
                let def = if batch_len.is_some_and(|n| (3..=6).contains(&n)) {
                    CLI_BATCH_SEARCH_BYTES
                } else {
                    SEARCH_RESPONSE_BYTES
                };
                (def, MAX_CLI_SEARCH_RESPONSE_BYTES)
            };
            let options =
                SearchOptions::from_request_with_cap(req, default_results, default_bytes, max_cap);
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
            let since_buf;
            let topic = if action == "changes" {
                if let Some(seq) = req.get_i64("since_seq").filter(|&v| v >= 0) {
                    since_buf = seq.to_string();
                    since_buf.as_str()
                } else {
                    req.get_str("topic").unwrap_or("0")
                }
            } else {
                req.get_str("topic").unwrap_or("")
            };
            let summary = req.get_str("summary").unwrap_or("");
            let paths = str_vec(req.get("paths"));
            let is_agy = context.as_ref().is_some_and(|c| c.host == "agy")
                || req.get_str("host") == Some("agy");
            let force = req.get_bool("force").unwrap_or(false);
            let raw = req.get_bool("raw").unwrap_or(false);
            let max_bytes = effective_max_bytes(req, is_agy, 32_768);
            match op_memo_full(
                svc,
                action,
                topic,
                summary,
                req.get_str("kind"),
                scoped_session.as_deref(),
                session_key,
                &paths,
                force,
                raw,
                max_bytes,
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
                        let pack_refs = str_vec(req.get("pack_refs"));
                        svc.broker.capsules.prepare_with_packs(
                            context,
                            mode,
                            req.get_str("assignment").unwrap_or_default(),
                            pack_refs,
                            None,
                            0,
                        )
                    }),
                "claim" => match svc
                    .broker
                    .capsules
                    .claim_with_packs(context, req.get_str("key").unwrap_or_default())
                {
                    Ok((mut text, pack_refs)) => {
                        if !pack_refs.is_empty() {
                            let ws_root = svc
                                .allowlist
                                .register_hint(&context.workspace, false)
                                .unwrap_or_else(|| context.workspace.clone());
                            let per_pack = if context.host == "agy" { 4096 } else { 16_384 };
                            for pname in &pack_refs {
                                if let Ok(rendered) = materialize_pack_for_workspace(
                                    svc,
                                    &ws_root,
                                    pname,
                                    session_key,
                                    false,
                                    false,
                                    per_pack,
                                ) {
                                    text.push_str("\n\n");
                                    text.push_str(&rendered);
                                }
                            }
                        }
                        Ok(text)
                    }
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
            let base_elf = req.get_str("baseline_elf_path");
            let base_asm = req.get_str("baseline_asm_path");
            match op_elf_audit_with_baseline(svc, elf, asm, base_elf, base_asm, cwd.as_deref()) {
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
        OpCode::Impact => {
            let mut targets = str_vec(req.get("targets"));
            if targets.is_empty() {
                if let Some(single) = req.get_str("target") {
                    if !single.trim().is_empty() {
                        targets.push(single.to_string());
                    }
                }
            }
            let is_agy = context.as_ref().is_some_and(|c| c.host == "agy")
                || req.get_str("host") == Some("agy");
            let max_callers = req.get_usize("max_callers").unwrap_or(20);
            let include_tests = req.get_bool("include_tests").unwrap_or(true);
            let include_git_status = req.get_bool("include_git_status").unwrap_or(true);
            let max_bytes = effective_max_bytes(req, is_agy, DEFAULT_READ_MAX_BYTES);
            match op_impact_with_git(
                svc,
                &targets,
                max_callers,
                include_tests,
                max_bytes,
                cwd.as_deref(),
                include_git_status,
            ) {
                Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
                Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
            }
        }
        OpCode::Edit => match op_edit_with_session(svc, req, session_key, cwd.as_deref()) {
            Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
            Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
        },
        OpCode::Git => match op_git(svc, req, cwd.as_deref()) {
            Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
            Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
        },
    }
}

/// Hard-clamps Antigravity MCP responses to `AGY_MCP_DEFAULT_MAX_BYTES` (`<= 9 KB`) even when
/// callers pass larger `max_bytes`, preventing blind middle-truncation by the host harness.
fn effective_max_bytes(req: &Json, is_agy: bool, non_agy_default: usize) -> usize {
    let explicit = req.get_usize("max_bytes").filter(|&v| v > 0);
    if is_agy {
        explicit
            .map(|v| v.min(AGY_MCP_DEFAULT_MAX_BYTES))
            .unwrap_or(AGY_MCP_DEFAULT_MAX_BYTES)
    } else {
        explicit.unwrap_or(non_agy_default)
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
        if query.is_some() || (queries.is_some() && explicit_roots.is_some()) {
            return fail("use queries or single-search fields");
        }
        let Some(items) = items.as_arr() else {
            return fail("queries must be an array");
        };
        if let Some(roots_arr) = explicit_roots.and_then(Json::as_arr).filter(|a| !a.is_empty()) {
            let scoped: Vec<Json> = items
                .iter()
                .map(|item| {
                    if let Some(spec) = item.as_str() {
                        if matches!(parse_shorthand_search_spec(spec, false), Ok((_, ref r)) if r.is_empty()) {
                            return Json::obj(vec![
                                ("query", Json::Str(spec.to_string())),
                                ("roots", Json::Arr(roots_arr.to_vec())),
                            ]);
                        }
                    }
                    item.clone()
                })
                .collect();
            return op_search_batch(svc, &scoped, options, cwd);
        }
        return op_search_batch(svc, items, options, cwd);
    }

    let roots = str_vec(explicit_roots);
    if let Some(q) = q {
        if query.is_some() {
            return fail("use q or query, not both");
        }
        let Some(spec) = q.as_str() else {
            return fail("q must be a string or array of 1–6 'root:query' strings");
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
    fn agy_effective_max_bytes_hard_clamps_and_search_accepts_q_with_roots() {
        let big = Json::obj(vec![("max_bytes", Json::Int(65_536))]);
        let small = Json::obj(vec![("max_bytes", Json::Int(4_096))]);
        let none = Json::obj(vec![]);
        assert_eq!(effective_max_bytes(&big, true, DEFAULT_READ_MAX_BYTES), AGY_MCP_DEFAULT_MAX_BYTES);
        assert_eq!(effective_max_bytes(&small, true, DEFAULT_READ_MAX_BYTES), 4_096);
        assert_eq!(effective_max_bytes(&none, true, DEFAULT_READ_MAX_BYTES), AGY_MCP_DEFAULT_MAX_BYTES);
        assert_eq!(effective_max_bytes(&big, false, DEFAULT_READ_MAX_BYTES), 65_536);
        assert_eq!(effective_max_bytes(&none, false, DEFAULT_READ_MAX_BYTES), DEFAULT_READ_MAX_BYTES);

        let dir = std::env::temp_dir().join(format!(
            "ctx-rpc-qroots-{}-{}",
            std::process::id(),
            now_ms_u64()
        ));
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("a.py"), "def alpha_tok():\n    return beta_tok\n").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        svc.allowlist.register_hint(&dir, true).unwrap();
        let req = Json::obj(vec![
            ("op", Json::Str("search".into())),
            ("q", Json::Arr(vec![Json::Str("alpha_tok".into()), Json::Str("beta_tok".into())])),
            ("roots", Json::Arr(vec![Json::Str("sub".into())])),
        ]);
        let opts = SearchOptions::from_request(&req, 32);
        let out = search_request(&svc, &req, opts, Some(&dir)).unwrap();
        assert!(out.contains("alpha_tok") && out.contains("beta_tok"), "out={out}");
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

    #[test]
    fn cli_lease_sets_trusted_author_preserves_cwd_and_cli_budgets_and_degrades_on_invalid() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-rpc-lease-{}-{}",
            std::process::id(),
            now_ms_u64()
        ));
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        let big_body = (1..=350)
            .map(|i| format!("int line_{i:03} = {i}; // padding_0123456789abcdef0123456789\n"))
            .collect::<String>();
        assert!(big_body.len() > AGY_MCP_DEFAULT_MAX_BYTES + 2000);
        fs::write(sub.join("big.cpp"), &big_body).unwrap();

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        let root = svc.allowlist.register_hint(&dir, true).unwrap();
        let tok = svc
            .broker
            .capsules
            .issue_cli_lease("agy:worker-lease-1".into(), root.clone())
            .unwrap();

        // 1. Valid cli_token with subdir cwd preserves cwd (`big.cpp` relative to `sub`),
        //    sets trusted author on memo put, and does NOT apply AGY 9 KB cap to CLI read.
        let put_rep = execute_request(
            &svc,
            &Json::obj(vec![
                ("op", Json::Str("memo".into())),
                ("action", Json::Str("put".into())),
                ("cwd", Json::Str(sub.to_string_lossy().into_owned())),
                ("cli_token", Json::Str(tok.clone())),
                ("topic", Json::Str("lease-topic".into())),
                ("summary", Json::Str("verified cli lease".into())),
                ("paths", Json::Arr(vec![Json::Str("big.cpp".into())])),
            ]),
        );
        assert_eq!(put_rep.get_bool("ok"), Some(true), "{put_rep:?}");
        let get_rep = execute_request(
            &svc,
            &Json::obj(vec![
                ("op", Json::Str("memo".into())),
                ("action", Json::Str("get".into())),
                ("cwd", Json::Str(sub.to_string_lossy().into_owned())),
                ("topic", Json::Str("lease-topic".into())),
            ]),
        );
        assert_eq!(
            get_rep.get("memo").and_then(|m| m.get_str("author")),
            Some("agy:worker-lease-1")
        );

        let read_rep = execute_request(
            &svc,
            &Json::obj(vec![
                ("op", Json::Str("read".into())),
                ("cwd", Json::Str(sub.to_string_lossy().into_owned())),
                ("cli_token", Json::Str(tok.clone())),
                ("paths", Json::Arr(vec![Json::Str("big.cpp".into())])),
            ]),
        );
        assert_eq!(read_rep.get_bool("ok"), Some(true));
        assert!(
            read_rep.get_str("text").unwrap().len() > AGY_MCP_DEFAULT_MAX_BYTES + 1000,
            "CLI lease must preserve 1 MiB read budget instead of AGY 9 KB cap"
        );

        // 2. Invalid/expired cli_token degrades gracefully to unverified session for read-only ops.
        let degraded = execute_request(
            &svc,
            &Json::obj(vec![
                ("op", Json::Str("read".into())),
                ("cwd", Json::Str(sub.to_string_lossy().into_owned())),
                ("session", Json::Str("agy:fallback".into())),
                ("cli_token", Json::Str("expired-or-bogus-token".into())),
                ("paths", Json::Arr(vec![Json::Str("big.cpp".into())])),
            ]),
        );
        assert_eq!(degraded.get_bool("ok"), Some(true));

        // 3. `requires_daemon` treats `cli_token` requests as daemon-required.
        let leased_req = Json::obj(vec![
            ("op", Json::Str("read".into())),
            ("cli_token", Json::Str(tok)),
        ]);
        assert_eq!(
            run_inproc(&leased_req).get_str("code"),
            Some("daemon_unavailable")
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
