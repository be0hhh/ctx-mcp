//! Localhost RPC client with process-local keep-alive connection cache,
//! strict mutation/close-race safety, busy backoff, single-spawner guard,
//! and honest stateless `inproc` degradation.

use super::{error_reply, execute_request, read_daemon_info, BrokerService, DaemonInfo};
use crate::base::json::{self, Json, JsonKey};
use crate::base::security::ensure_private_dir;
use crate::engine::op_status;
use crate::hooks::passthrough_raw;
use crate::store::{default_snapshot_path, runtime_dir};
use std::borrow::Cow;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const KEEPALIVE_CLIENT_MAX_IDLE: Duration = Duration::from_millis(8);

struct CachedClient {
    runtime_dir: PathBuf,
    info: DaemonInfo,
    conn: Option<(TcpStream, Instant)>,
}

static CLIENT_CACHE: OnceLock<Mutex<Option<CachedClient>>> = OnceLock::new();

fn client_cache() -> &'static Mutex<Option<CachedClient>> {
    CLIENT_CACHE.get_or_init(|| Mutex::new(None))
}

fn invalidate_client_cache() {
    if let Ok(mut guard) = client_cache().lock() {
        *guard = None;
    }
}

fn store_cached_client(cur_runtime: PathBuf, info: DaemonInfo, conn: Option<TcpStream>) {
    if let Ok(mut guard) = client_cache().lock() {
        *guard = Some(CachedClient {
            runtime_dir: cur_runtime,
            info,
            conn: conn.map(|s| (s, Instant::now())),
        });
    }
}

fn is_keepalive_stream_alive(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let mut probe = [0u8; 1];
    let alive = matches!(
        stream.peek(&mut probe),
        Err(e) if e.kind() == ErrorKind::WouldBlock
    );
    if stream.set_nonblocking(false).is_err() {
        return false;
    }
    alive
}

fn take_cached_client(
    cur_runtime: &Path,
    allow_reuse_conn: bool,
) -> (Option<DaemonInfo>, Option<TcpStream>) {
    let (info, candidate) = {
        let Ok(mut guard) = client_cache().lock() else {
            return (None, None);
        };
        let Some(cached) = guard.as_mut() else {
            return (None, None);
        };
        if cached.runtime_dir != cur_runtime {
            *guard = None;
            return (None, None);
        }
        let info = cached.info.clone();
        let cand = if allow_reuse_conn {
            cached.conn.take()
        } else {
            None
        };
        (Some(info), cand)
    };
    let conn = match candidate {
        Some((stream, last_used))
            if last_used.elapsed() < KEEPALIVE_CLIENT_MAX_IDLE
                && is_keepalive_stream_alive(&stream) =>
        {
            Some(stream)
        }
        _ => None,
    };
    (info, conn)
}

pub(super) enum SendOutcome {
    Reply(Json),
    Busy,
    ConnRefused,
    BeforeSend,
    AfterSend,
}

fn is_unauthorized(reply: &Json) -> bool {
    reply.get_bool("ok") == Some(false) && reply.get_str("error") == Some("unauthorized")
}

pub(super) fn changes_daemon_state(req: &Json) -> bool {
    if req.get("ctx_context").is_some() {
        return true;
    }
    match req.get_str("op") {
        Some("capsule" | "clear" | "edit" | "hook" | "save_snapshot" | "shutdown") => {
            true
        }
        Some("memo") => matches!(req.get_str("action"), Some("put" | "clear" | "pack")),
        _ => false,
    }
}

fn requires_daemon(req: &Json) -> bool {
    req.get("ctx_context").is_some()
        || matches!(req.get_str("op"), Some("search" | "capsule" | "edit"))
}

pub(super) fn complete_attempt(outcome: SendOutcome, req: &Json) -> Option<Json> {
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

fn encode_request_line(info: &DaemonInfo, req: &Json) -> String {
    let mut fields: Vec<(JsonKey, Json)> = match req {
        Json::Obj(items) => items.clone(),
        _ => Vec::new(),
    };
    fields.push((Cow::Borrowed("token"), Json::Str(info.token.clone())));
    let mut line = Json::Obj(fields).to_json_string();
    line.push('\n');
    line
}

enum ClientRead {
    Line { text: String, clean_boundary: bool },
    CloseRace,
    Failed,
}

fn read_client_reply_line(stream: &mut TcpStream) -> ClientRead {
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => {
                if buf.is_empty() {
                    return ClientRead::CloseRace;
                }
                return match String::from_utf8(buf) {
                    Ok(text) => ClientRead::Line {
                        text,
                        clean_boundary: false,
                    },
                    Err(_) => ClientRead::Failed,
                };
            }
            Ok(n) => {
                let chunk = &tmp[..n];
                if let Some(nl) = chunk.iter().position(|&b| b == b'\n') {
                    buf.extend_from_slice(&chunk[..=nl]);
                    let clean_boundary = nl + 1 == n;
                    return match String::from_utf8(buf) {
                        Ok(text) => ClientRead::Line {
                            text,
                            clean_boundary,
                        },
                        Err(_) => ClientRead::Failed,
                    };
                }
                buf.extend_from_slice(chunk);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e)
                if buf.is_empty()
                    && matches!(
                        e.kind(),
                        ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::BrokenPipe
                            | ErrorKind::UnexpectedEof
                    ) =>
            {
                return ClientRead::CloseRace;
            }
            Err(_) => return ClientRead::Failed,
        }
    }
}

fn parse_reply_outcome(
    resp_line: &str,
    write_ok: bool,
    clean_boundary: bool,
    allow_keep: bool,
    stream: TcpStream,
) -> (SendOutcome, Option<TcpStream>) {
    let trimmed = resp_line.trim();
    if trimmed.is_empty() {
        return (SendOutcome::AfterSend, None);
    }
    match json::parse(trimmed) {
        Ok(reply)
            if reply.get_bool("ok") == Some(false)
                && (reply.get_str("code") == Some("daemon_busy")
                    || (reply.get("code").is_none() && reply.get_str("error") == Some("busy"))) =>
        {
            (SendOutcome::Busy, None)
        }
        Ok(reply) if write_ok && reply.get_bool("ok").is_some() => {
            let keep = allow_keep && clean_boundary && !is_unauthorized(&reply);
            (SendOutcome::Reply(reply), keep.then_some(stream))
        }
        _ => (SendOutcome::AfterSend, None),
    }
}

fn try_send_reused_stream(
    mut stream: TcpStream,
    line: &[u8],
) -> Result<(SendOutcome, Option<TcpStream>), ()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    if stream.write_all(line).is_err() {
        return Err(());
    }
    match read_client_reply_line(&mut stream) {
        ClientRead::CloseRace => Err(()),
        ClientRead::Line {
            text,
            clean_boundary,
        } => {
            if text.trim().is_empty() {
                return Err(());
            }
            Ok(parse_reply_outcome(&text, true, clean_boundary, true, stream))
        }
        ClientRead::Failed => Ok((SendOutcome::AfterSend, None)),
    }
}

fn try_send_fresh_stream(
    info: &DaemonInfo,
    line: &[u8],
    allow_keep: bool,
) -> (SendOutcome, Option<TcpStream>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], info.port));
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
            return (SendOutcome::ConnRefused, None);
        }
        Err(_) => return (SendOutcome::BeforeSend, None),
    };
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    // Queue rejection can arrive before the server reads the request, even if our write fails.
    let write_ok = stream.write_all(line).is_ok();

    match read_client_reply_line(&mut stream) {
        ClientRead::Line {
            text,
            clean_boundary,
        } => parse_reply_outcome(&text, write_ok, clean_boundary, allow_keep, stream),
        ClientRead::CloseRace | ClientRead::Failed => (SendOutcome::AfterSend, None),
    }
}

pub(super) fn try_send_fresh(info: &DaemonInfo, req: &Json) -> SendOutcome {
    let line = encode_request_line(info, req);
    let (outcome, _) = try_send_fresh_stream(info, line.as_bytes(), false);
    outcome
}

pub(super) fn try_send_with_reuse(
    info: &DaemonInfo,
    reused: Option<TcpStream>,
    req: &Json,
) -> (SendOutcome, Option<TcpStream>) {
    let line = encode_request_line(info, req);
    let allow_keep = req.get_str("op") != Some("shutdown");
    if let Some(stream) = reused {
        if let Ok(result) = try_send_reused_stream(stream, line.as_bytes()) {
            return result;
        }
    }
    try_send_fresh_stream(info, line.as_bytes(), allow_keep)
}

fn send_with_busy_backoff(
    cur_runtime: &Path,
    info: &DaemonInfo,
    initial_reused: Option<TcpStream>,
    req: &Json,
) -> SendOutcome {
    let is_shutdown = req.get_str("op") == Some("shutdown");
    let mut reused = if changes_daemon_state(req) {
        None
    } else {
        initial_reused
    };
    let (mut outcome, mut keep_stream) = try_send_with_reuse(info, reused.take(), req);
    for wait_ms in [12, 25] {
        if !matches!(outcome, SendOutcome::Busy) {
            break;
        }
        thread::sleep(Duration::from_millis(wait_ms));
        (outcome, keep_stream) = try_send_with_reuse(info, None, req);
    }

    match &outcome {
        SendOutcome::ConnRefused => invalidate_client_cache(),
        SendOutcome::Reply(reply) if is_shutdown || is_unauthorized(reply) => {
            invalidate_client_cache();
        }
        SendOutcome::Reply(_) => {
            store_cached_client(cur_runtime.to_path_buf(), info.clone(), keep_stream);
        }
        SendOutcome::Busy | SendOutcome::BeforeSend | SendOutcome::AfterSend => {
            if is_shutdown {
                invalidate_client_cache();
            }
        }
    }
    outcome
}

pub fn stop_daemon_for_install() -> Result<(), String> {
    invalidate_client_cache();
    let Some(info) = read_daemon_info() else {
        return Ok(());
    };
    let request = Json::obj(vec![("op", Json::Str("shutdown".into()))]);
    let cur_runtime = runtime_dir();
    match send_with_busy_backoff(&cur_runtime, &info, None, &request) {
        SendOutcome::Reply(reply) if reply.get_bool("ok") == Some(true) => Ok(()),
        SendOutcome::ConnRefused => Ok(()),
        SendOutcome::Busy => {
            Err("ctx daemon is busy, retry install after active requests finish".into())
        }
        _ => Err("ctx daemon did not confirm shutdown before install".into()),
    }
}

pub fn call_daemon_or_inproc(req: Json) -> Json {
    if std::env::var("AGENT_CTX_INPROC").as_deref() == Ok("1") {
        return run_inproc(&req);
    }

    let is_shutdown = req.get_str("op") == Some("shutdown");
    let cur_runtime = runtime_dir();
    let allow_reuse = !changes_daemon_state(&req);
    if is_shutdown {
        invalidate_client_cache();
    }

    let (cached_info, cached_conn) = if is_shutdown {
        (None, None)
    } else {
        take_cached_client(&cur_runtime, allow_reuse)
    };

    if let Some(info) = cached_info {
        let outcome = send_with_busy_backoff(&cur_runtime, &info, cached_conn, &req);
        let stale_unauthorized =
            matches!(&outcome, SendOutcome::Reply(reply) if is_unauthorized(reply));
        if matches!(outcome, SendOutcome::ConnRefused) || stale_unauthorized {
            invalidate_client_cache();
            if let Some(disk_info) = read_daemon_info() {
                if disk_info.port != info.port || disk_info.token != info.token {
                    let retry = send_with_busy_backoff(&cur_runtime, &disk_info, None, &req);
                    if let Some(reply) = complete_attempt(retry, &req) {
                        return reply;
                    }
                }
            }
            if stale_unauthorized {
                if let Some(reply) = complete_attempt(outcome, &req) {
                    return reply;
                }
            }
        } else if let Some(reply) = complete_attempt(outcome, &req) {
            return reply;
        }
    } else if let Some(info) = read_daemon_info() {
        let outcome = send_with_busy_backoff(&cur_runtime, &info, None, &req);
        if let Some(reply) = complete_attempt(outcome, &req) {
            return reply;
        }
    }

    if is_shutdown {
        return Json::obj(vec![("ok", Json::Bool(true))]);
    }

    let _ = spawn_background_daemon_once();
    for attempt in 0..46u8 {
        let wait_ms = if attempt < 10 { 10 } else { 25 };
        thread::sleep(Duration::from_millis(wait_ms));
        if let Some(info) = read_daemon_info() {
            let outcome = send_with_busy_backoff(&cur_runtime, &info, None, &req);
            if let Some(reply) = complete_attempt(outcome, &req) {
                return reply;
            }
        }
    }

    run_inproc(&req)
}

/// Honest stateless fallback: never fakes cross-process mutations (`memo put/clear`,
/// `clear`, `save_snapshot`, or stateful hooks) when the daemon is unreachable.
pub(super) fn run_inproc(req: &Json) -> Json {
    let op = req.get_str("op").unwrap_or("");
    let explicit_inproc_write = op == "edit"
        && std::env::var("AGENT_CTX_INPROC").as_deref() == Ok("1");
    if requires_daemon(req) && !explicit_inproc_write {
        return error_reply(
            "daemon_unavailable",
            "this request requires a running ctx daemon",
            false,
        );
    }
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
            if matches!(action, "put" | "clear" | "pack") {
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
                items.push((Cow::Borrowed("degraded_inproc"), Json::Bool(true)));
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
        "edit" => {
            if std::env::var("AGENT_CTX_INPROC").as_deref() == Ok("1") {
                let svc = BrokerService::new_ephemeral_inproc(default_snapshot_path());
                execute_request(&svc, req)
            } else {
                error_reply(
                    "daemon_unavailable",
                    "ctx daemon unreachable: refusing file write in stateless in-process fallback (set AGENT_CTX_INPROC=1 to override)",
                    false,
                )
            }
        }
        "status" => {
            let svc = BrokerService::new_ephemeral_inproc(default_snapshot_path());
            let mut st = op_status(&svc);
            if let Json::Obj(ref mut fields) = st {
                fields.push((
                    Cow::Borrowed("mode"),
                    Json::Str("inproc_degraded".to_string()),
                ));
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
                items.push((Cow::Borrowed("degraded_inproc"), Json::Bool(true)));
            }
            res
        }
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
