//! Localhost TCP daemon loop with a 64-thread worker pool, bounded 1024-item accept queue,
//! reusable per-worker read buffers (zero `try_clone()` / `BufReader` malloc), and
//! starvation-free bounded keep-alive (`MAX_KEEPALIVE_WAITERS = WORKER_THREADS >> 2`).

use super::client::{try_send_fresh, SendOutcome};
use super::{
    daemon_info_path, error_reply, read_daemon_info, write_daemon_info, BrokerService,
};
use crate::base::json::{self, Json};
use crate::base::security::generate_csprng_token;
use crate::store::{default_snapshot_path, now_ms_u64, runtime_dir};
use std::collections::VecDeque;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

const IDLE_SHUTDOWN_MS: u64 = 4 * 60 * 60 * 1000; // 4 hours idle TTL
const WORKER_THREADS: usize = 64;
const MAX_ACCEPT_QUEUE: usize = 1024;
const MAX_KEEPALIVE_WAITERS: usize = WORKER_THREADS >> 2;
const MAX_KEEPALIVE_REQUESTS: usize = 64;
const INITIAL_READ_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_READ_TIMEOUT: Duration = Duration::from_millis(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_LINE_BYTES: usize = 2 << 20; // 2 MiB
const WORKER_BUF_CAP: usize = 8192;

pub(super) struct AcceptQueue {
    items: Mutex<VecDeque<TcpStream>>,
    cv: Condvar,
    queued_count: AtomicUsize,
}

impl AcceptQueue {
    fn new() -> Self {
        Self {
            items: Mutex::new(VecDeque::with_capacity(MAX_ACCEPT_QUEUE)),
            cv: Condvar::new(),
            queued_count: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub(super) fn new_for_test() -> Self {
        Self::new()
    }
}

struct KeepAliveGuard<'a> {
    counter: &'a AtomicUsize,
}

impl<'a> KeepAliveGuard<'a> {
    fn try_acquire(counter: &'a AtomicUsize) -> Option<Self> {
        let mut cur = counter.load(Ordering::Acquire);
        while cur < MAX_KEEPALIVE_WAITERS {
            match counter.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self { counter }),
                Err(actual) => cur = actual,
            }
        }
        None
    }
}

impl Drop for KeepAliveGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

enum LineStatus {
    Line(usize),
    Eof,
    TimedOut,
    TooLong,
    IoErr,
}

fn read_next_line(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    consumed: &mut usize,
    is_keepalive_wait: bool,
) -> LineStatus {
    if *consumed > 0 {
        if *consumed >= buf.len() {
            buf.clear();
        } else {
            buf.copy_within(*consumed.., 0);
            buf.truncate(buf.len() - *consumed);
        }
        *consumed = 0;
    }

    if let Some(nl) = buf.iter().position(|&b| b == b'\n') {
        let line_end = nl + 1;
        if line_end > MAX_LINE_BYTES {
            return LineStatus::TooLong;
        }
        *consumed = line_end;
        return LineStatus::Line(line_end);
    }
    if buf.len() > MAX_LINE_BYTES {
        return LineStatus::TooLong;
    }

    let mut tmp = [0u8; 4096];
    let mut switched_timeout = false;
    if is_keepalive_wait && !buf.is_empty() {
        let _ = stream.set_read_timeout(Some(INITIAL_READ_TIMEOUT));
        switched_timeout = true;
    }
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => {
                if buf.is_empty() {
                    return LineStatus::Eof;
                }
                if buf.len() > MAX_LINE_BYTES {
                    return LineStatus::TooLong;
                }
                let line_end = buf.len();
                *consumed = line_end;
                return LineStatus::Line(line_end);
            }
            Ok(n) => {
                let prev_len = buf.len();
                if let Some(rel_nl) = tmp[..n].iter().position(|&b| b == b'\n') {
                    let line_end = prev_len + rel_nl + 1;
                    if line_end > MAX_LINE_BYTES {
                        return LineStatus::TooLong;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    *consumed = line_end;
                    return LineStatus::Line(line_end);
                }
                if prev_len + n > MAX_LINE_BYTES {
                    return LineStatus::TooLong;
                }
                buf.extend_from_slice(&tmp[..n]);
                if is_keepalive_wait && !switched_timeout {
                    let _ = stream.set_read_timeout(Some(INITIAL_READ_TIMEOUT));
                    switched_timeout = true;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return LineStatus::TimedOut;
            }
            Err(_) => return LineStatus::IoErr,
        }
    }
}

pub fn run_daemon_forever() -> Result<(), String> {
    if let Some(info) = read_daemon_info() {
        if !matches!(
            try_send_fresh(&info, &Json::obj(vec![("op", Json::Str("ping".to_string()))])),
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
            fn listen(sockfd: i32, backlog: i32) -> i32;
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
    let queue = Arc::new(AcceptQueue::new());
    let keepalive_waiters = Arc::new(AtomicUsize::new(0));

    // Spawn bounded pool of 64 worker threads with reusable 8 KiB read buffers.
    for _ in 0..WORKER_THREADS {
        let q = Arc::clone(&queue);
        let svc = Arc::clone(&service);
        let tok = token.clone();
        let waiters = Arc::clone(&keepalive_waiters);
        thread::spawn(move || {
            let mut read_buf = Vec::with_capacity(WORKER_BUF_CAP);
            loop {
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
                    let popped = guard.pop_front();
                    if popped.is_some() {
                        q.queued_count.fetch_sub(1, Ordering::Relaxed);
                    }
                    popped
                };
                if let Some(stream) = stream_opt {
                    handle_client(stream, &svc, &tok, &q, &waiters, &mut read_buf, true);
                    read_buf.clear();
                    if read_buf.capacity() > WORKER_BUF_CAP {
                        read_buf.shrink_to(WORKER_BUF_CAP);
                    }
                }
            }
        });
    }

    // Background periodic metadata-only snapshot saver, 4h idle reaper, and ETag auto-patch updater
    let bg_svc = Arc::clone(&service);
    let bg_queue = Arc::clone(&queue);
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
        if crate::install::update::daemon_housekeeping_update_tick() {
            bg_svc.shutting_down.store(true, Ordering::Release);
            bg_queue.cv.notify_all();
            let _ = bg_svc.store.save_snapshot_if_dirty(true);
            let _ = fs::remove_file(&info_file);
            thread::sleep(Duration::from_millis(250));
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
                    queue.queued_count.fetch_add(1, Ordering::Relaxed);
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
    svc: &Arc<BrokerService>,
    expected_token: &str,
    queue: &AcceptQueue,
    keepalive_waiters: &AtomicUsize,
    read_buf: &mut Vec<u8>,
    exit_on_shutdown: bool,
) {
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    read_buf.clear();
    let mut consumed = 0usize;
    let mut requests_on_conn = 0usize;

    loop {
        let keepalive_guard = if requests_on_conn == 0 {
            let _ = stream.set_read_timeout(Some(INITIAL_READ_TIMEOUT));
            None
        } else {
            if svc.shutting_down.load(Ordering::Relaxed)
                || queue.queued_count.load(Ordering::Relaxed) > 0
                || requests_on_conn >= MAX_KEEPALIVE_REQUESTS
            {
                return;
            }
            let Some(guard) = KeepAliveGuard::try_acquire(keepalive_waiters) else {
                return;
            };
            if svc.shutting_down.load(Ordering::Relaxed)
                || queue.queued_count.load(Ordering::Relaxed) > 0
            {
                return;
            }
            let _ = stream.set_read_timeout(Some(KEEPALIVE_READ_TIMEOUT));
            Some(guard)
        };

        let line_end = match read_next_line(
            &mut stream,
            read_buf,
            &mut consumed,
            requests_on_conn > 0,
        ) {
            LineStatus::Line(end) => end,
            LineStatus::Eof | LineStatus::TimedOut | LineStatus::TooLong | LineStatus::IoErr => {
                return;
            }
        };

        // Release keep-alive slot immediately before parsing/executing the request.
        drop(keepalive_guard);

        let Ok(line_str) = std::str::from_utf8(&read_buf[..line_end]) else {
            return;
        };
        let Ok(req) = json::parse(line_str.trim()) else {
            return;
        };
        if req.get_str("token") != Some(expected_token) {
            let err = Json::obj(vec![
                ("ok", Json::Bool(false)),
                ("error", Json::Str("unauthorized".to_string())),
            ]);
            let mut out = err.to_json_string();
            out.push('\n');
            let _ = stream.write_all(out.as_bytes());
            let _ = stream.flush();
            return;
        }

        if req.get_str("op") == Some("shutdown") {
            svc.shutting_down.store(true, Ordering::Relaxed);
            queue.cv.notify_all();
            let _ = svc.store.save_snapshot_if_dirty(true);
            let _ = fs::remove_file(daemon_info_path());
            let ok = Json::obj(vec![("ok", Json::Bool(true))]).to_json_string() + "\n";
            let _ = stream.write_all(ok.as_bytes());
            let _ = stream.flush();
            if exit_on_shutdown {
                std::process::exit(0);
            }
            return;
        }

        let reply = super::execute_request_arc(svc, &req);
        let mut out = reply.to_json_string();
        out.push('\n');
        if stream.write_all(out.as_bytes()).is_err() || stream.flush().is_err() {
            return;
        }
        requests_on_conn += 1;
    }
}

#[cfg(test)]
pub(super) fn handle_client_for_test(
    stream: TcpStream,
    svc: &Arc<BrokerService>,
    expected_token: &str,
    queue: &AcceptQueue,
    keepalive_waiters: &AtomicUsize,
    read_buf: &mut Vec<u8>,
) {
    handle_client(
        stream,
        svc,
        expected_token,
        queue,
        keepalive_waiters,
        read_buf,
        false,
    );
}
