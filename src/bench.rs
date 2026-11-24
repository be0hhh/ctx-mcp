//! Built-in concurrency and latency load benchmark (`ctx bench`):
//! Spawns an isolated `ctx daemon` and drives waves of `1, 10, 50, 100, 200`
//! simultaneous agent threads across TCP IPC (`outline`, `symbols`, `read`, `memo`,
//! `hook agy`, Codex capsule launch and claim), reporting latency, throughput,
//! cache hits, isolation errors, and capsule delivery outcomes.

use crate::json::{self, Json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

struct BenchGuard {
    root: PathBuf,
    daemon: Option<Child>,
    port: u16,
    token: String,
}

impl Drop for BenchGuard {
    fn drop(&mut self) {
        if self.port != 0 && !self.token.is_empty() {
            let _ = send_bench_rpc(
                self.port,
                &self.token,
                &Json::obj(vec![("op", Json::Str("shutdown".to_string()))]),
            );
        }
        if let Some(ref mut child) = self.daemon {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn send_bench_rpc(port: u16, token: &str, req: &Json) -> Result<Json, String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    for attempt in 0..4 {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(mut stream) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let mut fields = match req {
                    Json::Obj(items) => items.clone(),
                    _ => Vec::new(),
                };
                fields.push(("token".to_string(), Json::Str(token.to_string())));
                let mut line = Json::Obj(fields).to_json_string();
                line.push('\n');
                stream
                    .write_all(line.as_bytes())
                    .map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
                let mut reader = BufReader::new(stream);
                let mut resp = String::new();
                reader.read_line(&mut resp).map_err(|e| e.to_string())?;
                return json::parse(resp.trim());
            }
            Err(e) => {
                if attempt == 3 {
                    return Err(e.to_string());
                }
                thread::sleep(Duration::from_millis(8));
            }
        }
    }
    Err("bench RPC exhausted retries".to_string())
}

enum CapsuleOutcome {
    Success,
    Misdelivery,
    Miss,
    Busy,
    RpcError,
}

#[derive(Default)]
struct CapsuleResults {
    success: usize,
    misdelivery: usize,
    miss: usize,
    busy: usize,
}

fn capsule_reply(reply: &Json) -> Result<(), CapsuleOutcome> {
    if reply.get_str("code") == Some("daemon_busy") {
        return Err(CapsuleOutcome::Busy);
    }
    if reply.get_bool("ok") != Some(true) {
        return Err(CapsuleOutcome::Miss);
    }
    if reply
        .get("hook_reply")
        .and_then(|hook| hook.get_str("systemMessage"))
        .is_some_and(|notice| {
            notice.starts_with("[RAM-Ctx] capsule registry full")
                || notice.starts_with("[RAM-Ctx] ctx host context busy")
        })
    {
        return Err(CapsuleOutcome::Busy);
    }
    Ok(())
}

fn codex_updated_input(reply: &Json) -> Option<&Json> {
    reply.get("hook_reply")?.get("hookSpecificOutput")?.get("updatedInput")
}

fn bench_capsule(
    port: u16,
    token: &str,
    cwd: &str,
    session: &str,
    launch: &str,
    brief: &str,
    claims_ready: &Barrier,
) -> CapsuleOutcome {
    let send = |req: &Json| -> Result<Json, CapsuleOutcome> {
        let reply = send_bench_rpc(port, token, req).map_err(|_| CapsuleOutcome::RpcError)?;
        capsule_reply(&reply)?;
        Ok(reply)
    };
    let hook = |event: &str, tool: &str, fields: Vec<(&'static str, Json)>| {
        let mut payload = vec![
            ("hook_event_name", Json::Str(event.into())),
            ("session_id", Json::Str(session.into())),
            ("cwd", Json::Str(cwd.into())),
            ("tool_name", Json::Str(tool.into())),
        ];
        payload.extend(fields);
        send(&Json::obj(vec![
            ("op", Json::Str("hook".into())),
            ("flavor", Json::Str("codex".into())),
            ("payload", Json::Str(Json::obj(payload).to_json_string())),
        ]))
    };
    let call_id = format!("spawn-{launch}");
    let child_id = format!("child-{launch}");
    let staged = (|| {
        let rewrite = hook("PreToolUse", "spawn_agent", vec![
            ("tool_use_id", Json::Str(call_id.clone())),
            ("tool_input", Json::obj(vec![
                ("agent_type", Json::Str("researcher".into())),
                ("message", Json::Str(brief.into())),
            ])),
        ])?;
        let message = codex_updated_input(&rewrite)
            .and_then(|input| input.get_str("message"))
            .ok_or(CapsuleOutcome::Miss)?;
        let key = message.lines().last()
            .and_then(|line| line.strip_prefix("CTX_CAPSULE_KEY="))
            .filter(|key| !key.is_empty())
            .ok_or(CapsuleOutcome::Miss)?;
        if !message.strip_prefix(brief).is_some_and(|tail| tail.starts_with("\n\n")) {
            return Err(CapsuleOutcome::Misdelivery);
        }

        hook("PostToolUse", "spawn_agent", vec![
            ("tool_use_id", Json::Str(call_id)),
            ("tool_response", Json::obj(vec![("agent_id", Json::Str(child_id.clone()))])),
        ])?;
        Ok(key.to_string())
    })();

    // Keep all successful launches pending together. Failed launches also reach this barrier.
    claims_ready.wait();

    let claim = (|| {
        let key = staged?;
        let pre_claim = hook("PreToolUse", "mcp__agent_ctx__ctx_capsule", vec![
            ("agent_id", Json::Str(child_id)),
            ("tool_input", Json::obj(vec![
                ("action", Json::Str("claim".into())),
                ("key", Json::Str(key.clone())),
            ])),
        ])?;
        let ticket = codex_updated_input(&pre_claim)
            .and_then(|input| input.get_str("ctx_context"))
            .ok_or(CapsuleOutcome::Miss)?;
        send(&Json::obj(vec![
            ("op", Json::Str("capsule".into())),
            ("action", Json::Str("claim".into())),
            ("key", Json::Str(key)),
            ("ctx_context", Json::Str(ticket.into())),
        ]))
    })();
    match claim {
        Ok(reply) => match reply.get_str("text") {
            Some(text) if text == brief => CapsuleOutcome::Success,
            Some(_) => CapsuleOutcome::Misdelivery,
            None => CapsuleOutcome::Miss,
        },
        Err(outcome) => outcome,
    }
}

fn populate_bench_workspace(ws: &PathBuf) -> Result<Vec<PathBuf>, String> {
    fs::create_dir_all(ws.join(".git")).map_err(|e| e.to_string())?;
    let src_dir = ws.join("src").join("Runtime");
    fs::create_dir_all(&src_dir).map_err(|e| e.to_string())?;

    let mut files = Vec::new();
    for idx in 0..16usize {
        let fp = src_dir.join(format!("BenchModule_{}.hpp", idx));
        let mut body = String::with_capacity(16 * 1024);
        body.push_str("#pragma once\n#include <cstdint>\nnamespace ctx_bench::fixture {\n");
        body.push_str(&format!("struct ModuleState_{} {{\n", idx));
        for ln in 0..320usize {
            body.push_str(&format!(
                "  std::int64_t metric_{}_{} = {};\n",
                idx,
                ln,
                (idx * 1000 + ln)
            ));
        }
        body.push_str(&format!(
            "  constexpr std::int64_t computeFast_{}(std::int64_t v) const noexcept {{\n    return (v << 1) + {};\n  }}\n}};\n}} // namespace ctx_bench::fixture\n",
            idx, idx
        ));
        fs::write(&fp, body).map_err(|e| e.to_string())?;
        files.push(fp);
    }
    Ok(files)
}

pub fn run_bench_cli(args: &[String]) -> i32 {
    let mut agent_levels: Vec<usize> = vec![1, 10, 50, 100, 200];
    let mut ops_per_agent: usize = 20;
    let mut as_json = false;
    let mut extended = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => as_json = true,
            "--extended" => extended = true,
            "--ops" if i + 1 < args.len() => {
                i += 1;
                if let Ok(v) = args[i].parse::<usize>() {
                    ops_per_agent = v.clamp(4, 500);
                }
            }
            "--agents" if i + 1 < args.len() => {
                i += 1;
                let parsed: Vec<usize> = args[i]
                    .split(',')
                    .filter_map(|s| s.trim().parse::<usize>().ok())
                    .filter(|&n| (1..=512).contains(&n))
                    .collect();
                if !parsed.is_empty() {
                    agent_levels = parsed;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let root = std::env::temp_dir().join(format!("ctx-bench-{}", std::process::id()));
    let ws = root.join("workspace");
    let rt = root.join("runtime");
    let snap = root.join("snapshot.bin");
    let _ = fs::remove_dir_all(&root);
    if let Err(e) = fs::create_dir_all(&rt) {
        eprintln!("ctx bench setup error: {}", e);
        return 1;
    }

    let files = match populate_bench_workspace(&ws) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ctx bench workspace error: {}", e);
            return 1;
        }
    };

    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("ctx bench current_exe error: {}", e);
            return 1;
        }
    };

    let child = match Command::new(&exe)
        .arg("daemon")
        .env("AGENT_CTX_RUNTIME_DIR", &rt)
        .env("AGENT_CTX_SNAPSHOT_PATH", &snap)
        .env("AGENT_CTX_MAX_RAM_MB", "512")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ctx bench daemon spawn error: {}", e);
            return 1;
        }
    };

    let mut guard = BenchGuard {
        root: root.clone(),
        daemon: Some(child),
        port: 0,
        token: String::new(),
    };

    let info_path = rt.join("daemon.json");
    for _ in 0..50 {
        if let Ok(txt) = fs::read_to_string(&info_path) {
            if let Ok(parsed) = json::parse(&txt) {
                if let (Some(p), Some(tok)) = (parsed.get_usize("port"), parsed.get_str("token")) {
                    guard.port = p as u16;
                    guard.token = tok.to_string();
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(15));
    }
    if guard.port == 0 {
        eprintln!("ctx bench error: isolated daemon did not publish daemon.json");
        return 1;
    }

    let port = guard.port;
    let token = Arc::new(guard.token.clone());
    let ws_str = Arc::new(ws.to_string_lossy().into_owned());
    let file_strs: Arc<Vec<String>> =
        Arc::new(files.iter().map(|p| p.to_string_lossy().into_owned()).collect());

    // Warm up initial file parse so waves measure realistic concurrent broker + cache traffic
    let _ = send_bench_rpc(
        port,
        &token,
        &Json::obj(vec![
            ("op", Json::Str("outline".to_string())),
            ("cwd", Json::Str((*ws_str).clone())),
            (
                "paths",
                Json::Arr(file_strs.iter().map(|s| Json::Str(s.clone())).collect()),
            ),
        ]),
    );

    if !as_json {
        println!(
            "ctx bench (32 worker threads, 64 cache shards, {} ops/agent, competing same-role capsules):",
            ops_per_agent
        );
        println!(
            "{:>8} | {:>10} | {:>11} | {:>8} | {:>8} | {:>8} | {:>9} | {:>9} | {:>8} | {:>11} | {:>8} | {:>8}",
            "agents", "total_ops", "ops/sec", "p50_us", "p95_us", "p99_us", "hit_rate", "iso_errs",
            "cap_ok", "cap_wrong", "cap_miss", "cap_busy"
        );
        println!("{}", "-".repeat(139));
    }

    let mut wave_results: Vec<Json> = Vec::new();
    let mut total_errors = 0usize;

    for (wave_id, &n_agents) in agent_levels.iter().enumerate() {
        let barrier = Arc::new(Barrier::new(n_agents));
        let mut handles = Vec::with_capacity(n_agents);
        let wave_start = Instant::now();

        for agent_id in 0..n_agents {
            let bar = Arc::clone(&barrier);
            let tok = Arc::clone(&token);
            let cwd_s = Arc::clone(&ws_str);
            let f_list = Arc::clone(&file_strs);

            handles.push(thread::spawn(move || {
                let mut lats = Vec::with_capacity(ops_per_agent);
                let mut errs = 0usize;
                let mut iso_errs = 0usize;
                let mut search_busy = 0usize;
                let mut capsule_outcome = CapsuleOutcome::Miss;
                let launch = format!("w{wave_id}-a{agent_id}");
                let conv_id = format!("bench-{launch}");
                let parent_sess = format!("cx-parent-w{wave_id}");
                let my_file_idx = agent_id & 15;
                let my_file = &f_list[my_file_idx];

                bar.wait();

                for step in 0..ops_per_agent {
                    if step == 3 {
                        bar.wait();
                        let t0 = Instant::now();
                        let brief = format!(
                            "Inspect the struct spans in src/Runtime/BenchModule_{my_file_idx}.hpp. \
                             Report the outcome, evidence, and scope for launch {launch}."
                        );
                        capsule_outcome = bench_capsule(
                            port,
                            &tok,
                            &cwd_s,
                            &parent_sess,
                            &launch,
                            &brief,
                            &bar,
                        );
                        lats.push(t0.elapsed().as_micros() as u64);
                        continue;
                    }
                    let t0 = Instant::now();
                    let kind = step & 3;
                    let req = if step == 5 {
                        bar.wait();
                        Json::obj(vec![
                            ("op", Json::Str("search".into())),
                            ("cwd", Json::Str((*cwd_s).clone())),
                            ("query", Json::Str("computeFast_".into())),
                            ("max_results", Json::Int(12)),
                        ])
                    } else if extended && step == 6 {
                        Json::obj(vec![
                            ("op", Json::Str("inspect".to_string())),
                            ("cwd", Json::Str((*cwd_s).clone())),
                            ("paths", Json::Arr(vec![Json::Str("src/Runtime".to_string())])),
                            ("max_files", Json::Int(20)),
                        ])
                    } else if extended && step == 7 {
                        Json::obj(vec![
                            ("op", Json::Str("search".to_string())),
                            ("cwd", Json::Str((*cwd_s).clone())),
                            (
                                "queries",
                                Json::Arr(vec![
                                    Json::obj(vec![
                                        ("query", Json::Str("computeFast_0".to_string())),
                                        ("roots", Json::Arr(vec![Json::Str("src/Runtime".to_string())])),
                                    ]),
                                    Json::obj(vec![
                                        ("query", Json::Str("ModuleState_1".to_string())),
                                        ("roots", Json::Arr(vec![Json::Str("BenchModule_1.hpp".to_string())])),
                                    ]),
                                ]),
                            ),
                        ])
                    } else { match kind {
                        0 => Json::obj(vec![
                            ("op", Json::Str("outline".to_string())),
                            ("cwd", Json::Str((*cwd_s).clone())),
                            ("paths", Json::Arr(vec![Json::Str(my_file.clone())])),
                        ]),
                        1 => Json::obj(vec![
                            ("op", Json::Str("symbols".to_string())),
                            ("cwd", Json::Str((*cwd_s).clone())),
                            (
                                "requests",
                                Json::Arr(vec![Json::Str(format!(
                                    "{}#computeFast_{}",
                                    my_file, my_file_idx
                                ))]),
                            ),
                        ]),
                        2 => {
                            if step == 2 {
                                // First read_file in this agent's isolated conversation MUST NOT be denied
                                // even though sibling agents already read the exact same file!
                                let hook_payload = Json::obj(vec![
                                    ("hookEventName", Json::Str("PreToolUse".to_string())),
                                    ("conversationId", Json::Str(conv_id.clone())),
                                    ("cwd", Json::Str((*cwd_s).clone())),
                                    (
                                        "toolCall",
                                        Json::obj(vec![
                                            ("id", Json::Str(format!("c-{}", step))),
                                            ("name", Json::Str("read_file".to_string())),
                                            (
                                                "args",
                                                Json::obj(vec![(
                                                    "Path",
                                                    Json::Str(my_file.clone()),
                                                )]),
                                            ),
                                        ]),
                                    ),
                                ]);
                                Json::obj(vec![
                                    ("op", Json::Str("hook".to_string())),
                                    ("flavor", Json::Str("agy".to_string())),
                                    ("payload", Json::Str(hook_payload.to_json_string())),
                                ])
                            } else {
                                Json::obj(vec![
                                    ("op", Json::Str("memo".to_string())),
                                    ("cwd", Json::Str((*cwd_s).clone())),
                                    ("action", Json::Str("list".to_string())),
                                ])
                            }
                        }
                        _ => Json::obj(vec![
                            ("op", Json::Str("read".to_string())),
                            ("cwd", Json::Str((*cwd_s).clone())),
                            ("force", Json::Bool(true)),
                            (
                                "paths",
                                Json::Arr(vec![Json::Str(format!("{}:1-120", my_file))]),
                            ),
                        ]),
                    } };

                    match send_bench_rpc(port, &tok, &req) {
                        Ok(rep) => {
                            let search_busy_reply = matches!(rep.get_str("code"), Some("search_busy" | "daemon_busy"))
                                || rep.get_str("text").is_some_and(|text| text.lines().any(|line| line == "Error: search busy"));
                            if (step == 5 || step == 7) && search_busy_reply {
                                search_busy += 1;
                                lats.push(t0.elapsed().as_micros() as u64);
                                continue;
                            }
                            if rep.get_bool("ok") != Some(true)
                                || rep.get_bool("degraded_inproc") == Some(true)
                            {
                                errs += 1;
                            } else if step == 2 {
                                if let Some(hr) = rep.get("hook_reply") {
                                    if hr.get_str("decision") == Some("deny") {
                                        iso_errs += 1;
                                    }
                                }
                            }
                        }
                        Err(_) => errs += 1,
                    }
                    lats.push(t0.elapsed().as_micros() as u64);
                }
                (lats, errs, iso_errs, capsule_outcome, search_busy)
            }));
        }

        let mut all_lats = Vec::with_capacity(n_agents * ops_per_agent);
        let mut wave_errs = 0usize;
        let mut wave_iso_errs = 0usize;
        let mut wave_search_busy = 0usize;
        let mut capsules = CapsuleResults::default();
        for h in handles {
            if let Ok((mut l, e, ie, capsule, search_busy)) = h.join() {
                all_lats.append(&mut l);
                wave_errs += e;
                wave_iso_errs += ie;
                wave_search_busy += search_busy;
                match capsule {
                    CapsuleOutcome::Success => capsules.success += 1,
                    CapsuleOutcome::Misdelivery => capsules.misdelivery += 1,
                    CapsuleOutcome::Miss => capsules.miss += 1,
                    CapsuleOutcome::Busy => capsules.busy += 1,
                    CapsuleOutcome::RpcError => {
                        wave_errs += 1;
                        capsules.miss += 1;
                    }
                }
            } else {
                wave_errs += 1;
                capsules.miss += 1;
            }
        }
        let elapsed_ns = wave_start.elapsed().as_nanos().max(1);
        all_lats.sort_unstable();
        let total_ops = all_lats.len();
        let p50 = percentile(&all_lats, 50);
        let p95 = percentile(&all_lats, 95);
        let p99 = percentile(&all_lats, 99);
        // Necessary reporting quotient over runtime wall-clock ns (zero-guarded above).
        let ops_sec = ((total_ops as u128 * 1_000_000_000u128) / elapsed_ns) as u64;

        let st = send_bench_rpc(
            port,
            &token,
            &Json::obj(vec![("op", Json::Str("status".to_string()))]),
        )
        .ok()
        .and_then(|r| r.get("status").cloned())
        .unwrap_or(Json::Null);
        let hits = st.get_i64("cache_hits").unwrap_or(0).max(0) as u64;
        let misses = st.get_i64("cache_misses").unwrap_or(0).max(0) as u64;
        let total_lookups = hits + misses;
        // Necessary reporting permille quotient (zero-guarded; formatted with fixed /10, %10).
        let hit_permille = if total_lookups > 0 {
            (hits * 1_000) / total_lookups
        } else {
            1_000
        };
        let hit_label = format!("{}.{}%", hit_permille / 10, hit_permille % 10);

        let wave_cap_errs = capsules.misdelivery + capsules.miss + capsules.busy;
        total_errors += wave_errs + wave_iso_errs + wave_cap_errs;
        if !as_json {
            println!(
                "{:>8} | {:>10} | {:>11} | {:>8} | {:>8} | {:>8} | {:>9} | {:>9} | {:>8} | {:>11} | {:>8} | {:>8}",
                n_agents, total_ops, ops_sec, p50, p95, p99, hit_label, wave_iso_errs,
                capsules.success, capsules.misdelivery, capsules.miss, capsules.busy
            );
        }
        wave_results.push(Json::obj(vec![
            ("agents", Json::Int(n_agents as i64)),
            ("total_ops", Json::Int(total_ops as i64)),
            ("ops_per_sec", Json::Int(ops_sec as i64)),
            ("p50_us", Json::Int(p50 as i64)),
            ("p95_us", Json::Int(p95 as i64)),
            ("p99_us", Json::Int(p99 as i64)),
            ("rpc_errors", Json::Int(wave_errs as i64)),
            ("isolation_errors", Json::Int(wave_iso_errs as i64)),
            ("capsule_errors", Json::Int(wave_cap_errs as i64)),
            ("capsule_success", Json::Int(capsules.success as i64)),
            ("capsule_misdelivery", Json::Int(capsules.misdelivery as i64)),
            ("capsule_miss", Json::Int(capsules.miss as i64)),
            ("capsule_busy", Json::Int(capsules.busy as i64)),
            ("search_busy", Json::Int(wave_search_busy as i64)),
            ("peak_subprocs", st.get("peak_subprocs").cloned().unwrap_or(Json::Int(0))),
        ]));
    }

    if as_json {
        println!(
            "{}",
            Json::obj(vec![
                ("ok", Json::Bool(total_errors == 0)),
                ("waves", Json::Arr(wave_results)),
            ])
            .to_json_string()
        );
    }
    if total_errors == 0 {
        0
    } else {
        1
    }
}

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct) / 100; // fixed power-of-ten scale (100)
    sorted[idx.min(sorted.len() - 1)]
}
