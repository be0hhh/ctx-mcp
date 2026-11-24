//! `ctx` — Single zero-dependency Rust Context Broker serving:
//!   1. `ctx daemon`                — Concurrent 32-thread / 64-shard <=4 GiB RAM broker + `0600` metadata-only snapshot
//!   2. `ctx inspect | read | outline | sym | search | memo | capsule | elf | status | clear` — Sub-ms CLI
//!   3. `ctx mcp [--repo-root DIR]` — Native Stdio MCP server (`agent_ctx`, 8 tools)
//!   4. `ctx hook <agy|codex|claude> [--global]` — Sub-ms per-agent lifecycle hook router
//!   5. `ctx install | doctor | bench` — Built-in cross-platform installer, diagnostics, and 200-agent load test

mod bench;
mod broker;
mod capsule;
mod engine;
mod hooks;
mod installer;
mod json;
mod mcp;
mod parser;
mod protocol;
mod security;
mod simd;
mod store;

use engine::DEFAULT_READ_MAX_BYTES;
use json::Json;
use protocol::{call_daemon_or_inproc, run_daemon_forever, workspace_cwd_str};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = dispatch(&args);
    std::process::exit(code);
}

fn dispatch(args: &[String]) -> i32 {
    let Some(cmd) = args.first().map(|s| s.as_str()) else {
        print_usage();
        return 2;
    };

    match cmd {
        "-h" | "--help" | "help" => {
            print_usage();
            0
        }
        "daemon" => match run_daemon_forever() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ctx daemon error: {}", e);
                1
            }
        },
        "install" => installer::run_install_cli(&args[1..]),
        "setup" => {
            let mut forwarded = vec!["--interactive".to_string()];
            forwarded.extend_from_slice(&args[1..]);
            installer::run_install_cli(&forwarded)
        }
        "uninstall" => installer::run_uninstall_cli(&args[1..]),
        "doctor" => installer::run_doctor_cli(&args[1..]),
        "serena" => match launch_serena(&args[1..]) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("ctx serena: {error}");
                1
            }
        },
        "bench" => bench::run_bench_cli(&args[1..]),
        "status" => {
            let reply =
                call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("status".to_string()))]));
            if let Some(st) = reply.get("status") {
                println!("{}", st.to_json_string());
            } else {
                println!("{}", reply.to_json_string());
            }
            0
        }
        "clear" => {
            let reply =
                call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("clear".to_string()))]));
            if let Some(txt) = reply.get_str("text") {
                println!("{}", txt);
            }
            0
        }
        "save-snapshot" => {
            let reply = call_daemon_or_inproc(Json::obj(vec![(
                "op",
                Json::Str("save_snapshot".to_string()),
            )]));
            if reply.get_bool("ok") == Some(true) {
                0
            } else {
                eprintln!(
                    "ctx save-snapshot error: {}",
                    reply.get_str("error").unwrap_or("failed")
                );
                1
            }
        }
        "shutdown" => {
            let _ =
                call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("shutdown".to_string()))]));
            0
        }
        "read" => {
            let mut max_bytes = DEFAULT_READ_MAX_BYTES as i64;
            let mut force = false;
            let mut session = std::env::var("AGENT_CTX_SESSION").ok().unwrap_or_default();
            let mut paths = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--force" | "-f" => force = true,
                    "--max-bytes" if i + 1 < args.len() => {
                        i += 1;
                        if let Ok(v) = args[i].parse::<i64>() {
                            max_bytes = v;
                        }
                    }
                    "--session" if i + 1 < args.len() => {
                        i += 1;
                        session = args[i].clone();
                    }
                    other => paths.push(Json::Str(other.to_string())),
                }
                i += 1;
            }
            let reply = call_daemon_or_inproc(Json::obj(vec![
                ("op", Json::Str("read".to_string())),
                ("cwd", Json::Str(workspace_cwd_str(None))),
                ("session", Json::Str(session)),
                ("force", Json::Bool(force)),
                ("max_bytes", Json::Int(max_bytes)),
                ("paths", Json::Arr(paths)),
            ]));
            print_reply(&reply)
        }
        "outline" => {
            let mut max_files: i64 = 40;
            let mut max_bytes: i64 = 0;
            let mut paths = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--max-files" && i + 1 < args.len() {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_files = v;
                    }
                } else if args[i] == "--max-bytes" && i + 1 < args.len() {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_bytes = v;
                    }
                } else {
                    paths.push(Json::Str(args[i].clone()));
                }
                i += 1;
            }
            let reply = call_daemon_or_inproc(Json::obj(vec![
                ("op", Json::Str("outline".to_string())),
                ("cwd", Json::Str(workspace_cwd_str(None))),
                ("max_files", Json::Int(max_files)),
                ("max_bytes", Json::Int(max_bytes)),
                ("paths", Json::Arr(paths)),
            ]));
            print_reply(&reply)
        }
        "inspect" => {
            let mut max_files: i64 = 80;
            let mut max_bytes = DEFAULT_READ_MAX_BYTES as i64;
            let mut warn_lines: i64 = 600;
            let mut paths = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--max-files" if i + 1 < args.len() => {
                        i += 1;
                        if let Ok(v) = args[i].parse::<i64>() {
                            max_files = v;
                        }
                    }
                    "--max-bytes" if i + 1 < args.len() => {
                        i += 1;
                        if let Ok(v) = args[i].parse::<i64>() {
                            max_bytes = v;
                        }
                    }
                    "--warn-lines" if i + 1 < args.len() => {
                        i += 1;
                        if let Ok(v) = args[i].parse::<i64>() {
                            warn_lines = v;
                        }
                    }
                    other => paths.push(Json::Str(other.to_string())),
                }
                i += 1;
            }
            let reply = call_daemon_or_inproc(Json::obj(vec![
                ("op", Json::Str("inspect".to_string())),
                ("cwd", Json::Str(workspace_cwd_str(None))),
                ("max_files", Json::Int(max_files)),
                ("max_bytes", Json::Int(max_bytes)),
                ("warn_lines", Json::Int(warn_lines)),
                ("paths", Json::Arr(paths)),
            ]));
            print_reply(&reply)
        }
        "capsule" => {
            let mut action = String::new();
            let mut key = String::new();
            let mut assignment = String::new();
            let mut workspace = String::from("inherit");
            let mut ctx_context: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--action" if i + 1 < args.len() => {
                        i += 1;
                        action = args[i].clone();
                    }
                    "--key" if i + 1 < args.len() => {
                        i += 1;
                        key = args[i].clone();
                    }
                    "--assignment" if i + 1 < args.len() => {
                        i += 1;
                        assignment = args[i].clone();
                    }
                    "--workspace" if i + 1 < args.len() => {
                        i += 1;
                        workspace = args[i].clone();
                    }
                    "--ctx-context" if i + 1 < args.len() => {
                        i += 1;
                        ctx_context = Some(args[i].clone());
                    }
                    other if action.is_empty() => action = other.to_string(),
                    other if key.is_empty() && action == "claim" => key = other.to_string(),
                    other if assignment.is_empty() && action == "prepare" => {
                        assignment = other.to_string()
                    }
                    _ => {}
                }
                i += 1;
            }
            if action.is_empty() {
                eprintln!("usage: ctx capsule claim <key> (via MCP tool agent_ctx ctx_capsule)");
                return 2;
            }
            let mut fields = vec![
                ("op", Json::Str("capsule".to_string())),
                ("action", Json::Str(action.clone())),
                ("workspace", Json::Str(workspace)),
            ];
            if !key.is_empty() {
                fields.push(("key", Json::Str(key.clone())));
            }
            if !assignment.is_empty() {
                fields.push(("assignment", Json::Str(assignment)));
            }
            if let Some(ticket) = ctx_context {
                fields.push(("ctx_context", Json::Str(ticket)));
            }
            let reply = call_daemon_or_inproc(Json::obj(fields));
            if reply.get_bool("ok") != Some(true) && reply.get_str("code") == Some("host_context") {
                let key_hint = if key.is_empty() { "<key>" } else { key.as_str() };
                eprintln!(
                    "ctx error [host_context]: capsule requires MCP tool call_mcp_tool(ServerName=\"agent_ctx\", ToolName=\"ctx_capsule\", Arguments={{\"action\":\"claim\",\"key\":\"{}\"}}) (or mcp__agent_ctx__ctx_capsule); otherwise use the assignment already in your prompt.",
                    key_hint
                );
                return 1;
            }
            print_reply(&reply)
        }
        "sym" | "symbols" => {
            let mut max_bytes = DEFAULT_READ_MAX_BYTES as i64;
            let mut compact = false;
            let mut reqs = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--max-bytes" && i + 1 < args.len() {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_bytes = v;
                    }
                } else if args[i] == "--compact" {
                    compact = true;
                } else {
                    reqs.push(Json::Str(args[i].clone()));
                }
                i += 1;
            }
            let reply = call_daemon_or_inproc(Json::obj(vec![
                ("op", Json::Str("symbols".to_string())),
                ("cwd", Json::Str(workspace_cwd_str(None))),
                ("max_bytes", Json::Int(max_bytes)),
                ("compact", Json::Bool(compact)),
                ("requests", Json::Arr(reqs)),
            ]));
            print_reply(&reply)
        }
        "search" => {
            if args.get(1).is_some_and(|arg| arg == "--batch-json") {
                let [_, _, payload] = args else {
                    eprintln!("usage: ctx search --batch-json '<array>'");
                    return 2;
                };
                let queries = match json::parse(payload) {
                    Ok(Json::Arr(items)) => Json::Arr(items),
                    _ => {
                        eprintln!("--batch-json expects a JSON array");
                        return 2;
                    }
                };
                let reply = call_daemon_or_inproc(Json::obj(vec![
                    ("op", Json::Str("search".to_string())),
                    ("cwd", Json::Str(workspace_cwd_str(None))),
                    ("queries", queries),
                ]));
                return print_reply(&reply);
            }
            let mut max_results: i64 = 40;
            let mut context_lines: i64 = 0;
            let mut detail: Option<String> = None;
            let mut q_specs: Vec<Json> = Vec::new();
            let mut pos = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if (args[i] == "-q" || args[i] == "--q") && i + 1 < args.len() {
                    i += 1;
                    q_specs.push(Json::Str(args[i].clone()));
                } else if args[i] == "--max-results" && i + 1 < args.len() {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_results = v;
                    }
                } else if args[i] == "--context-lines" && i + 1 < args.len() {
                    i += 1;
                    if let Ok(n) = args[i].parse::<i64>() {
                        context_lines = n;
                    }
                } else if args[i] == "--detail" && i + 1 < args.len() {
                    i += 1;
                    detail = Some(args[i].clone());
                } else {
                    pos.push(args[i].clone());
                }
                i += 1;
            }
            if !q_specs.is_empty() {
                if !pos.is_empty() {
                    eprintln!("usage: ctx search -q <root:query> [-q ...] (do not mix with positional query)");
                    return 2;
                }
                let reply = call_daemon_or_inproc(Json::obj(vec![
                    ("op", Json::Str("search".to_string())),
                    ("cwd", Json::Str(workspace_cwd_str(None))),
                    ("q", Json::Arr(q_specs)),
                ]));
                return print_reply(&reply);
            }
            let Some(query) = pos.first().cloned() else {
                eprintln!("usage: ctx search <query> [roots...]");
                return 2;
            };
            let effective_detail = detail.unwrap_or_else(|| {
                if context_lines > 0 {
                    "compact".to_string()
                } else {
                    "scopes".to_string()
                }
            });
            let roots: Vec<Json> = pos[1..].iter().map(|s| Json::Str(s.clone())).collect();
            let reply = call_daemon_or_inproc(Json::obj(vec![
                ("op", Json::Str("search".to_string())),
                ("cwd", Json::Str(workspace_cwd_str(None))),
                ("query", Json::Str(query)),
                ("roots", Json::Arr(roots)),
                ("max_results", Json::Int(max_results)),
                ("detail", Json::Str(effective_detail)),
                ("context_lines", Json::Int(context_lines)),
            ]));
            print_reply(&reply)
        }
        "memo" => {
            let action = args.get(1).map(|s| s.as_str()).unwrap_or("list");
            let mut topic = String::new();
            let mut summary = String::new();
            let mut kind = None;
            let mut paths = Vec::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--topic" | "-t" if i + 1 < args.len() => {
                        i += 1;
                        topic = args[i].clone();
                    }
                    "--summary" | "-s" if i + 1 < args.len() => {
                        i += 1;
                        summary = args[i].clone();
                    }
                    "--kind" if i + 1 < args.len() => {
                        i += 1;
                        kind = Some(args[i].clone());
                    }
                    "--author" | "-a" if i + 1 < args.len() => {
                        // Legacy callers may still supply a label; it is not provenance.
                        i += 1;
                    }
                    other => paths.push(Json::Str(other.to_string())),
                }
                i += 1;
            }
            let reply = call_daemon_or_inproc(Json::obj(vec![
                ("op", Json::Str("memo".to_string())),
                ("cwd", Json::Str(workspace_cwd_str(None))),
                ("action", Json::Str(action.to_string())),
                ("topic", Json::Str(topic)),
                ("summary", Json::Str(summary)),
                ("kind", kind.map(Json::Str).unwrap_or(Json::Null)),
                ("paths", Json::Arr(paths)),
            ]));
            print_reply(&reply)
        }
        "elf" | "elf-audit" => {
            let mut elf_path = String::new();
            let mut asm_path: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--elf" if i + 1 < args.len() => {
                        i += 1;
                        elf_path = args[i].clone();
                    }
                    "--asm" if i + 1 < args.len() => {
                        i += 1;
                        asm_path = Some(args[i].clone());
                    }
                    other if elf_path.is_empty() => elf_path = other.to_string(),
                    _ => {}
                }
                i += 1;
            }
            let reply = call_daemon_or_inproc(Json::obj(vec![
                ("op", Json::Str("elf_audit".to_string())),
                ("cwd", Json::Str(workspace_cwd_str(None))),
                ("elf_path", Json::Str(elf_path)),
                ("asm_path", asm_path.map(Json::Str).unwrap_or(Json::Null)),
            ]));
            print_reply(&reply)
        }
        "mcp" => {
            let mut repo_root: Option<PathBuf> = None;
            let mut check_only = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--repo-root" if i + 1 < args.len() => {
                        i += 1;
                        repo_root = Some(PathBuf::from(&args[i]));
                    }
                    "--protocol-check" => check_only = true,
                    _ => {}
                }
                i += 1;
            }
            if check_only {
                mcp::run_protocol_self_check(repo_root.as_deref())
            } else {
                mcp::run_mcp_stdio(repo_root.as_deref())
            }
        }
        "hook" => {
            let flavor = args.get(1).map(|s| s.as_str()).unwrap_or("agy");
            let is_global = args.iter().any(|a| a == "--global");
            let mut raw = Vec::with_capacity(4096);
            let _ = io::stdin().take(1_048_576).read_to_end(&mut raw);
            let raw_str = String::from_utf8_lossy(&raw);
            if raw_str.trim().is_empty() {
                println!("{{}}");
                return 0;
            }
            if is_global && hooks::should_skip_global_duplicate(flavor, &raw_str) {
                println!("{}", hooks::passthrough_raw(flavor, &raw_str).to_json_string());
                return 0;
            }
            let fallback_pre_tool =
                (flavor == "agy" || flavor == "antigravity") && raw_str.contains("\"PreToolUse\"");
            let reply = call_daemon_or_inproc(Json::obj(vec![
                ("op", Json::Str("hook".to_string())),
                ("flavor", Json::Str(flavor.to_string())),
                ("payload", Json::Str(raw_str.into_owned())),
            ]));
            if let Some(hr) = reply.get("hook_reply") {
                println!("{}", hr.to_json_string());
            } else if fallback_pre_tool {
                println!("{{\"decision\":\"allow\"}}");
            } else {
                println!("{{}}");
            }
            0
        }
        other => {
            eprintln!("ctx: unknown command `{}`", other);
            print_usage();
            2
        }
    }
}

fn print_reply(reply: &Json) -> i32 {
    if reply.get_bool("ok") == Some(true) {
        if let Some(txt) = reply.get_str("text") {
            print!("{}", txt);
            if !txt.ends_with('\n') {
                println!();
            }
        } else if let Some(items) = reply.get("memo").or_else(|| reply.get("memos")) {
            println!("{}", items.to_json_string());
        }
        0
    } else {
        let error = reply.get_str("error").unwrap_or("failed");
        if let Some(code) = reply.get_str("code") {
            eprintln!("ctx error [{code}]: {error}");
        } else {
            eprintln!("ctx error: {error}");
        }
        1
    }
}

fn launch_serena(args: &[String]) -> Result<i32, String> {
    let context_path = Path::new("agents/routing/SerenaContext.yml");
    let discover = |dir: &Path| {
        dir.canonicalize().ok()?.ancestors().find(|candidate| {
            candidate.join("agents/routing/AgentRouting.json").is_file()
                && candidate.join(context_path).is_file()
        }).map(Path::to_path_buf)
    };
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = match args {
        [] => discover(&cwd),
        [flag, dir] if flag == "--fallback-root" && !dir.is_empty() => {
            discover(&cwd).or_else(|| discover(Path::new(dir)))
        }
        _ => return Err("expected `ctx serena [--fallback-root DIR]`".into()),
    }.ok_or_else(|| format!("no CXETCPP Serena context for {}", cwd.display()))?;

    let mut command = std::process::Command::new("serena");
    command.current_dir(&root)
        .env("SERENA_HOME", root.join(".serena/home"))
        .arg("start-mcp-server")
        .arg("--project").arg(&root)
        .arg("--context").arg(root.join(context_path))
        .args(["--agent-interface", "tools", "--enable-web-dashboard", "false", "--enable-gui-log-window", "false",
            "--open-web-dashboard", "false", "--trace-lsp-communication", "false"]);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(format!("cannot start serena from PATH: {}", command.exec()))
    }
    #[cfg(not(unix))]
    {
        command.status().map(|status| status.code().unwrap_or(1))
            .map_err(|e| format!("cannot start serena from PATH: {e}"))
    }
}

fn print_usage() {
    eprintln!(
        "Usage: ctx <command> [args]\n\
         Commands:\n\
         \x20 ctx setup [--eager core|search|all|none]       Interactive harness scanner & installer\n\
         \x20 ctx install [--targets agy,claude,codex] [--eager core|search|all|none] [--no-wsl-bridge] [--check]\n\
         \x20 ctx uninstall [--targets agy,claude,codex] [--keep-binary]\n\
         \x20 ctx doctor [--json]\n\
         \x20 ctx bench [--agents 1,10,50,100,200] [--ops 20] [--json]\n\
         \x20 ctx inspect <file_or_dir...> [--max-files 80] [--max-bytes 1048576] [--warn-lines 600]\n\
         \x20 ctx read <path[:start-end]> [...] [--max-bytes 1048576] [--force]\n\
         \x20 ctx outline <file_or_dir...> [--max-files 40] [--max-bytes N]\n\
         \x20 ctx sym <ModOrPath#Symbol> [...] [--compact] [--max-bytes 1048576]\n\
         \x20 ctx search -q <ModOrDir:query> [-q ...]\n\
         \x20 ctx search <query> [roots...] [--max-results 40] [--context-lines 0] [--detail compact|scopes]\n\
         \x20 ctx search --batch-json '<array>'\n\
         \x20 ctx memo <put|get|list|clear> [--topic K] [--summary S] [--kind finding|observation] [paths...]\n\
         \x20 ctx capsule <claim|prepare> [key] [--assignment TEXT] [--workspace inherit|branch|share]\n\
         \x20 ctx elf <--elf path> [--asm path]\n\
         \x20 ctx status | clear | save-snapshot | shutdown\n\
         \x20 ctx mcp [--repo-root DIR] [--protocol-check]\n\
         \x20 ctx serena [--fallback-root DIR]\n\
         \x20 ctx hook <agy|codex|claude> [--global]"
    );
}
