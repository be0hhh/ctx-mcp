//! Top-level CLI command dispatcher for `ctx`.

pub mod diag;
pub mod search_args;

use crate::base::json::{self, Json};
use crate::base::mode::{current_write_mode, set_persisted_write_mode};
use crate::hooks::{passthrough_raw, should_skip_global_duplicate};
use crate::install;
use crate::mcp;
use crate::rpc::{call_daemon_or_inproc, run_daemon_forever, workspace_cwd_str};
use std::borrow::Cow;
use std::io::{self, Read};
use std::path::PathBuf;

fn cli_session_fields_from(
    explicit_session: Option<&str>,
    env_session: Option<&str>,
    env_token: Option<&str>,
) -> Vec<(&'static str, Json)> {
    let mut out = Vec::new();
    let env_s = env_session.map(str::trim).filter(|s| !s.is_empty());
    let explicit = explicit_session.map(str::trim).filter(|s| !s.is_empty());
    if let Some(s) = explicit.or(env_s) {
        out.push(("session", Json::Str(s.to_string())));
    }
    let attach_token = match (explicit, env_s) {
        (None, _) => true,
        (Some(exp), Some(env_val)) => exp == env_val,
        (Some(_), None) => false,
    };
    if attach_token {
        if let Some(tok) = env_token.map(str::trim).filter(|s| !s.is_empty()) {
            out.push(("cli_token", Json::Str(tok.to_string())));
        }
    }
    out
}

pub(super) fn cli_session_fields(explicit_session: Option<&str>) -> Vec<(&'static str, Json)> {
    let env_session = std::env::var("AGENT_CTX_SESSION").ok();
    let env_token = std::env::var("AGENT_CTX_CLI_TOKEN").ok();
    cli_session_fields_from(
        explicit_session,
        env_session.as_deref(),
        env_token.as_deref(),
    )
}

const READ_USAGE: &str = "Usage: ctx read <path[:start-end|s1-e1,s2-e2]> [...] [options]\n\
Options:\n\
  --force, -f           Bypass session dedup and delta output\n\
  --hashes              Prefix lines with 3-char edit hash anchors\n\
  --max-bytes <n>       Max output bytes (AGY CLI hard-clamped at 9200)\n\
  --session <id>        Session identifier\n\
  -h, --help            Show this help";

const INSPECT_USAGE: &str = "Usage: ctx inspect <file_or_dir...> [options]\n\
Options:\n\
  --max-files <n>       Max files to inspect (default: 80)\n\
  --warn-lines <n>      Line threshold for size warnings (default: 600)\n\
  --max-bytes <n>       Max output bytes\n\
  --session <id>        Session identifier\n\
  -h, --help            Show this help";

const OUTLINE_USAGE: &str = "Usage: ctx outline <file_or_dir...> [options]\n\
Options:\n\
  --max-files <n>       Max files to outline (default: 40)\n\
  --max-symbols <n>     Max symbols per file (0 = unlimited)\n\
  --max-bytes <n>       Max output bytes\n\
  --session <id>        Session identifier\n\
  -h, --help            Show this help";

const SYM_USAGE: &str = "Usage: ctx sym <ModOrPath#Symbol|path> [...] [options]\n\
Options:\n\
  --compact             Cap each symbol body preview to 48 lines\n\
  --hashes              Prefix lines with 3-char edit hash anchors\n\
  --raw                 Disable doc/config compaction\n\
  --max-bytes <n>       Max output bytes\n\
  --session <id>        Session identifier\n\
  -h, --help            Show this help";

const IMPACT_USAGE: &str = "Usage: ctx impact <ModOrPath#Symbol...> [options]\n\
Options:\n\
  --max-callers <n>     Max callers per target (default: 20)\n\
  --no-tests            Exclude test files from caller scan\n\
  --no-git              Omit git dirty-status annotations\n\
  --max-bytes <n>       Max output bytes\n\
  --session <id>        Session identifier\n\
  -h, --help            Show this help";

const EDIT_USAGE: &str = "Usage: ctx edit [--dry-run] [--session <id>] [--json '<payload>']\n\
Reads JSON edit payload from --json or stdin.\n\
Options:\n\
  --json <payload>      Inline JSON payload (edits/renames/creates/verify_absent)\n\
  --dry-run             Preview changes without writing to disk\n\
  --session <id>        Session identifier\n\
  -h, --help            Show this help";

const REFACTOR_USAGE: &str = "Usage: ctx refactor <old_name> <new_name> <paths...> [options]\n\
Options:\n\
  --apply               Apply renames to disk (default: dry-run preview)\n\
  --dry-run             Preview renames without writing\n\
  --session <id>        Session identifier\n\
  -h, --help            Show this help";

const MODE_USAGE: &str = "Usage: ctx mode [write|read-only]\n\
Show or update persisted write mode.\n\
Options:\n\
  -h, --help            Show this help";

const CAPSULE_USAGE: &str = "Usage: ctx capsule <claim|prepare> [key] [options]\n\
Options:\n\
  --action <act>        Action: claim or prepare\n\
  --key <key>           Capsule claim key\n\
  --assignment <text>   Assignment text for prepare\n\
  --workspace <mode>    Workspace mode: inherit | branch | share\n\
  --ctx-context <tok>   Host context ticket\n\
  -h, --help            Show this help";

const ELF_USAGE: &str = "Usage: ctx elf <--elf path> [--asm path] [--baseline-elf path] [--baseline-asm path]\n\
Options:\n\
  --elf <path>          Target ELF binary path\n\
  --asm <path>          Optional assembly listing path\n\
  --baseline-elf <path> Baseline ELF binary for comparison\n\
  --baseline-asm <path> Baseline assembly listing\n\
  -h, --help            Show this help";

const MCP_USAGE: &str = "Usage: ctx mcp [--repo-root DIR] [--read-only|--write] [--protocol-check]\n\
Options:\n\
  --repo-root <dir>     Workspace root directory\n\
  --read-only           Force read-only MCP mode\n\
  --write               Enable write tools in MCP mode\n\
  --protocol-check      Run MCP protocol self-check and exit\n\
  -h, --help            Show this help";

const HOOK_USAGE: &str = "Usage: ctx hook <agy|codex|claude> [--global]\n\
Reads host hook JSON event from stdin and writes response JSON to stdout.\n\
Options:\n\
  --global              Skip duplicate firing when project hook is present\n\
  -h, --help            Show this help";

const DIAG_USAGE: &str = "Usage: ctx diag [--file PATH] [--hashes] [--max-errors 15] [--context 2] [-- <cmd> [args...]]\n\
Deduplicates verbose compiler/test/log output or compacts large JSON.\n\
Options:\n\
  -h, --help            Show this help";

const INSTALL_USAGE: &str = "Usage: ctx install [--targets agy,claude,codex] [--all] [--eager core|search|all|none] [--no-wsl-bridge] [--no-codex-rules] [--check]\n\
Options:\n\
  -h, --help            Show this help";

const SETUP_USAGE: &str = "Usage: ctx setup [--eager core|search|all|none]\n\
Interactive harness scanner and installer.\n\
Options:\n\
  -h, --help            Show this help";

const UNINSTALL_USAGE: &str = "Usage: ctx uninstall [--targets agy,claude,codex] [--all] [--keep-binary] [--no-wsl-bridge]\n\
Options:\n\
  -h, --help            Show this help";

const DOCTOR_USAGE: &str = "Usage: ctx doctor [--json]\n\
Check daemon, binary, hooks, and MCP installation health.\n\
Options:\n\
  --json                Emit machine-readable JSON report\n\
  -h, --help            Show this help";

const UPDATE_USAGE: &str = "Usage: ctx update [--check] [--rebuild] [--force] [--auto [off|patch|all]] [--json]\n\
Options:\n\
  -h, --help            Show this help";

fn has_help_before_dd(args: &[String]) -> bool {
    for arg in args {
        if arg == "--" {
            break;
        }
        if matches!(arg.as_str(), "--help" | "-h") {
            return true;
        }
    }
    false
}

fn build_read_request(
    args: &[String],
    cwd: String,
    session_fields: Vec<(&'static str, Json)>,
) -> CliParse<Json> {
    let mut max_bytes: Option<i64> = None;
    let mut force = false;
    let mut hashes = false;
    let mut paths = Vec::new();
    let mut after_dd = false;
    let mut i = 0;
    while i < args.len() {
        if !after_dd {
            match args[i].as_str() {
                "--help" | "-h" => return CliParse::Help(READ_USAGE),
                "--" => {
                    after_dd = true;
                    i += 1;
                    continue;
                }
                "--force" | "-f" => force = true,
                "--hashes" => hashes = true,
                "--max-bytes" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_bytes = Some(v);
                    }
                }
                "--session" if i + 1 < args.len() => {
                    i += 1;
                }
                other => paths.push(Json::Str(other.to_string())),
            }
        } else {
            paths.push(Json::Str(args[i].clone()));
        }
        i += 1;
    }
    let mut fields = vec![
        ("op", Json::Str("read".to_string())),
        ("cwd", Json::Str(cwd)),
        ("force", Json::Bool(force)),
        ("hashes", Json::Bool(hashes)),
        ("paths", Json::Arr(paths)),
    ];
    if let Some(mb) = max_bytes {
        fields.push(("max_bytes", Json::Int(mb)));
    }
    fields.extend(session_fields);
    CliParse::Request(Json::obj(fields))
}

fn build_inspect_request(
    args: &[String],
    cwd: String,
    session_fields: Vec<(&'static str, Json)>,
) -> CliParse<Json> {
    let mut max_files: i64 = 80;
    let mut max_bytes: Option<i64> = None;
    let mut warn_lines: i64 = 600;
    let mut paths = Vec::new();
    let mut after_dd = false;
    let mut i = 0;
    while i < args.len() {
        if !after_dd {
            match args[i].as_str() {
                "--help" | "-h" => return CliParse::Help(INSPECT_USAGE),
                "--" => {
                    after_dd = true;
                    i += 1;
                    continue;
                }
                "--max-files" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_files = v;
                    }
                }
                "--max-bytes" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_bytes = Some(v);
                    }
                }
                "--warn-lines" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        warn_lines = v;
                    }
                }
                "--session" if i + 1 < args.len() => {
                    i += 1;
                }
                other => paths.push(Json::Str(other.to_string())),
            }
        } else {
            paths.push(Json::Str(args[i].clone()));
        }
        i += 1;
    }
    let mut fields = vec![
        ("op", Json::Str("inspect".to_string())),
        ("cwd", Json::Str(cwd)),
        ("max_files", Json::Int(max_files)),
        ("warn_lines", Json::Int(warn_lines)),
        ("paths", Json::Arr(paths)),
    ];
    if let Some(mb) = max_bytes {
        fields.push(("max_bytes", Json::Int(mb)));
    }
    fields.extend(session_fields);
    CliParse::Request(Json::obj(fields))
}

fn build_outline_request<F>(args: &[String], cwd: String, session_fields: F) -> CliParse<Json>
where
    F: FnOnce(Option<&str>) -> Vec<(&'static str, Json)>,
{
    let mut max_files: i64 = 40;
    let mut max_bytes: Option<i64> = None;
    let mut max_symbols: i64 = 0;
    let mut session: Option<String> = None;
    let mut paths = Vec::new();
    let mut after_dd = false;
    let mut i = 0;
    while i < args.len() {
        if !after_dd {
            match args[i].as_str() {
                "--help" | "-h" => return CliParse::Help(OUTLINE_USAGE),
                "--" => {
                    after_dd = true;
                    i += 1;
                    continue;
                }
                "--max-files" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_files = v;
                    }
                }
                "--max-bytes" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_bytes = Some(v);
                    }
                }
                "--max-symbols" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_symbols = v;
                    }
                }
                "--session" if i + 1 < args.len() => {
                    i += 1;
                    session = Some(args[i].clone());
                }
                other => paths.push(Json::Str(other.to_string())),
            }
        } else {
            paths.push(Json::Str(args[i].clone()));
        }
        i += 1;
    }
    let mut fields = vec![
        ("op", Json::Str("outline".to_string())),
        ("cwd", Json::Str(cwd)),
        ("max_files", Json::Int(max_files)),
        ("max_symbols", Json::Int(max_symbols)),
        ("paths", Json::Arr(paths)),
    ];
    if let Some(mb) = max_bytes {
        fields.push(("max_bytes", Json::Int(mb)));
    }
    fields.extend(session_fields(session.as_deref()));
    CliParse::Request(Json::obj(fields))
}

fn build_symbols_request(
    args: &[String],
    cwd: String,
    session_fields: Vec<(&'static str, Json)>,
) -> CliParse<Json> {
    let mut max_bytes: Option<i64> = None;
    let mut compact = false;
    let mut hashes = false;
    let mut raw = false;
    let mut reqs = Vec::new();
    let mut after_dd = false;
    let mut i = 0;
    while i < args.len() {
        if !after_dd {
            match args[i].as_str() {
                "--help" | "-h" => return CliParse::Help(SYM_USAGE),
                "--" => {
                    after_dd = true;
                    i += 1;
                    continue;
                }
                "--max-bytes" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_bytes = Some(v);
                    }
                }
                "--session" if i + 1 < args.len() => {
                    i += 1;
                }
                "--compact" => compact = true,
                "--hashes" => hashes = true,
                "--raw" => raw = true,
                other => reqs.push(Json::Str(other.to_string())),
            }
        } else {
            reqs.push(Json::Str(args[i].clone()));
        }
        i += 1;
    }
    let mut fields = vec![
        ("op", Json::Str("symbols".to_string())),
        ("cwd", Json::Str(cwd)),
        ("compact", Json::Bool(compact)),
        ("hashes", Json::Bool(hashes)),
        ("raw", Json::Bool(raw)),
        ("requests", Json::Arr(reqs)),
    ];
    if let Some(mb) = max_bytes {
        fields.push(("max_bytes", Json::Int(mb)));
    }
    fields.extend(session_fields);
    CliParse::Request(Json::obj(fields))
}

fn build_impact_request<F>(args: &[String], cwd: String, session_fields: F) -> CliParse<Json>
where
    F: FnOnce(Option<&str>) -> Vec<(&'static str, Json)>,
{
    let mut max_callers: i64 = 20;
    let mut max_bytes: Option<i64> = None;
    let mut include_tests = true;
    let mut include_git_status = true;
    let mut session: Option<String> = None;
    let mut targets = Vec::new();
    let mut after_dd = false;
    let mut i = 0;
    while i < args.len() {
        if !after_dd {
            match args[i].as_str() {
                "--help" | "-h" => return CliParse::Help(IMPACT_USAGE),
                "--" => {
                    after_dd = true;
                    i += 1;
                    continue;
                }
                "--max-callers" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_callers = v;
                    }
                }
                "--max-bytes" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_bytes = Some(v);
                    }
                }
                "--session" if i + 1 < args.len() => {
                    i += 1;
                    session = Some(args[i].clone());
                }
                "--no-tests" => include_tests = false,
                "--no-git" => include_git_status = false,
                other => targets.push(Json::Str(other.to_string())),
            }
        } else {
            targets.push(Json::Str(args[i].clone()));
        }
        i += 1;
    }
    let mut fields = vec![
        ("op", Json::Str("impact".to_string())),
        ("cwd", Json::Str(cwd)),
        ("targets", Json::Arr(targets)),
        ("max_callers", Json::Int(max_callers)),
        ("include_tests", Json::Bool(include_tests)),
        ("include_git_status", Json::Bool(include_git_status)),
    ];
    if let Some(mb) = max_bytes {
        fields.push(("max_bytes", Json::Int(mb)));
    }
    fields.extend(session_fields(session.as_deref()));
    CliParse::Request(Json::obj(fields))
}

fn build_refactor_request<F>(args: &[String], cwd: String, session_fields: F) -> CliParse<Json>
where
    F: FnOnce(Option<&str>) -> Vec<(&'static str, Json)>,
{
    let mut old_name = String::new();
    let mut new_name = String::new();
    let mut dry_run = true;
    let mut session: Option<String> = None;
    let mut paths = Vec::new();
    let mut after_dd = false;
    let mut i = 0;
    while i < args.len() {
        if !after_dd {
            match args[i].as_str() {
                "--help" | "-h" => return CliParse::Help(REFACTOR_USAGE),
                "--" => {
                    after_dd = true;
                    i += 1;
                    continue;
                }
                "--apply" => dry_run = false,
                "--dry-run" => dry_run = true,
                "--session" if i + 1 < args.len() => {
                    i += 1;
                    session = Some(args[i].clone());
                }
                other if old_name.is_empty() => old_name = other.to_string(),
                other if new_name.is_empty() => new_name = other.to_string(),
                other => paths.push(Json::Str(other.to_string())),
            }
        } else if old_name.is_empty() {
            old_name = args[i].clone();
        } else if new_name.is_empty() {
            new_name = args[i].clone();
        } else {
            paths.push(Json::Str(args[i].clone()));
        }
        i += 1;
    }
    let rename_spec = Json::obj(vec![
        ("old_name", Json::Str(old_name)),
        ("new_name", Json::Str(new_name)),
        ("paths", Json::Arr(paths)),
    ]);
    let mut fields = vec![
        ("op", Json::Str("edit".to_string())),
        ("cwd", Json::Str(cwd)),
        ("renames", Json::Arr(vec![rename_spec])),
        ("dry_run", Json::Bool(dry_run)),
    ];
    fields.extend(session_fields(session.as_deref()));
    CliParse::Request(Json::obj(fields))
}

fn run_cli_parse(parsed: CliParse<Json>) -> i32 {
    match parsed {
        CliParse::Help(usage) => {
            println!("{usage}");
            0
        }
        CliParse::Error(error) => {
            eprintln!("{error}");
            2
        }
        CliParse::Request(request) => {
            let reply = call_daemon_or_inproc(request);
            print_reply(&reply)
        }
    }
}

const GIT_USAGE: &str = "Usage: ctx git [diff|status|log|show] [options] [--] [paths...]\n\
Options:\n\
  --staged, --cached    Diff staged changes\n\
  --stat                Show diffstat summary only\n\
  --rev <ref>           Revision or range (required for show)\n\
  --symbol, -S <sym>    Filter log commits matching symbol\n\
  --limit, -n <n>       Max commits for log (default: 10)\n\
  --max-bytes <n>       Max output bytes (default: 8192)\n\
  --hashes/--no-hashes  Include/omit line hashes (default: on)\n\
  --session <id>        Session identifier\n\
  -h, --help            Show this help";

const MEMO_USAGE: &str = "Usage: ctx memo <action> [options] [paths...]\n\
Actions: put | get | list | clear | changes | pack | pack-get | packs\n\
Options:\n\
  --topic, -t <key>     Memo topic or pack name\n\
  --summary, -s <text>  Memo or pack summary\n\
  --kind <kind>         Optional memo kind\n\
  --since, --since-seq <n>  Start sequence for changes\n\
  --limit, -n <n>       Max events for changes (default: 30, 1..=200)\n\
  --max-bytes <n>       Max output bytes (pack-get / changes)\n\
  --force               Force full pack re-delivery\n\
  --raw                 Disable doc/config compaction\n\
  --session <id>        Session identifier\n\
  -h, --help            Show this help";

#[derive(Debug)]
enum CliParse<T> {
    Request(T),
    Help(&'static str),
    Error(String),
}

fn build_git_request<F>(args: &[String], cwd: String, session_fields: F) -> CliParse<Json>
where
    F: FnOnce(Option<&str>) -> Vec<(&'static str, Json)>,
{
    if matches!(args.first().map(String::as_str), Some("--help" | "-h" | "help")) {
        return CliParse::Help(GIT_USAGE);
    }
    let mut action = "diff".to_string();
    let mut rev: Option<String> = None;
    let mut staged = false;
    let mut stat = false;
    let mut hashes = true;
    let mut limit: i64 = 10;
    let mut max_bytes: i64 = 8192;
    let mut symbol: Option<String> = None;
    let mut session: Option<String> = None;
    let mut paths = Vec::new();
    let mut i = 0;
    if let Some(first) = args.first() {
        if matches!(first.as_str(), "diff" | "status" | "log" | "show") {
            action = first.clone();
            i = 1;
        }
    }
    let mut after_dd = false;
    while i < args.len() {
        if !after_dd {
            match args[i].as_str() {
                "--help" | "-h" => return CliParse::Help(GIT_USAGE),
                "--" => {
                    after_dd = true;
                    i += 1;
                    continue;
                }
                "--staged" | "--cached" => staged = true,
                "--stat" => stat = true,
                "--no-hashes" => hashes = false,
                "--hashes" => hashes = true,
                "--rev" => {
                    if i + 1 >= args.len() {
                        return CliParse::Error("ctx git: missing value for --rev".to_string());
                    }
                    i += 1;
                    rev = Some(args[i].clone());
                }
                "--symbol" | "-S" => {
                    if i + 1 >= args.len() {
                        return CliParse::Error(format!("ctx git: missing value for {}", args[i]));
                    }
                    i += 1;
                    symbol = Some(args[i].clone());
                }
                "--limit" | "-n" => {
                    if i + 1 >= args.len() {
                        return CliParse::Error(format!("ctx git: missing value for {}", args[i]));
                    }
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        limit = v;
                    }
                }
                "--max-bytes" => {
                    if i + 1 >= args.len() {
                        return CliParse::Error(
                            "ctx git: missing value for --max-bytes".to_string(),
                        );
                    }
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_bytes = v;
                    }
                }
                "--session" => {
                    if i + 1 >= args.len() {
                        return CliParse::Error("ctx git: missing value for --session".to_string());
                    }
                    i += 1;
                    session = Some(args[i].clone());
                }
                other if other.starts_with('-') => {
                    return CliParse::Error(format!(
                        "ctx git: unknown flag '{other}'; supported: --stat, --staged, --rev <ref>, --symbol <sym>, --limit <n>, --max-bytes <n>, [--] [paths...]"
                    ));
                }
                other => {
                    if action == "show" && rev.is_none() {
                        rev = Some(other.to_string());
                    } else {
                        paths.push(Json::Str(other.to_string()));
                    }
                }
            }
        } else {
            paths.push(Json::Str(args[i].clone()));
        }
        i += 1;
    }
    let mut fields = vec![
        ("op", Json::Str("git".to_string())),
        ("cwd", Json::Str(cwd)),
        ("action", Json::Str(action)),
        ("staged", Json::Bool(staged)),
        ("stat", Json::Bool(stat)),
        ("hashes", Json::Bool(hashes)),
        ("limit", Json::Int(limit)),
        ("max_bytes", Json::Int(max_bytes)),
        ("paths", Json::Arr(paths)),
    ];
    if let Some(r) = rev {
        fields.push(("rev", Json::Str(r)));
    }
    if let Some(s) = symbol {
        fields.push(("symbol", Json::Str(s)));
    }
    fields.extend(session_fields(session.as_deref()));
    CliParse::Request(Json::obj(fields))
}

fn build_memo_request<F>(args: &[String], cwd: String, session_fields: F) -> CliParse<Json>
where
    F: FnOnce(Option<&str>) -> Vec<(&'static str, Json)>,
{
    let raw_action = args.first().map(|s| s.as_str()).unwrap_or("list");
    if matches!(raw_action, "--help" | "-h" | "help") {
        return CliParse::Help(MEMO_USAGE);
    }
    let action = if raw_action == "pack-get" {
        "pack_get"
    } else {
        raw_action
    };
    let mut topic = String::new();
    let mut summary = String::new();
    let mut kind = None;
    let mut since_seq: Option<i64> = None;
    let mut limit: Option<i64> = None;
    let mut force = false;
    let mut raw = false;
    let mut max_bytes: Option<i64> = None;
    let mut session: Option<String> = None;
    let mut paths = Vec::new();
    let mut after_dd = false;
    let mut i = 1;
    while i < args.len() {
        if !after_dd {
            match args[i].as_str() {
                "--help" | "-h" => return CliParse::Help(MEMO_USAGE),
                "--" => {
                    after_dd = true;
                    i += 1;
                    continue;
                }
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
                "--since-seq" | "--since" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        since_seq = Some(v);
                    }
                }
                "--limit" | "-n" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        limit = Some(v);
                    }
                }
                "--max-bytes" if i + 1 < args.len() => {
                    i += 1;
                    if let Ok(v) = args[i].parse::<i64>() {
                        max_bytes = Some(v);
                    }
                }
                "--session" if i + 1 < args.len() => {
                    i += 1;
                    session = Some(args[i].clone());
                }
                "--force" => force = true,
                "--raw" => raw = true,
                "--author" | "-a" if i + 1 < args.len() => {
                    // Legacy callers may still supply a label; it is not provenance.
                    i += 1;
                }
                other => {
                    if matches!(action, "get" | "pack" | "pack_get") && topic.is_empty() {
                        topic = other.to_string();
                    } else {
                        paths.push(Json::Str(other.to_string()));
                    }
                }
            }
        } else {
            paths.push(Json::Str(args[i].clone()));
        }
        i += 1;
    }
    let mut fields = vec![
        ("op", Json::Str("memo".to_string())),
        ("cwd", Json::Str(cwd)),
        ("action", Json::Str(action.to_string())),
        ("topic", Json::Str(topic)),
        ("summary", Json::Str(summary)),
        ("kind", kind.map(Json::Str).unwrap_or(Json::Null)),
        ("paths", Json::Arr(paths)),
        ("force", Json::Bool(force)),
        ("raw", Json::Bool(raw)),
    ];
    if let Some(seq) = since_seq {
        fields.push(("since_seq", Json::Int(seq)));
    }
    if let Some(lim) = limit {
        fields.push(("limit", Json::Int(lim)));
    }
    if let Some(mb) = max_bytes {
        fields.push(("max_bytes", Json::Int(mb)));
    }
    fields.extend(session_fields(session.as_deref()));
    CliParse::Request(Json::obj(fields))
}

fn extract_cli_session_flag(args: &[String]) -> Option<&str> {
    let mut out = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--" {
            break;
        }
        if args[i] == "--session" && i + 1 < args.len() {
            i += 1;
            out = Some(args[i].as_str());
        }
        i += 1;
    }
    out
}

pub fn dispatch(args: &[String]) -> i32 {
    let Some(cmd) = args.first().map(|s| s.as_str()) else {
        print_usage();
        return 2;
    };

    match cmd {
        "-h" | "--help" | "help" => {
            print_usage();
            0
        }
        "-V" | "--version" | "version" => {
            println!(
                "ctx {} ({})",
                install::update::CURRENT_VERSION,
                crate::base::ext::policy().build_flavor()
            );
            0
        }
        "daemon" => {
            if has_help_before_dd(&args[1..]) {
                println!("Usage: ctx daemon\nRun the resident in-RAM context daemon.");
                return 0;
            }
            install::update::maybe_spawn_background_update_check();
            match run_daemon_forever() {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("ctx daemon error: {}", e);
                    1
                }
            }
        }
        "install" => {
            if has_help_before_dd(&args[1..]) {
                println!("{INSTALL_USAGE}");
                return 0;
            }
            install::run_install_cli(&args[1..])
        }
        "setup" => {
            if has_help_before_dd(&args[1..]) {
                println!("{SETUP_USAGE}");
                return 0;
            }
            let mut forwarded = vec!["--interactive".to_string()];
            forwarded.extend_from_slice(&args[1..]);
            install::run_install_cli(&forwarded)
        }
        "uninstall" => {
            if has_help_before_dd(&args[1..]) {
                println!("{UNINSTALL_USAGE}");
                return 0;
            }
            install::run_uninstall_cli(&args[1..])
        }
        "doctor" => {
            if has_help_before_dd(&args[1..]) {
                println!("{DOCTOR_USAGE}");
                return 0;
            }
            install::run_doctor_cli(&args[1..])
        }
        "update" => {
            if has_help_before_dd(&args[1..]) {
                println!("{UPDATE_USAGE}");
                return 0;
            }
            install::update::run_update_cli(&args[1..])
        }
        "diag" => {
            if has_help_before_dd(&args[1..]) {
                println!("{DIAG_USAGE}");
                return 0;
            }
            diag::run_diag_cli(&args[1..])
        }
        "mode" => {
            if has_help_before_dd(&args[1..]) {
                println!("{MODE_USAGE}");
                return 0;
            }
            let Some(arg) = args.get(1).map(|s| s.as_str()) else {
                let st = current_write_mode(None);
                println!(
                    "write_mode: {} (source: {}, flavor: {})",
                    if st.enabled { "write" } else { "read-only" },
                    st.source.as_str(),
                    crate::base::ext::policy().build_flavor(),
                );
                return 0;
            };
            let target = match arg.trim().to_ascii_lowercase().as_str() {
                "write" | "rw" | "on" | "enable" => true,
                "read-only" | "readonly" | "ro" | "off" | "disable" => false,
                other => {
                    eprintln!("ctx mode: unknown mode `{other}` (expected `write` or `read-only`)");
                    return 2;
                }
            };
            match set_persisted_write_mode(target) {
                Ok(path) => {
                    println!(
                        "ctx mode: {} (saved to {}; applies live on next call)",
                        if target { "write" } else { "read-only" },
                        path.display()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("ctx mode error: {e}");
                    1
                }
            }
        }
        "status" => {
            if has_help_before_dd(&args[1..]) {
                println!("Usage: ctx status\nPrint daemon RAM cache, session, and update status JSON.");
                return 0;
            }
            let reply =
                call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("status".to_string()))]));
            if let Some(mut st) = reply.get("status").cloned() {
                if let Json::Obj(ref mut fields) = st {
                    fields.push((
                        Cow::Borrowed("update"),
                        install::update::update_status_json(),
                    ));
                }
                println!("{}", st.to_json_string());
            } else {
                println!("{}", reply.to_json_string());
            }
            0
        }
        "clear" => {
            if has_help_before_dd(&args[1..]) {
                println!("Usage: ctx clear\nClear in-RAM cache, memos, and saved snapshot.");
                return 0;
            }
            let reply =
                call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("clear".to_string()))]));
            if let Some(txt) = reply.get_str("text") {
                println!("{}", txt);
            }
            0
        }
        "save-snapshot" => {
            if has_help_before_dd(&args[1..]) {
                println!("Usage: ctx save-snapshot\nPersist current RAM store metadata snapshot to disk.");
                return 0;
            }
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
            if has_help_before_dd(&args[1..]) {
                println!("Usage: ctx shutdown\nStop the running resident ctx daemon.");
                return 0;
            }
            let _ =
                call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("shutdown".to_string()))]));
            0
        }
        "read" => {
            let session = extract_cli_session_flag(&args[1..]);
            let parsed = build_read_request(
                &args[1..],
                workspace_cwd_str(None),
                cli_session_fields(session),
            );
            run_cli_parse(parsed)
        }
        "outline" => run_cli_parse(build_outline_request(
            &args[1..],
            workspace_cwd_str(None),
            cli_session_fields,
        )),
        "inspect" => {
            let session = extract_cli_session_flag(&args[1..]);
            let parsed = build_inspect_request(
                &args[1..],
                workspace_cwd_str(None),
                cli_session_fields(session),
            );
            run_cli_parse(parsed)
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
                    "--help" | "-h" => {
                        println!("{CAPSULE_USAGE}");
                        return 0;
                    }
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
            let session = extract_cli_session_flag(&args[1..]);
            let parsed = build_symbols_request(
                &args[1..],
                workspace_cwd_str(None),
                cli_session_fields(session),
            );
            run_cli_parse(parsed)
        }
        "impact" => run_cli_parse(build_impact_request(
            &args[1..],
            workspace_cwd_str(None),
            cli_session_fields,
        )),
        "edit" => {
            let mut raw_json: Option<String> = None;
            let mut dry_run_flag = false;
            let mut session: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--help" | "-h" => {
                        println!("{EDIT_USAGE}");
                        return 0;
                    }
                    "--dry-run" => dry_run_flag = true,
                    "--json" if i + 1 < args.len() => {
                        i += 1;
                        raw_json = Some(args[i].clone());
                    }
                    "--session" if i + 1 < args.len() => {
                        i += 1;
                        session = Some(args[i].clone());
                    }
                    _ => {}
                }
                i += 1;
            }
            let payload_str = match raw_json {
                Some(s) => s,
                None => {
                    let mut buf = Vec::new();
                    let _ = io::stdin().take(2 * 1024 * 1024).read_to_end(&mut buf);
                    String::from_utf8_lossy(&buf).into_owned()
                }
            };
            let parsed = match json::parse(&payload_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ctx edit: invalid JSON payload: {e}");
                    return 2;
                }
            };
            let mut fields = vec![
                ("op", Json::Str("edit".to_string())),
                ("cwd", Json::Str(workspace_cwd_str(None))),
            ];
            if let Some(edits) = parsed.get("edits") {
                fields.push(("edits", edits.clone()));
            }
            if let Some(renames) = parsed.get("renames") {
                fields.push(("renames", renames.clone()));
            }
            if let Some(creates) = parsed.get("creates") {
                fields.push(("creates", creates.clone()));
            }
            if let Some(verify_absent) = parsed.get("verify_absent") {
                fields.push(("verify_absent", verify_absent.clone()));
            }
            if dry_run_flag {
                fields.push(("dry_run", Json::Bool(true)));
            } else if let Some(dr) = parsed.get_bool("dry_run") {
                fields.push(("dry_run", Json::Bool(dr)));
            }
            fields.extend(cli_session_fields(session.as_deref()));
            let reply = call_daemon_or_inproc(Json::obj(fields));
            print_reply(&reply)
        }
        "refactor" => run_cli_parse(build_refactor_request(
            &args[1..],
            workspace_cwd_str(None),
            cli_session_fields,
        )),
        "git" => run_cli_parse(build_git_request(
            &args[1..],
            workspace_cwd_str(None),
            cli_session_fields,
        )),
        "search" => match search_args::parse_search_cli_action(&args[1..]) {
            Ok(search_args::SearchCliAction::Help(usage)) => {
                println!("{usage}");
                0
            }
            Ok(search_args::SearchCliAction::Request(request)) => {
                let reply = call_daemon_or_inproc(request);
                if let Some(text) = reply.get_str("text") {
                    print!("{text}");
                    0
                } else {
                    print_reply(&reply)
                }
            }
            Err(error) => {
                eprintln!("{error}");
                2
            }
        },
        "memo" => run_cli_parse(build_memo_request(
            &args[1..],
            workspace_cwd_str(None),
            cli_session_fields,
        )),
        "elf" | "elf-audit" => {
            let mut elf_path = String::new();
            let mut asm_path: Option<String> = None;
            let mut baseline_elf_path: Option<String> = None;
            let mut baseline_asm_path: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--help" | "-h" => {
                        println!("{ELF_USAGE}");
                        return 0;
                    }
                    "--elf" if i + 1 < args.len() => {
                        i += 1;
                        elf_path = args[i].clone();
                    }
                    "--asm" if i + 1 < args.len() => {
                        i += 1;
                        asm_path = Some(args[i].clone());
                    }
                    "--baseline-elf" if i + 1 < args.len() => {
                        i += 1;
                        baseline_elf_path = Some(args[i].clone());
                    }
                    "--baseline-asm" if i + 1 < args.len() => {
                        i += 1;
                        baseline_asm_path = Some(args[i].clone());
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
                (
                    "baseline_elf_path",
                    baseline_elf_path.map(Json::Str).unwrap_or(Json::Null),
                ),
                (
                    "baseline_asm_path",
                    baseline_asm_path.map(Json::Str).unwrap_or(Json::Null),
                ),
            ]));
            print_reply(&reply)
        }
        "mcp" => {
            let mut repo_root: Option<PathBuf> = None;
            let mut check_only = false;
            let mut cli_write: Option<bool> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--help" | "-h" => {
                        println!("{MCP_USAGE}");
                        return 0;
                    }
                    "--repo-root" if i + 1 < args.len() => {
                        i += 1;
                        repo_root = Some(PathBuf::from(&args[i]));
                    }
                    "--protocol-check" => check_only = true,
                    "--read-only" => cli_write = Some(false),
                    "--write" => cli_write = Some(true),
                    _ => {}
                }
                i += 1;
            }
            if check_only {
                mcp::run_protocol_self_check_with_mode(repo_root.as_deref(), cli_write)
            } else {
                mcp::run_mcp_stdio_with_mode(repo_root.as_deref(), cli_write)
            }
        }
        "hook" => {
            if has_help_before_dd(&args[1..]) {
                println!("{HOOK_USAGE}");
                return 0;
            }
            let flavor = args.get(1).map(|s| s.as_str()).unwrap_or("agy");
            let is_global = args.iter().any(|a| a == "--global");
            let mut raw = Vec::with_capacity(4096);
            let _ = io::stdin().take(1_048_576).read_to_end(&mut raw);
            let raw_str = String::from_utf8_lossy(&raw);
            if raw_str.trim().is_empty() {
                println!("{{}}");
                return 0;
            }
            if is_global && should_skip_global_duplicate(flavor, &raw_str) {
                println!("{}", passthrough_raw(flavor, &raw_str).to_json_string());
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
        } else if let Some(items) = reply
            .get("memo")
            .or_else(|| reply.get("memos"))
            .or_else(|| reply.get("changes"))
        {
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

fn print_usage() {
    eprintln!(
        "Usage: ctx <command> [args]\n\
         Commands:\n\
         \x20 ctx setup [--eager core|search|all|none]       Interactive harness scanner & installer\n\
         \x20 ctx install [--targets agy,claude,codex] [--all] [--eager core|search|all|none] [--no-wsl-bridge] [--no-codex-rules] [--check]\n\
         \x20 ctx uninstall [--targets agy,claude,codex] [--all] [--keep-binary] [--no-wsl-bridge]\n\
         \x20 ctx doctor [--json]\n\
         \x20 ctx mode [write|read-only]\n\
         \x20 ctx update [--check] [--rebuild] [--force] [--auto [off|patch|all]] [--json]\n\
         \x20 ctx inspect <file_or_dir...> [--max-files 80] [--max-bytes N] [--warn-lines 600] [--session ID]\n\
         \x20 ctx read <path[:start-end|s1-e1,s2-e2]> [...] [--max-bytes N] [--session ID] [--force] [--hashes]\n\
         \x20 ctx outline <file_or_dir...> [--max-files 40] [--max-symbols N] [--max-bytes N]\n\
         \x20 ctx sym <ModOrPath#Symbol|path> [...] [--compact] [--hashes] [--session ID] [--max-bytes N]\n\
         \x20 ctx search -q <ModOrDir:query> [-q ...] [--code-only] [--session ID] [--max-bytes 14336]  (8 KiB default, 12 KiB for 3-6 queries, 14 KiB cap)\n\
         \x20 ctx search <query> [roots...] [--max-results 40] [--context-lines 0] [--detail compact|scopes] [--code-only] [--session ID] [--max-bytes 14336]\n\
         \x20 ctx search --batch-json '<array>' [--code-only] [--session ID] [--max-bytes 14336]\n\
         \x20 ctx impact <Mod#Symbol...> [--max-callers 20] [--no-tests] [--no-git] [--session ID] [--max-bytes N]\n\
         \x20 ctx edit [--dry-run] [--session ID] --json '<payload>'\n\
         \x20 ctx refactor <old_name> <new_name> <paths...> [--session ID] [--apply]\n\
         \x20 ctx git [diff|status|log|show] [--staged] [--stat] [--rev R] [--symbol S] [--no-hashes] [--session ID] [--] [paths...]\n\
         \x20 ctx diag [--file PATH] [--hashes] [--max-errors 15] [--context 2] [-- <cmd> [args...]]\n\
         \x20 ctx memo <put|get|list|clear|changes|pack|pack-get|packs> [--topic K] [--summary S] [--since N] [--limit N] [--max-bytes N] [--session ID] [paths...]\n\
         \x20 ctx capsule <claim|prepare> [key] [--assignment TEXT] [--workspace inherit|branch|share]\n\
         \x20 ctx elf <--elf path> [--asm path] [--baseline-elf path] [--baseline-asm path]\n\
         \x20 ctx status | clear | save-snapshot | shutdown | --version\n\
         \x20 ctx mcp [--repo-root DIR] [--read-only|--write] [--protocol-check]\n\
         \x20 ctx hook <agy|codex|claude> [--global]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{AGY_CLI_DEFAULT_MAX_BYTES, AGY_CLI_INLINE_CAP};
    use crate::rpc::{execute_request, BrokerService};
    use crate::store::now_ms_u64;
    use std::fs;

    fn svec(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn cli_read_inspect_sym_omit_default_max_bytes_attach_lease_and_hit_agy_cli_9200b_cap() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-cli-rpc-agy-{}-{}",
            std::process::id(),
            now_ms_u64()
        ));
        fs::create_dir_all(&dir).unwrap();
        let mut big = String::from("pub fn big_entry() -> i32 {\n");
        for i in 1..=320 {
            big.push_str(&format!(
                "    let x_{i:03} = {i}; // padding_0123456789abcdef0123456789\n"
            ));
        }
        big.push_str("    0\n}\n");
        fs::write(dir.join("big.rs"), &big).unwrap();
        for f in 0..90 {
            fs::write(
                dir.join(format!("m_{f:02}.rs")),
                format!("pub fn f1_{f:02}() {{}}\npub fn f2_{f:02}() {{}}\npub fn f3_{f:02}() {{}}\n"),
            )
            .unwrap();
        }

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        let root = svc.allowlist.register_hint(&dir, true).unwrap();
        let tok = svc
            .broker
            .capsules
            .issue_cli_lease("agy:cli-path-1".into(), root)
            .unwrap();
        let cwd = dir.to_string_lossy().into_owned();

        // 1. Serialization omits `max_bytes` unless `--max-bytes` is explicitly supplied,
        //    and attaches `cli_token` + `session` on `read`, `inspect`, and `sym`.
        let sess_fields = |explicit: Option<&str>| {
            cli_session_fields_from(explicit, Some("agy:cli-path-1"), Some(&tok))
        };

        let read_args = svec(&["big.rs"]);
        let CliParse::Request(read_req) =
            build_read_request(&read_args, cwd.clone(), sess_fields(None))
        else {
            panic!("expected read request");
        };
        assert!(read_req.get("max_bytes").is_none());
        assert_eq!(read_req.get_str("cli_token"), Some(tok.as_str()));

        let CliParse::Request(read_explicit) = build_read_request(
            &svec(&["big.rs", "--max-bytes", "65536"]),
            cwd.clone(),
            sess_fields(None),
        ) else {
            panic!("expected read request");
        };
        assert_eq!(read_explicit.get_i64("max_bytes"), Some(65_536));

        let CliParse::Request(read_small_explicit) = build_read_request(
            &svec(&["big.rs", "--max-bytes", "3500", "--force"]),
            cwd.clone(),
            sess_fields(None),
        ) else {
            panic!("expected read request");
        };

        let CliParse::Request(plain_read_explicit) = build_read_request(
            &svec(&["big.rs", "--max-bytes", "65536"]),
            cwd.clone(),
            Vec::new(),
        ) else {
            panic!("expected plain read request");
        };

        let inspect_args = svec(&[".", "--max-files", "100", "--session", "agy:cli-path-1"]);
        let CliParse::Request(inspect_req) = build_inspect_request(
            &inspect_args,
            cwd.clone(),
            sess_fields(extract_cli_session_flag(&inspect_args)),
        ) else {
            panic!("expected inspect request");
        };
        assert!(inspect_req.get("max_bytes").is_none());
        assert_eq!(inspect_req.get_str("session"), Some("agy:cli-path-1"));
        assert_eq!(inspect_req.get_str("cli_token"), Some(tok.as_str()));

        // Overriding `--session` to a different value must drop the mismatched env `cli_token`.
        let foreign_fields = cli_session_fields_from(Some("other:s"), Some("agy:cli-path-1"), Some(&tok));
        let CliParse::Request(foreign_inspect) =
            build_inspect_request(&svec(&["."]), cwd.clone(), foreign_fields)
        else {
            panic!("expected foreign inspect request");
        };
        assert_eq!(foreign_inspect.get_str("session"), Some("other:s"));
        assert!(foreign_inspect.get("cli_token").is_none());

        let sym_args = svec(&["big.rs#big_entry"]);
        let CliParse::Request(sym_req) =
            build_symbols_request(&sym_args, cwd.clone(), sess_fields(None))
        else {
            panic!("expected symbols request");
        };
        assert!(sym_req.get("max_bytes").is_none());
        assert_eq!(sym_req.get_str("cli_token"), Some(tok.as_str()));

        // 2. End-to-end CLI-to-RPC execution hard-clamps AGY CLI at 9,200 B even on explicit
        //    `--max-bytes 65536`, while honoring smaller explicit caps and preserving plain CLI budgets.
        let r_read = execute_request(&svc, &read_req);
        let r_read_txt = r_read.get_str("text").unwrap();
        assert!(
            r_read_txt.len() <= AGY_CLI_DEFAULT_MAX_BYTES
                && r_read_txt.contains("AGY CLI inline cap 9200B")
                && !r_read_txt.contains("--max-bytes"),
            "len={}",
            r_read_txt.len()
        );

        let r_read_big = execute_request(&svc, &read_explicit);
        let r_read_big_txt = r_read_big.get_str("text").unwrap();
        assert!(
            r_read_big_txt.len() <= AGY_CLI_DEFAULT_MAX_BYTES,
            "AGY CLI must hard-clamp explicit --max-bytes 65536: len={}",
            r_read_big_txt.len()
        );

        let r_read_small = execute_request(&svc, &read_small_explicit);
        assert!(
            r_read_small.get_str("text").unwrap().len() <= 3500,
            "AGY CLI must still allow smaller explicit --max-bytes"
        );

        let r_plain_big = execute_request(&svc, &plain_read_explicit);
        assert!(
            r_plain_big.get_str("text").unwrap().len() > AGY_CLI_INLINE_CAP,
            "non-AGY CLI must preserve explicit --max-bytes"
        );

        let r_inspect = execute_request(&svc, &inspect_req);
        assert!(
            r_inspect.get_str("text").unwrap().len() <= AGY_CLI_DEFAULT_MAX_BYTES + 128,
            "inspect len={}",
            r_inspect.get_str("text").unwrap().len()
        );

        let r_sym = execute_request(&svc, &sym_req);
        assert!(
            r_sym.get_str("text").unwrap().len() <= AGY_CLI_DEFAULT_MAX_BYTES,
            "sym len={}",
            r_sym.get_str("text").unwrap().len()
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_git_memo_search_help_double_dash_and_unknown_flag_handling() {
        let no_sess = |s: Option<&str>| cli_session_fields_from(s, None, None);

        // `ctx git diff --stat -- src/a.hpp` strips `--` and passes only `src/a.hpp`.
        let parsed = build_git_request(
            &svec(&["diff", "--stat", "--", "src/a.hpp"]),
            "/tmp".into(),
            no_sess,
        );
        match parsed {
            CliParse::Request(req) => {
                assert_eq!(req.get_str("action"), Some("diff"));
                assert_eq!(req.get_bool("stat"), Some(true));
                let paths: Vec<&str> = req
                    .get("paths")
                    .and_then(Json::as_arr)
                    .unwrap()
                    .iter()
                    .filter_map(Json::as_str)
                    .collect();
                assert_eq!(paths, vec!["src/a.hpp"]);
            }
            other => panic!("expected git request, got {other:?}"),
        }

        // `ctx git show HEAD -- src/a.hpp` keeps `rev=HEAD` and puts post-`--` args in `paths`.
        match build_git_request(
            &svec(&["show", "HEAD", "--", "src/a.hpp"]),
            "/tmp".into(),
            no_sess,
        ) {
            CliParse::Request(req) => {
                assert_eq!(req.get_str("action"), Some("show"));
                assert_eq!(req.get_str("rev"), Some("HEAD"));
                let paths: Vec<&str> = req
                    .get("paths")
                    .and_then(Json::as_arr)
                    .unwrap()
                    .iter()
                    .filter_map(Json::as_str)
                    .collect();
                assert_eq!(paths, vec!["src/a.hpp"]);
            }
            other => panic!("expected git show request, got {other:?}"),
        }

        // `ctx git --help` / `-h` / `help` / `diff --help` return Help and dispatch exits 0.
        for form in [
            vec!["--help"],
            vec!["-h"],
            vec!["help"],
            vec!["diff", "--help"],
            vec!["diff", "-h"],
        ] {
            assert!(
                matches!(
                    build_git_request(&svec(&form), "/tmp".into(), no_sess),
                    CliParse::Help(msg) if msg.contains("ctx git")
                ),
                "form={form:?}"
            );
        }
        assert_eq!(dispatch(&svec(&["git", "--help"])), 0);
        assert_eq!(dispatch(&svec(&["git", "diff", "--help"])), 0);

        // Unknown flags before `--` fail cleanly with exit 2 and supported-flag hint.
        match build_git_request(&svec(&["diff", "--name-only"]), "/tmp".into(), no_sess) {
            CliParse::Error(err) => {
                assert!(
                    err.contains("unknown flag '--name-only'")
                        && err.contains("supported: --stat, --staged"),
                    "err={err}"
                );
            }
            other => panic!("expected error for unknown flag, got {other:?}"),
        }
        assert_eq!(dispatch(&svec(&["git", "diff", "--name-only"])), 2);

        // `ctx memo` help handling: action or pre-positional `--help` / `-h`.
        for form in [
            vec!["--help"],
            vec!["-h"],
            vec!["help"],
            vec!["pack", "--help"],
            vec!["pack", "my_pack", "--help"],
            vec!["put", "-t", "k", "-h"],
        ] {
            assert!(
                matches!(
                    build_memo_request(&svec(&form), "/tmp".into(), no_sess),
                    CliParse::Help(msg) if msg.contains("pack-get") && msg.contains("changes")
                ),
                "memo form={form:?}"
            );
        }
        assert_eq!(dispatch(&svec(&["memo", "--help"])), 0);
        assert_eq!(dispatch(&svec(&["memo", "pack", "--help"])), 0);

        // Positional `ctx memo get <topic>` sets `topic` cleanly without requiring `--topic`.
        match build_memo_request(&svec(&["get", "squad:runtime"]), "/tmp".into(), no_sess) {
            CliParse::Request(req) => {
                assert_eq!(req.get_str("action"), Some("get"));
                assert_eq!(req.get_str("topic"), Some("squad:runtime"));
            }
            other => panic!("expected positional memo get request, got {other:?}"),
        }

        // Value of `--summary "--help"` must not trigger help.
        match build_memo_request(
            &svec(&["put", "-t", "k", "--summary", "--help", "src/a.rs"]),
            "/tmp".into(),
            no_sess,
        ) {
            CliParse::Request(req) => {
                assert_eq!(req.get_str("summary"), Some("--help"));
            }
            other => panic!("expected memo request, got {other:?}"),
        }

        // `ctx search --help` / `-h` exits 0 cleanly.
        assert_eq!(dispatch(&svec(&["search", "--help"])), 0);
        assert_eq!(dispatch(&svec(&["search", "-h"])), 0);
    }

    #[test]
    fn cli_universal_help_and_memo_changes_since_limit_flags() {
        let no_sess = |s: Option<&str>| cli_session_fields_from(s, None, None);

        // Universal `--help` and `-h` across all CLI subcommands exit 0 without executing or blocking on stdin.
        for cmd in [
            "read",
            "inspect",
            "outline",
            "sym",
            "symbols",
            "impact",
            "edit",
            "refactor",
            "memo",
            "git",
            "search",
            "mode",
            "capsule",
            "elf",
            "elf-audit",
            "mcp",
            "hook",
            "status",
            "clear",
            "save-snapshot",
            "shutdown",
            "daemon",
            "diag",
            "install",
            "setup",
            "uninstall",
            "doctor",
            "update",
        ] {
            assert_eq!(dispatch(&svec(&[cmd, "--help"])), 0, "{cmd} --help");
            assert_eq!(dispatch(&svec(&[cmd, "-h"])), 0, "{cmd} -h");
        }

        // Builder-level checks: `--help` returns Help even alongside positional args,
        // while `--session --help` or `-- --help` does not hijack help.
        assert!(matches!(
            build_read_request(&svec(&["src/a.rs", "--help"]), "/tmp".into(), Vec::new()),
            CliParse::Help(u) if u.contains("ctx read")
        ));
        assert!(matches!(
            build_read_request(&svec(&["--session", "--help", "src/a.rs"]), "/tmp".into(), Vec::new()),
            CliParse::Request(req) if req.get("paths").and_then(Json::as_arr).is_some_and(|a| a.len() == 1)
        ));
        assert!(matches!(
            build_inspect_request(&svec(&["-h"]), "/tmp".into(), Vec::new()),
            CliParse::Help(u) if u.contains("ctx inspect")
        ));
        assert!(matches!(
            build_outline_request(&svec(&["--help"]), "/tmp".into(), no_sess),
            CliParse::Help(u) if u.contains("ctx outline")
        ));
        assert!(matches!(
            build_symbols_request(&svec(&["-h"]), "/tmp".into(), Vec::new()),
            CliParse::Help(u) if u.contains("ctx sym")
        ));
        assert!(matches!(
            build_impact_request(&svec(&["--help"]), "/tmp".into(), no_sess),
            CliParse::Help(u) if u.contains("ctx impact")
        ));
        assert!(matches!(
            build_refactor_request(&svec(&["--help"]), "/tmp".into(), no_sess),
            CliParse::Help(u) if u.contains("ctx refactor")
        ));

        // `ctx memo changes --since <n> --limit <n> --max-bytes <n>` and `-n <n>`.
        match build_memo_request(
            &svec(&["changes", "--since", "42", "--limit", "15", "--max-bytes", "4096"]),
            "/tmp".into(),
            no_sess,
        ) {
            CliParse::Request(req) => {
                assert_eq!(req.get_str("action"), Some("changes"));
                assert_eq!(req.get_i64("since_seq"), Some(42));
                assert_eq!(req.get_i64("limit"), Some(15));
                assert_eq!(req.get_i64("max_bytes"), Some(4096));
            }
            other => panic!("expected memo changes request, got {other:?}"),
        }
        match build_memo_request(&svec(&["changes", "--since-seq", "7", "-n", "10"]), "/tmp".into(), no_sess) {
            CliParse::Request(req) => {
                assert_eq!(req.get_i64("since_seq"), Some(7));
                assert_eq!(req.get_i64("limit"), Some(10));
            }
            other => panic!("expected memo changes -n request, got {other:?}"),
        }
        assert!(matches!(
            build_memo_request(&svec(&["changes", "--help"]), "/tmp".into(), no_sess),
            CliParse::Help(u) if u.contains("--since") && u.contains("--limit")
        ));
    }
}
