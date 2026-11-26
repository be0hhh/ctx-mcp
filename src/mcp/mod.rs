//! Native Stdio MCP server (`ctx mcp [--repo-root <dir>]`) speaking JSON-RPC 2.0
//! over newline-delimited frames (`2024-11-05`, `2025-03-26`, `2025-06-18`).
//! The published tool inventory is checked against `mcp_tools.json`.

mod resources;
mod schema;

use crate::base::json::{self, Json, JsonKey};
use crate::base::security::generate_csprng_token;
use crate::rpc::{call_daemon_or_inproc, workspace_cwd_str};
use resources::read_mcp_resource;
use schema::{resource_schemas, tool_schemas};
use std::borrow::Cow;
use std::io::{self, BufRead, Write};
use std::path::Path;

const DEFAULT_WIRE_VER: &str = "2025-06-18";
const SUPPORTED_WIRE_VERS: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18"];
const MEMO_ACTIONS: &[&str] = &["put", "get", "list"];

pub fn expected_tool_names() -> Vec<String> {
    let catalog =
        json::parse(include_str!("../../mcp_tools.json")).expect("valid embedded MCP catalog");
    catalog
        .as_arr()
        .expect("MCP catalog array")
        .iter()
        .map(|name| name.as_str().expect("MCP tool name").to_owned())
        .collect()
}

pub fn run_mcp_stdio(repo_root: Option<&Path>) -> i32 {
    let dedicated = std::env::var("AGENT_CTX_DEDICATED_STDIO").ok().as_deref() == Some("1");
    let session = dedicated
        .then(generate_csprng_token)
        .and_then(Result::ok)
        .map(|key| format!("mcp:stdio:{key}"));
    let mut host_hint = std::env::var("AGENT_CTX_HOST")
        .ok()
        .filter(|s| !s.is_empty());
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return 0,
            Ok(_) => {}
            Err(_) => return 0,
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > 1_048_576 {
            let err = rpc_error(Json::Null, -32700, "MCP frame exceeds 1 MiB");
            let _ = writeln!(stdout, "{}", err.to_json_string());
            let _ = stdout.flush();
            continue;
        }
        let parsed = match json::parse(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = rpc_error(Json::Null, -32700, &format!("invalid JSON: {}", e));
                let _ = writeln!(stdout, "{}", err.to_json_string());
                let _ = stdout.flush();
                continue;
            }
        };
        if parsed.get_str("method") == Some("initialize") {
            if host_hint.is_none() {
                if let Some(name) = parsed
                    .get("params")
                    .and_then(|p| p.get("clientInfo"))
                    .and_then(|c| c.get_str("name"))
                {
                    let lower = name.to_ascii_lowercase();
                    if lower.contains("antigravity")
                        || lower.contains("agy")
                        || lower.contains("gemini")
                        || lower.contains("cascade")
                        || lower.contains("jetski")
                    {
                        host_hint = Some("agy".to_string());
                    }
                }
            }
            if std::env::var("AGENT_CTX_INPROC").as_deref() != Ok("1") {
                let warm_cwd = workspace_cwd_str(repo_root);
                let explicit = repo_root.is_some();
                let _ = std::thread::Builder::new()
                    .name("ctx-mcp-warm".into())
                    .spawn(move || {
                        let _ = call_daemon_or_inproc(Json::obj(vec![
                            ("op", Json::Str("ping".to_string())),
                            ("cwd", Json::Str(warm_cwd)),
                            ("explicit_root", Json::Bool(explicit)),
                        ]));
                    });
            }
        }
        if let Some(reply) =
            handle_mcp_message_scoped(&parsed, repo_root, session.as_deref(), host_hint.as_deref())
        {
            let _ = writeln!(stdout, "{}", reply.to_json_string());
            let _ = stdout.flush();
        }
    }
}

fn handle_mcp_message_scoped(
    msg: &Json,
    repo_root: Option<&Path>,
    session: Option<&str>,
    host_hint: Option<&str>,
) -> Option<Json> {
    if msg.get_str("jsonrpc") != Some("2.0") {
        return Some(rpc_error(Json::Null, -32600, "invalid JSON-RPC envelope"));
    }
    let Some(method) = msg.get_str("method") else {
        return Some(rpc_error(Json::Null, -32600, "missing method"));
    };
    let Some(req_id) = msg.get("id").cloned() else {
        return None;
    };

    let empty_obj = Json::Obj(Vec::new());
    let params = msg.get("params").unwrap_or(&empty_obj);

    match method {
        "initialize" => {
            let requested = params.get_str("protocolVersion").unwrap_or(DEFAULT_WIRE_VER);
            let chosen = if SUPPORTED_WIRE_VERS.contains(&requested) {
                requested
            } else {
                DEFAULT_WIRE_VER
            };
            Some(rpc_result(
                req_id,
                Json::obj(vec![
                    ("protocolVersion", Json::Str(chosen.to_string())),
                    (
                        "capabilities",
                        Json::obj(vec![
                            ("tools", Json::Obj(Vec::new())),
                            ("resources", Json::Obj(Vec::new())),
                        ]),
                    ),
                    (
                        "serverInfo",
                        Json::obj(vec![
                            ("name", Json::Str("agent_ctx".to_string())),
                            ("version", Json::Str("2.4.0".to_string())),
                        ]),
                    ),
                    (
                        "instructions",
                        Json::Str(
                            "Batch related lookups. For ctx_search q arrays, use a known root in every item, \
                             for example graph:scan_manifests. Limit hits per query with max_results. \
                             Finish when the hits answer the question. If exact bodies are needed, use one compact ctx_symbols call."
                                .to_string(),
                        ),
                    ),
                ]),
            ))
        }
        "ping" => Some(rpc_result(req_id, Json::Obj(Vec::new()))),
        "tools/list" => Some(rpc_result(
            req_id,
            Json::obj(vec![("tools", tool_schemas())]),
        )),
        "resources/list" => Some(rpc_result(
            req_id,
            Json::obj(vec![("resources", resource_schemas())]),
        )),
        "resources/templates/list" => Some(rpc_result(
            req_id,
            Json::obj(vec![("resourceTemplates", Json::Arr(Vec::new()))]),
        )),
        "resources/read" => {
            let Some(uri) = params.get_str("uri") else {
                return Some(rpc_error(req_id, -32602, "missing resource uri"));
            };
            match read_mcp_resource(uri, repo_root) {
                Ok(result) => Some(rpc_result(req_id, result)),
                Err(msg) => Some(rpc_error(req_id, -32602, &msg)),
            }
        }
        "tools/call" => {
            let Some(name) = params.get_str("name") else {
                return Some(rpc_error(req_id, -32602, "missing tool name"));
            };
            let args = params.get("arguments").unwrap_or(&empty_obj);
            Some(rpc_result(
                req_id,
                invoke_mcp_tool(name, args, repo_root, session, host_hint),
            ))
        }
        _ => Some(rpc_error(
            req_id,
            -32601,
            &format!("method not found: {}", method),
        )),
    }
}

fn invoke_mcp_tool(
    name: &str,
    args: &Json,
    repo_root: Option<&Path>,
    session: Option<&str>,
    host_hint: Option<&str>,
) -> Json {
    let cwd = workspace_cwd_str(repo_root);
    let explicit_root = repo_root.is_some();
    let mcp_session = session.unwrap_or_default().to_string();

    let mut rpc_req = match name {
        "ctx_read" => Json::obj(vec![
            ("op", Json::Str("read".to_string())),
            ("cwd", Json::Str(cwd)),
            ("explicit_root", Json::Bool(explicit_root)),
            ("session", Json::Str(mcp_session)),
            (
                "paths",
                args.get("paths").cloned().unwrap_or(Json::Arr(Vec::new())),
            ),
            (
                "max_bytes",
                Json::Int(args.get_i64("max_bytes").unwrap_or(0)),
            ),
            ("force", Json::Bool(args.get_bool("force").unwrap_or(false))),
        ]),
        "ctx_outline" => Json::obj(vec![
            ("op", Json::Str("outline".to_string())),
            ("cwd", Json::Str(cwd)),
            ("explicit_root", Json::Bool(explicit_root)),
            (
                "paths",
                args.get("paths").cloned().unwrap_or(Json::Arr(Vec::new())),
            ),
            (
                "max_files",
                Json::Int(args.get_i64("max_files").unwrap_or(40)),
            ),
            (
                "max_bytes",
                Json::Int(args.get_i64("max_bytes").unwrap_or(0)),
            ),
        ]),
        "ctx_inspect" => Json::obj(vec![
            ("op", Json::Str("inspect".to_string())),
            ("cwd", Json::Str(cwd)),
            ("explicit_root", Json::Bool(explicit_root)),
            (
                "paths",
                args.get("paths").cloned().unwrap_or(Json::Arr(Vec::new())),
            ),
            (
                "max_files",
                Json::Int(args.get_i64("max_files").unwrap_or(80)),
            ),
            (
                "max_bytes",
                Json::Int(args.get_i64("max_bytes").unwrap_or(0)),
            ),
            (
                "warn_lines",
                Json::Int(args.get_i64("warn_lines").unwrap_or(600)),
            ),
        ]),
        "ctx_symbols" => Json::obj(vec![
            ("op", Json::Str("symbols".to_string())),
            ("compact", Json::Bool(args.get_bool("compact").unwrap_or(false))),
            ("cwd", Json::Str(cwd)),
            ("explicit_root", Json::Bool(explicit_root)),
            ("session", Json::Str(mcp_session)),
            (
                "requests",
                args.get("requests")
                    .cloned()
                    .unwrap_or(Json::Arr(Vec::new())),
            ),
            (
                "max_bytes",
                Json::Int(args.get_i64("max_bytes").unwrap_or(0)),
            ),
        ]),
        "ctx_search" => {
            let mut fields: Vec<(JsonKey, Json)> = vec![
                (Cow::Borrowed("op"), Json::Str("search".to_string())),
                (Cow::Borrowed("cwd"), Json::Str(cwd)),
                (Cow::Borrowed("explicit_root"), Json::Bool(explicit_root)),
            ];
            for key in [
                "q",
                "query",
                "roots",
                "max_results",
                "context_lines",
                "detail",
                "max_bytes",
                "queries",
            ] {
                if let Some(value) = args.get(key) {
                    fields.push((Cow::Borrowed(key), value.clone()));
                }
            }
            Json::Obj(fields)
        }
        "ctx_capsule" => {
            let mut fields: Vec<(JsonKey, Json)> =
                vec![(Cow::Borrowed("op"), Json::Str("capsule".into()))];
            for key in ["action", "workspace", "assignment", "key"] {
                if let Some(value) = args.get_str(key) {
                    fields.push((Cow::Borrowed(key), Json::Str(value.into())));
                }
            }
            Json::Obj(fields)
        }
        "ctx_memo" => {
            let action = match args.get("action") {
                Some(value) => value.as_str().unwrap_or(""),
                None => "list",
            };
            if !MEMO_ACTIONS.contains(&action) {
                return tool_payload("MCP ctx_memo action must be put, get or list", true);
            }
            Json::obj(vec![
                ("op", Json::Str("memo".to_string())),
                ("cwd", Json::Str(cwd)),
                ("explicit_root", Json::Bool(explicit_root)),
                ("action", Json::Str(action.to_string())),
                (
                    "topic",
                    Json::Str(args.get_str("topic").unwrap_or("").to_string()),
                ),
                (
                    "summary",
                    Json::Str(args.get_str("summary").unwrap_or("").to_string()),
                ),
                ("kind", args.get("kind").cloned().unwrap_or(Json::Null)),
                (
                    "paths",
                    args.get("paths").cloned().unwrap_or(Json::Arr(Vec::new())),
                ),
            ])
        }
        "ctx_elf_audit" => Json::obj(vec![
            ("op", Json::Str("elf_audit".to_string())),
            ("cwd", Json::Str(cwd)),
            ("explicit_root", Json::Bool(explicit_root)),
            (
                "elf_path",
                Json::Str(args.get_str("elf_path").unwrap_or("").to_string()),
            ),
            (
                "asm_path",
                args.get_str("asm_path")
                    .map(|s| Json::Str(s.to_string()))
                    .unwrap_or(Json::Null),
            ),
        ]),
        _ => {
            return tool_payload(&format!("unknown tool: {}", name), true);
        }
    };

    if let (Some(ticket), Json::Obj(fields)) = (args.get_str("ctx_context"), &mut rpc_req) {
        fields.push((Cow::Borrowed("ctx_context"), Json::Str(ticket.into())));
    }
    if let (Some(host), Json::Obj(fields)) = (host_hint, &mut rpc_req) {
        fields.push((Cow::Borrowed("host"), Json::Str(host.into())));
    }
    let reply = call_daemon_or_inproc(rpc_req);
    if reply.get_bool("ok") == Some(true) {
        if let Some(text) = reply.get_str("text") {
            return tool_payload(text, false);
        }
        for key in ["memos", "memo"] {
            if let Some(value) = reply.get(key) {
                let data = Json::obj(vec![(key, value.clone())]);
                return with_structured(tool_payload(&data.to_json_string(), false), data);
            }
        }
        tool_payload("", false)
    } else {
        let err = reply.get_str("error").unwrap_or("tool execution failed");
        with_structured(tool_payload(err, true), reply)
    }
}

fn with_structured(mut result: Json, data: Json) -> Json {
    if let Json::Obj(fields) = &mut result {
        fields.push((Cow::Borrowed("structuredContent"), data));
    }
    result
}

fn tool_payload(text: &str, is_error: bool) -> Json {
    Json::obj(vec![
        (
            "content",
            Json::Arr(vec![Json::obj(vec![
                ("type", Json::Str("text".to_string())),
                ("text", Json::Str(text.to_string())),
            ])]),
        ),
        ("isError", Json::Bool(is_error)),
    ])
}

fn rpc_result(id: Json, result: Json) -> Json {
    Json::obj(vec![
        ("jsonrpc", Json::Str("2.0".to_string())),
        ("id", id),
        ("result", result),
    ])
}

fn rpc_error(id: Json, code: i64, message: &str) -> Json {
    Json::obj(vec![
        ("jsonrpc", Json::Str("2.0".to_string())),
        ("id", id),
        (
            "error",
            Json::obj(vec![
                ("code", Json::Int(code)),
                ("message", Json::Str(message.to_string())),
            ]),
        ),
    ])
}

pub fn check_mcp_protocol(repo_root: Option<&Path>) -> Result<usize, String> {
    let init = Json::obj(vec![
        ("jsonrpc", Json::Str("2.0".to_string())),
        ("id", Json::Int(1)),
        ("method", Json::Str("initialize".to_string())),
        ("params", Json::Obj(Vec::new())),
    ]);
    let list = Json::obj(vec![
        ("jsonrpc", Json::Str("2.0".to_string())),
        ("id", Json::Int(2)),
        ("method", Json::Str("tools/list".to_string())),
        ("params", Json::Obj(Vec::new())),
    ]);
    let res_list = Json::obj(vec![
        ("jsonrpc", Json::Str("2.0".to_string())),
        ("id", Json::Int(3)),
        ("method", Json::Str("resources/list".to_string())),
        ("params", Json::Obj(Vec::new())),
    ]);
    let reply = handle_mcp_message_scoped(&init, repo_root, None, None)
        .ok_or("initialize did not reply")?;
    if reply.get("result").and_then(|r| r.get_str("protocolVersion")) != Some(DEFAULT_WIRE_VER) {
        return Err("initialize did not return the default protocol version".into());
    }
    if reply
        .get("result")
        .and_then(|r| r.get("capabilities"))
        .and_then(|c| c.get("resources"))
        .is_none()
    {
        return Err("initialize did not advertise resources capability".into());
    }
    let reply = handle_mcp_message_scoped(&list, repo_root, None, None)
        .ok_or("tools/list did not reply")?;
    let mut actual: Vec<_> = reply
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Json::as_arr)
        .ok_or("tools/list did not return a tools array")?
        .iter()
        .map(|tool| {
            tool.get_str("name")
                .ok_or("tools/list returned a tool without a name")
        })
        .collect::<Result<_, _>>()?;
    actual.sort_unstable();
    let mut expected = expected_tool_names();
    expected.sort_unstable();
    if !actual.iter().copied().eq(expected.iter().map(String::as_str)) {
        return Err(format!(
            "tools/list mismatch: expected {expected:?}, got {actual:?}"
        ));
    }
    let r_reply = handle_mcp_message_scoped(&res_list, repo_root, None, None)
        .ok_or("resources/list did not reply")?;
    let uris: Vec<_> = r_reply
        .get("result")
        .and_then(|r| r.get("resources"))
        .and_then(Json::as_arr)
        .ok_or("resources/list did not return a resources array")?
        .iter()
        .filter_map(|item| item.get_str("uri"))
        .collect();
    if uris != ["ctx://status", "ctx://memos"] {
        return Err(format!("resources/list mismatch: got {uris:?}"));
    }
    Ok(actual.len())
}

pub fn run_protocol_self_check(repo_root: Option<&Path>) -> i32 {
    match check_mcp_protocol(repo_root) {
        Ok(count) => {
            println!("agent_ctx mcp protocol check: OK ({count} tools)");
            0
        }
        Err(error) => {
            eprintln!("agent_ctx mcp protocol check: FAIL ({error})");
            1
        }
    }
}
