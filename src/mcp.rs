//! Native Stdio MCP server (`ctx mcp [--repo-root <dir>]`) speaking JSON-RPC 2.0
//! over newline-delimited frames (`2024-11-05`, `2025-03-26`, `2025-06-18`).
//! The published tool inventory is checked against `mcp_tools.json`.

use crate::engine::DEFAULT_READ_MAX_BYTES;
use crate::json::{self, Json};
use crate::protocol::{call_daemon_or_inproc, workspace_cwd_str};
use std::io::{self, BufRead, Write};
use std::path::Path;

const DEFAULT_WIRE_VER: &str = "2025-06-18";
const SUPPORTED_WIRE_VERS: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18"];
const MEMO_ACTIONS: &[&str] = &["put", "get", "list"];

pub fn expected_tool_names() -> Vec<String> {
    let catalog = json::parse(include_str!("../mcp_tools.json")).expect("valid embedded MCP catalog");
    catalog.as_arr().expect("MCP catalog array").iter()
        .map(|name| name.as_str().expect("MCP tool name").to_owned())
        .collect()
}

pub fn run_mcp_stdio(repo_root: Option<&Path>) -> i32 {
    let dedicated = std::env::var("AGENT_CTX_DEDICATED_STDIO").ok().as_deref() == Some("1");
    let session = dedicated.then(crate::security::generate_csprng_token)
        .and_then(Result::ok).map(|key| format!("mcp:stdio:{key}"));
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
        if parsed.get_str("method") == Some("initialize")
            && std::env::var("AGENT_CTX_INPROC").as_deref() != Ok("1")
        {
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
        if let Some(reply) = handle_mcp_message_scoped(&parsed, repo_root, session.as_deref()) {
            let _ = writeln!(stdout, "{}", reply.to_json_string());
            let _ = stdout.flush();
        }
    }
}

fn handle_mcp_message_scoped(msg: &Json, repo_root: Option<&Path>, session: Option<&str>) -> Option<Json> {
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
                        Json::obj(vec![("tools", Json::Obj(Vec::new()))]),
                    ),
                    (
                        "serverInfo",
                        Json::obj(vec![
                            ("name", Json::Str("agent_ctx".to_string())),
                            ("version", Json::Str("2.2.0".to_string())),
                        ]),
                    ),
                    (
                        "instructions",
                        Json::Str(
                            "In-RAM Context Broker. Batch paths/searches; finish from search or compact symbols when sufficient.\n\
                             - ctx_search: {\"q\":[\"ModOrDir:pat\",...]} (1-4 parallel searches, 8KiB cap; bare stem matches .hpp+.cpp; lowercase = smart-case)\n\
                             - ctx_inspect: {\"paths\":[\"dir1\",\"dir2\"],\"max_files\":80} (lines, >=600L/>800L flags, ns, #include, symbols)\n\
                             - ctx_symbols: {\"requests\":[\"ModOrPath#Sym\"],\"compact\":false} (compact=true: <=24L + continuation)\n\
                             - ctx_read: {\"paths\":[\"file\"|\"file:1-250\"],\"max_bytes\":1048576,\"force\":false}\n\
                             - ctx_outline: {\"paths\":[\"dir_or_file\"],\"max_files\":40}\n\
                             - ctx_memo: {\"action\":\"put|get|list\",\"topic\":\"key\",\"summary\":\"...\",\"paths\":[\"file\"]}\n\
                             - ctx_elf_audit: {\"elf_path\":\"bin\",\"asm_path\":\"opt\"}"
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
        "tools/call" => {
            let Some(name) = params.get_str("name") else {
                return Some(rpc_error(req_id, -32602, "missing tool name"));
            };
            let args = params.get("arguments").unwrap_or(&empty_obj);
            Some(rpc_result(req_id, invoke_mcp_tool(name, args, repo_root, session)))
        }
        _ => Some(rpc_error(
            req_id,
            -32601,
            &format!("method not found: {}", method),
        )),
    }
}

fn invoke_mcp_tool(name: &str, args: &Json, repo_root: Option<&Path>, session: Option<&str>) -> Json {
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
                Json::Int(args.get_i64("max_bytes").unwrap_or(DEFAULT_READ_MAX_BYTES as i64)),
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
                Json::Int(args.get_i64("max_bytes").unwrap_or(DEFAULT_READ_MAX_BYTES as i64)),
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
                Json::Int(args.get_i64("max_bytes").unwrap_or(DEFAULT_READ_MAX_BYTES as i64)),
            ),
        ]),
        "ctx_search" => {
            let mut fields = vec![
                ("op".into(), Json::Str("search".to_string())),
                ("cwd".into(), Json::Str(cwd)),
                ("explicit_root".into(), Json::Bool(explicit_root)),
            ];
            for key in ["q", "query", "roots", "max_results", "context_lines", "detail", "queries"] {
                if let Some(value) = args.get(key) {
                    fields.push((key.into(), value.clone()));
                }
            }
            Json::Obj(fields)
        }
        "ctx_capsule" => {
            let mut fields = vec![("op".into(), Json::Str("capsule".into()))];
            for key in ["action", "workspace", "assignment", "key"] {
                if let Some(value) = args.get_str(key) {
                    fields.push((key.into(), Json::Str(value.into())));
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
                ("topic", Json::Str(args.get_str("topic").unwrap_or("").to_string())),
                ("summary", Json::Str(args.get_str("summary").unwrap_or("").to_string())),
                ("kind", args.get("kind").cloned().unwrap_or(Json::Null)),
                ("paths", args.get("paths").cloned().unwrap_or(Json::Arr(Vec::new()))),
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
        fields.push(("ctx_context".into(), Json::Str(ticket.into())));
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
        fields.push(("structuredContent".into(), data));
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

fn tool_schemas() -> Json {
    let str_array = Json::obj(vec![
        ("type", Json::Str("array".to_string())),
        ("items", Json::obj(vec![("type", Json::Str("string".to_string()))])),
    ]);

    let string = || Json::obj(vec![("type", Json::Str("string".into()))]);
    let mut tools = vec![
        Json::obj(vec![
            ("name", Json::Str("ctx_capsule".into())),
            ("description", Json::Str("Prepare or claim a host-addressed subagent launch capsule.".into())),
            ("inputSchema", Json::obj(vec![
                ("type", Json::Str("object".into())),
                ("properties", Json::obj(vec![
                    ("action", string()), ("assignment", string()), ("workspace", string()), ("key", string()),
                ])),
                ("required", Json::Arr(vec![Json::Str("action".into())])),
            ])),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_read".to_string())),
            (
                "description",
                Json::Str(
                    "Batch-read full files (<=1 MiB, no 800L cap) or `path:start-end` slices from RAM."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("paths", str_array.clone()),
                            ("max_bytes", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                            ("force", Json::obj(vec![("type", Json::Str("boolean".to_string()))])),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("paths".to_string())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_inspect".to_string())),
            (
                "description",
                Json::Str(
                    "Batch-inspect directories/files (<=80 default): lines, >=600L/>800L flags, ns, #include, [L_start-L_end] symbols."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("paths", str_array.clone()),
                            ("max_files", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                            ("max_bytes", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                            ("warn_lines", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("paths".to_string())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_outline".to_string())),
            (
                "description",
                Json::Str(
                    "Return structural [L_start-L_end] symbol outlines from RAM."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("paths", str_array.clone()),
                            ("max_files", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                            ("max_bytes", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("paths".to_string())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_symbols".to_string())),
            (
                "description",
                Json::Str(
                    "Batch symbol bodies (`path#Symbol`; shorthand filenames supported). Set compact=true for <=24L + continuation."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("requests", str_array.clone()),
                            ("compact", Json::obj(vec![("type", Json::Str("boolean".to_string()))])),
                            ("max_bytes", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("requests".to_string())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_search".to_string())),
            (
                "description",
                Json::Str(
                    "Fast RAM/SIMD search. Prefer `q`: [\"ModOrDir:pattern\", ...] (1-4 parallel searches; bare module stem matches .hpp+.cpp; lowercase = smart-case; `a|b` alternation). `query`+`roots` or `queries` also supported."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("q", str_array.clone()),
                            ("query", Json::obj(vec![("type", Json::Str("string".to_string()))])),
                            ("roots", str_array.clone()),
                            ("max_results", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                            ("context_lines", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                            ("detail", Json::obj(vec![
                                ("type", Json::Str("string".to_string())),
                                ("enum", Json::Arr(vec![Json::Str("compact".to_string()), Json::Str("scopes".to_string())])),
                            ])),
                            ("queries", Json::obj(vec![
                                ("type", Json::Str("array".to_string())),
                                ("minItems", Json::Int(1)),
                                ("maxItems", Json::Int(4)),
                                ("items", Json::obj(vec![
                                    ("type", Json::Str("object".to_string())),
                                    ("properties", Json::obj(vec![
                                        ("query", Json::obj(vec![("type", Json::Str("string".to_string()))])),
                                        ("roots", str_array.clone()),
                                        ("max_results", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                                        ("context_lines", Json::obj(vec![("type", Json::Str("integer".to_string()))])),
                                    ])),
                                    ("required", Json::Arr(vec![Json::Str("query".to_string()), Json::Str("roots".to_string())])),
                                ])),
                            ])),
                        ]),
                    ),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_memo".to_string())),
            (
                "description",
                Json::Str(
                    "Shared in-RAM workspace memo board (`put` | `get` | `list`) for frozen path maps, invariant notes, and cross-agent findings, automatically tagged `[STALE]` if linked files change."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("action", Json::obj(vec![
                                ("type", Json::Str("string".into())),
                                ("enum", Json::Arr(MEMO_ACTIONS.iter().map(|&action| Json::Str(action.into())).collect())),
                            ])),
                            ("topic", Json::obj(vec![("type", Json::Str("string".to_string()))])),
                            ("summary", Json::obj(vec![("type", Json::Str("string".to_string()))])),
                            ("kind", string()),
                            ("paths", str_array),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("action".to_string())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_elf_audit".to_string())),
            (
                "description",
                Json::Str(
                    "Read-only static ELF64 section/symbol and optional ASM audit for a compiled binary artifact."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("elf_path", Json::obj(vec![("type", Json::Str("string".to_string()))])),
                            ("asm_path", Json::obj(vec![("type", Json::Str("string".to_string()))])),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("elf_path".to_string())])),
                ]),
            ),
        ]),
    ];
    for tool in &mut tools {
        if let Json::Obj(fields) = tool {
            let read_only = fields.iter().any(|(key, value)| {
                key == "name" && matches!(value.as_str(),
                    Some("ctx_inspect" | "ctx_read" | "ctx_outline" | "ctx_symbols" | "ctx_search"))
            });
            if read_only {
                fields.push(("annotations".into(), Json::obj(vec![
                    ("readOnlyHint", Json::Bool(true)),
                    ("destructiveHint", Json::Bool(false)),
                    ("openWorldHint", Json::Bool(false)),
                ])));
            }
            if let Some((_, Json::Obj(schema))) = fields.iter_mut().find(|(key, _)| key == "inputSchema") {
                if let Some((_, Json::Obj(properties))) = schema.iter_mut().find(|(key, _)| key == "properties") {
                    properties.push(("ctx_context".into(), string()));
                }
            }
        }
    }
    Json::Arr(tools)
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
    let reply = handle_mcp_message_scoped(&init, repo_root, None).ok_or("initialize did not reply")?;
    if reply.get("result").and_then(|r| r.get_str("protocolVersion")) != Some(DEFAULT_WIRE_VER) {
        return Err("initialize did not return the default protocol version".into());
    }
    let reply = handle_mcp_message_scoped(&list, repo_root, None).ok_or("tools/list did not reply")?;
    let mut actual: Vec<_> = reply.get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Json::as_arr)
        .ok_or("tools/list did not return a tools array")?.iter()
        .map(|tool| tool.get_str("name").ok_or("tools/list returned a tool without a name"))
        .collect::<Result<_, _>>()?;
    actual.sort_unstable();
    let mut expected = expected_tool_names();
    expected.sort_unstable();
    if !actual.iter().copied().eq(expected.iter().map(String::as_str)) {
        return Err(format!("tools/list mismatch: expected {expected:?}, got {actual:?}"));
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
