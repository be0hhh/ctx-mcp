use super::*;
use crate::engine::{AGY_MCP_DEFAULT_MAX_BYTES, AGY_MCP_INLINE_CAP};
use crate::protocol::{execute_request, BrokerService};

#[test]
fn codex_exec_object_extracts_cmd_and_preserves_legacy_script() {
    let obj_input = Json::obj(vec![(
        "cmd",
        Json::Str("sed -n '1,80p' src/foo.cpp".to_string()),
    )]);
    assert_eq!(
        extract_codex_exec_commands("exec", &obj_input),
        vec!["sed -n '1,80p' src/foo.cpp".to_string()]
    );

    let legacy_script = Json::Str("run({ cmd: \"cat src/bar.cpp\" })".to_string());
    assert_eq!(
        extract_codex_exec_commands("exec", &legacy_script),
        vec!["cat src/bar.cpp".to_string()]
    );
}

#[test]
fn capsule_auto_stage_disabled_by_default_and_mcp_rewrite_narrowed() {
    if std::env::var("AGENT_CTX_ENABLE_CAPSULE").as_deref() == Ok("1") {
        return;
    }
    let workspace = std::env::temp_dir().join(format!(
        "ctx-hooks-unit-{}-{}",
        std::process::id(),
        crate::store::now_ms_u64()
    ));
    fs::create_dir(&workspace).unwrap();
    let big = (1..=300)
        .map(|i| format!("int field_{i:03} = {i}; // padding_payload_0123456789\n"))
        .collect::<String>();
    fs::write(workspace.join("Big.hpp"), &big).unwrap();

    let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
    svc.allowlist.register_hint(&workspace, true).unwrap();

    // 1. Auto-capsule staging is OFF by default on AGY `swarm` and Codex `spawn_agent`
    let agy_swarm = Json::obj(vec![
        ("hookEventName", Json::Str("PreToolUse".into())),
        ("conversationId", Json::Str("coord-1".into())),
        ("cwd", Json::Str(workspace.to_string_lossy().into_owned())),
        (
            "toolCall",
            Json::obj(vec![
                ("id", Json::Str("call-1".into())),
                ("name", Json::Str("swarm".into())),
                (
                    "args",
                    Json::obj(vec![
                        ("action", Json::Str("add".into())),
                        ("name", Json::Str("worker-1".into())),
                        ("brief", Json::Str("Inspect Big.hpp".into())),
                    ]),
                ),
            ]),
        ),
    ]);
    let swarm_reply = handle_hook(&svc, "agy", &agy_swarm.to_json_string());
    assert!(swarm_reply.get("overwrite").is_none());

    let codex_spawn = Json::obj(vec![
        ("hook_event_name", Json::Str("PreToolUse".into())),
        ("session_id", Json::Str("sess-1".into())),
        ("cwd", Json::Str(workspace.to_string_lossy().into_owned())),
        ("tool_name", Json::Str("spawn_agent".into())),
        (
            "tool_input",
            Json::obj(vec![
                ("agent_type", Json::Str("context_scout".into())),
                ("message", Json::Str("Locate Big.hpp".into())),
            ]),
        ),
    ]);
    let spawn_reply = handle_hook(&svc, "codex", &codex_spawn.to_json_string());
    assert!(spawn_reply.get("hookSpecificOutput").is_none());

    // 2. AGY `ctx_search` and `ctx_inspect` skip `ctx_context` rewrite; `ctx_read` gets it and enforces AGY default cap
    for readonly_tool in ["mcp_agent_ctx_ctx_search", "mcp_agent_ctx_ctx_inspect"] {
        let req = Json::obj(vec![
            ("hookEventName", Json::Str("PreToolUse".into())),
            ("conversationId", Json::Str("coord-1".into())),
            ("cwd", Json::Str(workspace.to_string_lossy().into_owned())),
            (
                "toolCall",
                Json::obj(vec![
                    ("id", Json::Str("call-ro".into())),
                    ("name", Json::Str(readonly_tool.into())),
                    ("args", Json::obj(vec![("paths", Json::Arr(vec![Json::Str("Big.hpp".into())]))])),
                ]),
            ),
        ]);
        let reply = handle_hook(&svc, "agy", &req.to_json_string());
        assert!(reply.get("overwrite").is_none(), "{readonly_tool} should not rewrite ctx_context");
    }

    let agy_read_hook = Json::obj(vec![
        ("hookEventName", Json::Str("PreToolUse".into())),
        ("conversationId", Json::Str("coord-1".into())),
        ("cwd", Json::Str(workspace.to_string_lossy().into_owned())),
        (
            "toolCall",
            Json::obj(vec![
                ("id", Json::Str("call-read".into())),
                ("name", Json::Str("mcp_agent_ctx_ctx_read".into())),
                ("args", Json::obj(vec![("paths", Json::Arr(vec![Json::Str("Big.hpp".into())]))])),
            ]),
        ),
    ]);
    let read_hook_reply = handle_hook(&svc, "agy", &agy_read_hook.to_json_string());
    let ticket = read_hook_reply
        .get("overwrite")
        .and_then(|v| v.get_str("ctx_context"))
        .expect("ctx_read must receive ctx_context ticket");

    let rpc = execute_request(
        &svc,
        &Json::obj(vec![
            ("op", Json::Str("read".into())),
            ("ctx_context", Json::Str(ticket.to_string())),
            ("paths", Json::Arr(vec![Json::Str("Big.hpp".into())])),
            ("max_bytes", Json::Int(0)),
        ]),
    );
    assert_eq!(rpc.get_bool("ok"), Some(true));
    let text = rpc.get_str("text").unwrap();
    assert!(text.len() <= AGY_MCP_INLINE_CAP);
    assert!(text.len() <= AGY_MCP_DEFAULT_MAX_BYTES + 256);

    // 3. `host = "agy"` also caps `inspect` to inline budget, while default host stays uncapped
    let agy_inspect = execute_request(
        &svc,
        &Json::obj(vec![
            ("op", Json::Str("inspect".into())),
            ("host", Json::Str("agy".into())),
            ("cwd", Json::Str(workspace.to_string_lossy().into_owned())),
            ("paths", Json::Arr(vec![Json::Str("Big.hpp".into())])),
        ]),
    );
    assert_eq!(agy_inspect.get_bool("ok"), Some(true));
    assert!(agy_inspect.get_str("text").unwrap().len() <= AGY_MCP_INLINE_CAP);

    fs::remove_dir_all(&workspace).unwrap();
}
