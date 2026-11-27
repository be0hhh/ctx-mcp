//! Claude Code (`claude`) hook handler.

use super::startup::startup_reply;
use super::{
    apply_launch_receipt, build_scoped_session_key, codex_deny, extract_cwd, host_context,
    is_workspace_mutating_shell, mcp_context_rewrite, parse_tool_input_field,
    register_payload_workspaces, workspace_grep_redirect_reason,
};
use crate::base::json::Json;
use crate::broker::key_in_assignment;
use crate::rpc::BrokerService;
use crate::store::resolve_input_path;

pub(super) fn handle_claude(svc: &BrokerService, payload: &Json) -> Json {
    let event = payload.get_str("hook_event_name").unwrap_or("");
    let ws_root = register_payload_workspaces(svc, payload);
    let cwd = extract_cwd(payload);
    let sess_key = build_scoped_session_key("claude", payload);

    if event == "PreCompact" {
        svc.store.clear_session(&sess_key);
        return Json::Obj(Vec::new());
    }

    if event == "SubagentStart" {
        return startup_reply(svc, payload, cwd.as_deref(), ws_root.as_deref());
    }

    let tool_name = payload.get_str("tool_name").unwrap_or("");
    let tool_input = parse_tool_input_field(payload);

    if event == "PreToolUse" {
        svc.store.bump_session_step(&sess_key);
        if let Some(context) = host_context("claude", payload, ws_root.as_deref()) {
            if let Some(reply) = mcp_context_rewrite(svc, payload, &context, tool_name, &tool_input)
            {
                return reply;
            }
            if matches!(tool_name, "Agent" | "Task") {
                if let (Some(key), Some(call_id)) = (
                    tool_input.get_str("prompt").and_then(key_in_assignment),
                    payload.get_str("tool_use_id"),
                ) {
                    svc.broker.capsules.record_launch(&context, key, call_id);
                }
                return Json::Obj(Vec::new());
            }
        }

        if tool_name == "Bash" {
            if let Some(cmd) = tool_input.get_str("command") {
                if let Some(reason) =
                    workspace_grep_redirect_reason(svc, "claude", &sess_key, cmd, cwd.as_deref())
                {
                    return codex_deny(&reason);
                }
            }
        } else if tool_name == "Read" {
            if let Some(fp) = tool_input.get_str("file_path") {
                let p = resolve_input_path(fp, cwd.as_deref());
                if let Ok((canon, root)) = svc.allowlist.admit_file(&p, cwd.as_deref()) {
                    let req_s = tool_input.get_usize("offset");
                    let req_e = match (req_s, tool_input.get_usize("limit")) {
                        (Some(o), Some(l)) => Some(o + l),
                        (None, Some(l)) => Some(l),
                        _ => None,
                    };
                    if let Some(dup) = svc.store.check_duplicate_read(
                        &sess_key,
                        &canon,
                        Some(&root),
                        req_s,
                        req_e,
                    ) {
                        return codex_deny(&format!(
                            "[RAM-Ctx] Already in your context: `{}` lines {}-{} of {} unchanged on disk. Outline: {}. (Repeat once if compacted.)",
                            dup.rel_path,
                            dup.covered_start,
                            dup.covered_end,
                            dup.total_lines,
                            dup.outline_summary
                        ));
                    }
                }
            }
        }
    } else if event == "PostToolUse" {
        if matches!(tool_name, "Agent" | "Task") {
            apply_launch_receipt(svc, "claude", payload, ws_root.as_deref());
        }
        if tool_name == "Read" {
            if let Some(fp) = tool_input.get_str("file_path") {
                let p = resolve_input_path(fp, cwd.as_deref());
                if let Ok((canon, root)) = svc.allowlist.admit_file(&p, cwd.as_deref()) {
                    if let Ok(entry) = svc.store.get_outline_entry(&canon, Some(&root)) {
                        let total_l = entry.line_count as usize;
                        let s = tool_input.get_usize("offset").unwrap_or(1).max(1);
                        let e = tool_input
                            .get_usize("limit")
                            .map(|l| (s + l).min(total_l))
                            .unwrap_or(total_l)
                            .max(s);
                        svc.store.record_read(&sess_key, &canon, Some(&root), s, e);
                    }
                }
            }
        } else if tool_name == "Edit" || tool_name == "MultiEdit" || tool_name == "Write" {
            if let Some(fp) = tool_input.get_str("file_path") {
                svc.store
                    .invalidate_path(&resolve_input_path(fp, cwd.as_deref()));
            }
            if tool_name == "Write" {
                svc.store.invalidate_workspace_indices();
            }
        } else if tool_name == "Bash" {
            if let Some(cmd) = tool_input.get_str("command") {
                if is_workspace_mutating_shell(cmd) {
                    svc.store.invalidate_workspace_indices();
                }
            }
        }
    }

    Json::Obj(Vec::new())
}
