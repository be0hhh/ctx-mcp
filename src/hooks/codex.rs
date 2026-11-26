//! Codex CLI (`codex`) hook handler.

use super::startup::startup_reply;
use super::{
    apply_launch_receipt, build_scoped_session_key, capsule_auto_stage_enabled, codex_deny,
    delivery_notice, detect_shell_file_slicing, extract_cwd, host_context,
    is_workspace_mutating_shell, mcp_context_rewrite, parse_tool_input_field,
    register_payload_workspaces, replace_field, rewrite_input,
};
use crate::base::json::{self, Json};
use crate::broker::{HostContext, WorkspaceMode};
use crate::rpc::BrokerService;
use crate::store::{resolve_input_path, RamStore, MAX_SINGLE_FILE_CACHE_BYTES};

fn codex_capsule_rewrite(
    svc: &BrokerService,
    parent: &HostContext,
    payload: &Json,
    args: &Json,
) -> Json {
    let Some(call_id) = payload
        .get_str("tool_use_id")
        .filter(|value| !value.is_empty())
    else {
        return delivery_notice(
            "codex",
            "launch receipt unavailable; using the original assignment",
        );
    };
    let Some((field, brief)) = ["message", "prompt", "instructions"]
        .iter()
        .find_map(|&field| args.get_str(field).map(|brief| (field, brief)))
    else {
        return Json::Obj(Vec::new());
    };
    match svc
        .broker
        .capsules
        .prepare(parent, WorkspaceMode::Inherit, brief, Some(call_id), 0)
    {
        Ok(assignment) => rewrite_input("codex", replace_field(args, field, Json::Str(assignment))),
        Err(reason) => delivery_notice("codex", &reason),
    }
}

pub(super) fn extract_codex_exec_commands(tool_name: &str, tool_input: &Json) -> Vec<String> {
    let mut cmds = Vec::new();
    if matches!(tool_name, "exec_command" | "Bash" | "shell" | "run_command") {
        if let Some(c) = tool_input
            .get_str("cmd")
            .or_else(|| tool_input.get_str("command"))
            .or_else(|| tool_input.get_str("CommandLine"))
        {
            cmds.push(c.to_string());
        } else if let Some(arr) = tool_input.get("command").and_then(|v| v.as_arr()) {
            if let Some(last) = arr.last().and_then(|v| v.as_str()) {
                cmds.push(last.to_string());
            }
        }
        return cmds;
    }
    if tool_name == "exec" {
        if let Some(c) = tool_input
            .get_str("cmd")
            .or_else(|| tool_input.get_str("command"))
        {
            cmds.push(c.to_string());
            return cmds;
        }
        let script = tool_input
            .as_str()
            .or_else(|| tool_input.get_str("script"))
            .or_else(|| tool_input.get_str("code"))
            .or_else(|| tool_input.get_str("input"))
            .unwrap_or("");
        let mut rest = script;
        while let Some(pos) = rest.find("cmd") {
            rest = &rest[pos + 3..];
            let trimmed = rest.trim_start();
            if let Some(after_colon) = trimmed.strip_prefix(':') {
                let val_trim = after_colon.trim_start();
                if val_trim.starts_with('"') {
                    if let Some(end_q) = find_closing_quote(val_trim) {
                        if let Ok(Json::Str(parsed)) = json::parse(&val_trim[..=end_q]) {
                            cmds.push(parsed);
                        }
                    }
                }
            }
        }
    }
    cmds
}

fn extract_apply_patch_paths(tool_name: &str, payload: &Json, tool_input: &Json) -> Vec<String> {
    let mut texts: Vec<&str> = Vec::new();
    if tool_name == "apply_patch" {
        if let Some(s) = tool_input.as_str() {
            texts.push(s);
        }
        for key in &["patch", "input", "diff", "content", "cmd", "command"] {
            if let Some(s) = tool_input.get_str(key) {
                texts.push(s);
            }
        }
        if let Some(s) = payload.get_str("tool_input") {
            texts.push(s);
        }
    } else {
        for key in &["cmd", "command", "CommandLine", "script", "code", "input"] {
            if let Some(s) = tool_input.get_str(key) {
                if s.contains("*** ") && s.contains(" File:") {
                    texts.push(s);
                }
            }
        }
    }

    let mut paths = Vec::new();
    for txt in texts {
        for line in txt.lines() {
            let trimmed = line.trim();
            for prefix in &[
                "*** Update File:",
                "*** Add File:",
                "*** Delete File:",
                "*** Move to:",
            ] {
                if let Some(rest) = trimmed.strip_prefix(prefix) {
                    let p = rest.trim().to_string();
                    if !p.is_empty() && !paths.contains(&p) {
                        paths.push(p);
                    }
                }
            }
        }
    }
    paths
}

fn find_closing_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub(super) fn handle_codex(svc: &BrokerService, payload: &Json) -> Json {
    let event = payload.get_str("hook_event_name").unwrap_or("");
    let ws_root = register_payload_workspaces(svc, payload);
    let cwd = extract_cwd(payload);
    let sess_key = build_scoped_session_key("codex", payload);

    if event == "SessionStart" {
        let src = payload.get_str("source").unwrap_or("");
        if src == "compact" || src == "clear" {
            svc.store.clear_session(&sess_key);
        }
        return Json::Obj(Vec::new());
    }

    if event == "SubagentStart" {
        return startup_reply(svc, payload, cwd.as_deref(), ws_root.as_deref());
    }

    if event == "PreToolUse" {
        let tool_name = payload.get_str("tool_name").unwrap_or("");
        let tool_input = parse_tool_input_field(payload);
        svc.store.bump_session_step(&sess_key);

        if let Some(context) = host_context("codex", payload, ws_root.as_deref()) {
            if let Some(reply) = mcp_context_rewrite(svc, payload, &context, tool_name, &tool_input)
            {
                return reply;
            }
            if capsule_auto_stage_enabled() && matches!(tool_name, "spawn_agent" | "Agent") {
                return codex_capsule_rewrite(svc, &context, payload, &tool_input);
            }
        }

        let cmds = extract_codex_exec_commands(tool_name, &tool_input);
        for cmd in cmds {
            if let Some(hit) = detect_shell_file_slicing(svc, &cmd, cwd.as_deref()) {
                if let Some(dup) = svc.store.check_duplicate_read(
                    &sess_key,
                    &hit.target_path,
                    Some(&hit.ws_root),
                    hit.start_line,
                    hit.end_line,
                ) {
                    return codex_deny(&format!(
                        "[RAM-Ctx] Already in your context: `{}` lines {}-{} of {} unchanged on disk. Reuse existing context or run `ctx read --force \"{}\"`.",
                        dup.rel_path,
                        dup.covered_start,
                        dup.covered_end,
                        dup.total_lines,
                        dup.rel_path
                    ));
                }
                if let (Some(s), Some(e)) = (hit.start_line, hit.end_line) {
                    if let Ok(entry) = svc
                        .store
                        .get_outline_entry(&hit.target_path, Some(&hit.ws_root))
                    {
                        let total_l = entry.line_count as usize;
                        if s == 1
                            && e < total_l
                            && e <= 350
                            && entry.size_bytes as usize <= MAX_SINGLE_FILE_CACHE_BYTES
                        {
                            let outline = RamStore::format_outline_compact(&entry, 10);
                            return codex_deny(&format!(
                                "[RAM-Ctx] Avoid paginating `{}` ({}L) in small `sed` chunks. Read the whole file in 1 call via `ctx read \"{}\"` (up to 1 MiB) or read exact symbols via `ctx sym \"{}#<Symbol>\"`. Outline: {}",
                                entry.rel_path, entry.line_count, entry.rel_path, entry.rel_path, outline
                            ));
                        }
                    }
                }
            }
        }
        return Json::Obj(Vec::new());
    }

    if event == "PostToolUse" {
        let tool_name = payload.get_str("tool_name").unwrap_or("");
        let tool_input = parse_tool_input_field(payload);

        if matches!(tool_name, "spawn_agent" | "Agent") {
            apply_launch_receipt(svc, "codex", payload, ws_root.as_deref());
        }

        let patched = extract_apply_patch_paths(tool_name, payload, &tool_input);
        if !patched.is_empty() || tool_name == "apply_patch" {
            for rel_or_abs in patched {
                let p = resolve_input_path(&rel_or_abs, cwd.as_deref());
                svc.store.invalidate_path(&p);
            }
            svc.store.invalidate_workspace_indices();
        }

        let cmds = extract_codex_exec_commands(tool_name, &tool_input);
        for cmd in cmds {
            if is_workspace_mutating_shell(&cmd) {
                svc.store.invalidate_workspace_indices();
            }
            if let Some(hit) = detect_shell_file_slicing(svc, &cmd, cwd.as_deref()) {
                if let Ok(entry) = svc
                    .store
                    .get_outline_entry(&hit.target_path, Some(&hit.ws_root))
                {
                    let total_l = entry.line_count as usize;
                    let s = hit.start_line.unwrap_or(1).max(1);
                    let e = hit.end_line.unwrap_or(total_l).min(total_l).max(s);
                    svc.store
                        .record_read(&sess_key, &hit.target_path, Some(&hit.ws_root), s, e);
                }
            }
        }
    }

    Json::Obj(Vec::new())
}
