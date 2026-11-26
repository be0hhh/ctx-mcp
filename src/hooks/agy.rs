//! Antigravity (`agy` / `antigravity`) hook handler:
//!   - `SessionStart` / `PreInvocation` turn-0 startup outline & memo injection.
//!   - `PreToolUse` MCP ticket binding, opt-in capsule staging, moved-file resolution,
//!     duplicate-read prevention with exact `800L / 46,080B` accounting, auto-widen for
//!     `<=800L & <=44KB` reads, and `BroadFind` / shell-slicing guards.
//!   - `PostToolUse` cache invalidation and exact delivered read-span recording.

use super::startup::{classify_agy_startup, prewarm_and_build_startup_capsule, AgyStartupKind};
use super::{
    capsule_auto_stage_enabled, delivery_notice, detect_shell_file_slicing, extract_cwd,
    host_context, is_internal_ide_path, is_workspace_mutating_shell, mcp_context_rewrite,
    passthrough, register_payload_workspaces, replace_field, AGY_NATIVE_DELIVERY_BYTE_CAP,
    AGY_NATIVE_LINE_CAP, AGY_WIDEN_MAX_BYTES,
};
use crate::base::json::{Json, JsonKey};
use crate::base::security::is_sensitive_path;
use crate::base::simd::fast_hash64;
use crate::broker::{HostContext, WorkspaceMode};
use crate::engine::walk_source_dir;
use crate::rpc::BrokerService;
use crate::store::{
    display_workspace_path, is_multimodal_or_binary_ext, resolve_input_path,
    restore_caller_path_style, CachedFile, MissingResolution, RamStore,
};
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};

fn is_lexically_inside_workspace(raw_str: &str, resolved: &Path, ws_root: &Path) -> bool {
    let raw_trim = raw_str.trim().trim_matches('"').trim_matches('\'');
    if !Path::new(raw_trim).is_absolute() && !raw_trim.starts_with("~/") {
        return !raw_trim.starts_with("..");
    }
    if resolved.starts_with(ws_root) {
        return true;
    }
    if let Ok(canon_root) = fs::canonicalize(ws_root) {
        if resolved.starts_with(&canon_root) {
            return true;
        }
    }
    false
}

/// Computes the exact 1-based end line delivered by Antigravity's native `read_file`,
/// which returns at most `800` lines OR `46,080` UTF-8 bytes starting from `StartLine` + `ByteOffset`.
fn compute_agy_delivered_end(
    entry: &CachedFile,
    start_line: usize,
    req_end: Option<usize>,
    byte_offset: usize,
) -> usize {
    let total = (entry.line_count as usize).max(1);
    let s = start_line.max(1).min(total);
    let line_cap_end = s.saturating_add(AGY_NATIVE_LINE_CAP - 1).min(total);
    let target_end = match req_end {
        Some(e) => e.max(s).min(line_cap_end),
        None => line_cap_end,
    };

    if entry.content.is_none() {
        return target_end;
    }

    let mut acc_bytes = 0usize;
    let mut delivered_end = s;
    let mut skipped_offset = 0usize;
    let max_present = entry.line_count as usize;

    for ln in s..=target_end.min(max_present) {
        let line = entry.line_slice(ln as u32);
        let line_bytes = line.len() + 1;
        if skipped_offset < byte_offset {
            let to_skip = (byte_offset - skipped_offset).min(line_bytes);
            skipped_offset += to_skip;
            acc_bytes += line_bytes - to_skip;
        } else {
            acc_bytes += line_bytes;
        }
        if acc_bytes > AGY_NATIVE_DELIVERY_BYTE_CAP && ln > s {
            break;
        }
        delivered_end = ln;
        if acc_bytes >= AGY_NATIVE_DELIVERY_BYTE_CAP {
            break;
        }
    }
    delivered_end
}

fn agy_capsule_rewrite(
    svc: &BrokerService,
    parent: &HostContext,
    call_id: &str,
    name: &str,
    args: &Json,
) -> Json {
    if call_id.is_empty() {
        return delivery_notice(
            "agy",
            "launch receipt unavailable; using the original assignment",
        );
    }
    let mut reason = None;
    let mut prepare = |index, mode_value: &str, brief: &str| {
        let result = WorkspaceMode::parse(mode_value)
            .map_err(str::to_owned)
            .and_then(|mode| {
                svc.broker
                    .capsules
                    .prepare(parent, mode, brief, Some(call_id), index)
            });
        result
            .map_err(|err| {
                reason = Some(err);
            })
            .ok()
    };
    let workspace_mode = args
        .get_str("Workspace")
        .or_else(|| args.get_str("workspace"))
        .unwrap_or("inherit");
    let mut changed: Option<(&'static str, Json)> = None;
    if name == "invoke_subagent" {
        if let Some((field, items)) = ["Subagents", "subagents"].iter().find_map(|&field| {
            args.get(field)
                .and_then(Json::as_arr)
                .map(|items| (field, items))
        }) {
            let updated = items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let mode = item
                        .get_str("Workspace")
                        .or_else(|| item.get_str("workspace"))
                        .unwrap_or(workspace_mode);
                    let brief = ["Prompt", "prompt", "Brief", "brief"]
                        .iter()
                        .find_map(|&key| item.get_str(key).map(|value| (key, value)));
                    match brief
                        .and_then(|(key, value)| prepare(index, mode, value).map(|text| (key, text)))
                    {
                        Some((key, text)) => replace_field(item, key, Json::Str(text)),
                        None => item.clone(),
                    }
                })
                .collect();
            changed = Some((field, Json::Arr(updated)));
        }
    } else if let Some(items) = args
        .get("tasks")
        .and_then(Json::as_arr)
        .filter(|items| !items.is_empty())
    {
        let updated = items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                item.as_str()
                    .and_then(|brief| prepare(index, workspace_mode, brief))
                    .map(Json::Str)
                    .unwrap_or_else(|| item.clone())
            })
            .collect();
        changed = Some(("tasks", Json::Arr(updated)));
    } else if args.get_usize("n").unwrap_or(1) == 1 {
        changed = args
            .get_str("brief")
            .and_then(|brief| prepare(0, workspace_mode, brief))
            .map(|brief| ("brief", Json::Str(brief)));
    } else {
        reason = Some("shared swarm brief has no individual launch address".into());
    }
    if let Some((field, rewritten)) = changed {
        let mut output = vec![
            ("decision", Json::Str("allow".into())),
            ("overwrite", Json::obj(vec![(field, rewritten)])),
        ];
        if let Some(reason) = reason {
            output.push(("reason", Json::Str(format!("[RAM-Ctx] {reason}"))));
        }
        Json::obj(output)
    } else {
        delivery_notice(
            "agy",
            reason
                .as_deref()
                .unwrap_or("unsupported dispatch shape; using the original assignment"),
        )
    }
}

fn detect_broad_source_find(
    svc: &BrokerService,
    cmd: &str,
    cwd: Option<&Path>,
) -> Option<Vec<String>> {
    let trimmed = cmd.trim();
    if trimmed.is_empty()
        || trimmed.contains("&&")
        || trimmed.contains("||")
        || trimmed.contains(';')
        || trimmed.contains("<<")
        || trimmed.contains(" >")
        || trimmed.contains(">>")
        || trimmed.contains("-delete")
        || trimmed.contains("-exec")
        || trimmed.contains("-maxdepth 1")
        || trimmed.contains("-maxdepth 2")
    {
        return None;
    }

    let stages: Vec<&str> = trimmed.split('|').map(|s| s.trim()).collect();
    if stages.is_empty() || stages.len() > 2 {
        return None;
    }
    if stages.len() == 2 {
        let pipe_prog = stages[1]
            .split_whitespace()
            .next()
            .and_then(|t| Path::new(t).file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if pipe_prog != "sort" {
            return None;
        }
    }

    let tokens: Vec<&str> = stages[0]
        .split_whitespace()
        .map(|t| t.trim_matches('"').trim_matches('\''))
        .collect();
    if tokens.first().copied() != Some("find") {
        return None;
    }

    let mut dir_roots: Vec<(String, PathBuf)> = Vec::new();
    for &tok in &tokens[1..] {
        if tok.starts_with('-') || tok == "(" || tok == ")" || tok == "!" {
            break;
        }
        let p = resolve_input_path(tok, cwd);
        if is_internal_ide_path(&p) || is_sensitive_path(&p) {
            return None;
        }
        if let Ok((canon_dir, ws_root)) = svc.allowlist.admit_dir(&p, cwd) {
            let rel = display_workspace_path(&canon_dir, Some(&ws_root));
            dir_roots.push((rel, canon_dir));
        }
    }
    if dir_roots.is_empty() {
        return None;
    }

    let mut total_files = 0usize;
    for (_, canon_dir) in &dir_roots {
        let mut probe = Vec::new();
        walk_source_dir(canon_dir, &mut probe, 45usize.saturating_sub(total_files));
        total_files += probe.len();
        if total_files > 40 {
            break;
        }
    }

    if total_files > 40 {
        Some(dir_roots.into_iter().map(|(rel, _)| rel).collect())
    } else {
        None
    }
}

pub(super) fn handle_agy(svc: &BrokerService, payload: &Json) -> Json {
    let event = payload.get_str("hookEventName").unwrap_or("");
    let conv_id = payload.get_str("conversationId").unwrap_or("");
    if conv_id.is_empty() {
        return passthrough("agy", event);
    }
    let ws_root = register_payload_workspaces(svc, payload);
    let cwd = extract_cwd(payload);
    let sess_key = format!("agy:{}", conv_id);

    // Antigravity fires `SessionStart` (not `PreInvocation`) before turn 0 of `swarm(action="add")`
    // workers, while `PreInvocation` fires on user turns and subsequent worker wakeups (`inv_num <= 1`).
    if event == "SessionStart" || event == "PreInvocation" {
        if event == "PreInvocation" {
            let inv_num = payload.get_i64("invocationNum").unwrap_or(0);
            if inv_num > 1 {
                return Json::Obj(Vec::new());
            }
        }
        if svc.store.has_startup_settled(&sess_key) {
            return Json::Obj(Vec::new());
        }
        match classify_agy_startup(payload, conv_id) {
            AgyStartupKind::RootUser | AgyStartupKind::IgnoreAux => {
                let _ = svc.store.try_mark_startup_injected(&sess_key);
                return Json::Obj(Vec::new());
            }
            AgyStartupKind::Undetermined => {
                return Json::Obj(Vec::new());
            }
            AgyStartupKind::Worker {
                brief: transcript_brief,
            } => {
                if svc.store.try_mark_startup_injected(&sess_key) {
                    let msg = prewarm_and_build_startup_capsule(
                        svc,
                        &transcript_brief,
                        cwd.as_deref(),
                        ws_root.as_deref(),
                        true,
                    );
                    return Json::obj(vec![(
                        "injectSteps",
                        Json::Arr(vec![Json::obj(vec![(
                            "systemMessage",
                            Json::obj(vec![("systemMessage", Json::Str(msg))]),
                        )])]),
                    )]);
                }
            }
        }
        return Json::Obj(Vec::new());
    }

    if event == "PreToolUse" {
        let Some(tc) = payload.get("toolCall") else {
            return passthrough("agy", event);
        };
        let tool_name = tc.get_str("name").unwrap_or("");
        let call_id = tc.get_str("id").unwrap_or("");
        let empty_args = Json::Obj(Vec::new());
        let args = tc.get("args").unwrap_or(&empty_args);

        if !call_id.is_empty() {
            let dedup = format!("agy:{}:Pre:{}", conv_id, call_id);
            if svc.store.check_and_mark_dedup(&dedup) {
                return passthrough("agy", event);
            }
        }
        svc.store.bump_session_step(&sess_key);

        if let Some(context) = host_context("agy", payload, ws_root.as_deref()) {
            if let Some(reply) = mcp_context_rewrite(svc, payload, &context, tool_name, args) {
                return reply;
            }
            if capsule_auto_stage_enabled()
                && (tool_name == "invoke_subagent"
                    || (tool_name == "swarm" && args.get_str("action") == Some("add")))
            {
                return agy_capsule_rewrite(svc, &context, call_id, tool_name, args);
            }
        }

        if tool_name == "read_file" || tool_name == "view_file" {
            let path_key: &'static str = if args.get("AbsolutePath").is_some() {
                "AbsolutePath"
            } else {
                "Path"
            };
            let Some(raw_path) = args.get_str(path_key) else {
                return passthrough("agy", event);
            };
            let path = resolve_input_path(raw_path, cwd.as_deref());
            if is_internal_ide_path(&path)
                || is_multimodal_or_binary_ext(&path)
                || is_sensitive_path(&path)
            {
                return passthrough("agy", event);
            }

            // Moved / missing file auto-resolution via in-RAM WorkspaceIndex
            if !path.exists() {
                if let Some(ref root) = ws_root {
                    if is_lexically_inside_workspace(raw_path, &path, root) {
                        match svc.store.resolve_missing_path(&path, root) {
                            MissingResolution::Unique(real_path) => {
                                let mut new_args: Vec<(JsonKey, Json)> = Vec::new();
                                if let Some(existing) = args.as_obj() {
                                    for (k, v) in existing {
                                        if k.as_ref() != path_key {
                                            new_args.push((k.clone(), v.clone()));
                                        }
                                    }
                                }
                                new_args.push((
                                    Cow::Borrowed(path_key),
                                    Json::Str(restore_caller_path_style(raw_path, &real_path)),
                                ));
                                return Json::obj(vec![
                                    ("decision", Json::Str("ask".to_string())),
                                    ("overwrite", Json::Obj(new_args)),
                                ]);
                            }
                            MissingResolution::Ambiguous(cands) => {
                                let rels: Vec<String> = cands
                                    .iter()
                                    .map(|p| display_workspace_path(p, Some(root)))
                                    .collect();
                                let reason = format!(
                                    "[RAM-Ctx] `{}` does not exist at that path. Matching workspace files: {}. Call `{}` on the exact target path.",
                                    raw_path,
                                    rels.join(", "),
                                    tool_name
                                );
                                return Json::obj(vec![
                                    ("decision", Json::Str("deny".to_string())),
                                    ("reason", Json::Str(reason)),
                                ]);
                            }
                            MissingResolution::NotFound => {}
                        }
                    }
                }
                return passthrough("agy", event);
            }

            if !path.is_file() || args.get("ByteOffset").is_some() {
                return passthrough("agy", event);
            }

            // Non-workspace paths (`~/.agents/skills/**`, etc.) pass through untouched
            let Ok((canon, root)) = svc.allowlist.admit_file(&path, cwd.as_deref()) else {
                return passthrough("agy", event);
            };

            let req_start = args.get_usize("StartLine");
            let req_end = args.get_usize("EndLine");

            if let Ok(entry) = svc.store.get_full_entry(&canon, Some(&root)) {
                let s = req_start.unwrap_or(1).max(1);
                let effective_end = compute_agy_delivered_end(&entry, s, req_end, 0);

                // 1. Duplicate read check against exact delivered span (with 1-strike escape)
                if let Some(dup) = svc.store.check_duplicate_read(
                    &sess_key,
                    &canon,
                    Some(&root),
                    Some(s),
                    Some(effective_end),
                ) {
                    let unread_str = if dup.unread_ranges.is_empty() {
                        "none (entire file already read)".to_string()
                    } else {
                        dup.unread_ranges
                            .iter()
                            .map(|(a, b)| format!("{}-{}", a, b))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    let reason = format!(
                        "[RAM-Ctx] Already in your context: `{}` lines {}-{} of {} are unchanged on disk. Reuse them directly without re-reading. Unread ranges: {}. Outline: {}. (If context was compacted, repeat this exact read once to bypass.)",
                        dup.rel_path,
                        dup.covered_start,
                        dup.covered_end,
                        dup.total_lines,
                        unread_str,
                        dup.outline_summary
                    );
                    return Json::obj(vec![
                        ("decision", Json::Str("deny".to_string())),
                        ("reason", Json::Str(reason)),
                    ]);
                }

                // 2. Auto-widen small top-of-file pagination chunks on <=800L & <=44KB workspace files
                //    (Never deny >800L files in Antigravity!)
                let lines = (entry.line_count as usize).max(1);
                let size_b = entry.size_bytes;
                if lines <= AGY_NATIVE_LINE_CAP && size_b <= AGY_WIDEN_MAX_BYTES {
                    if let (Some(1), Some(e)) = (req_start, req_end) {
                        if e < lines && e <= 500 {
                            let mut new_args: Vec<(JsonKey, Json)> = Vec::new();
                            if let Some(existing) = args.as_obj() {
                                for (k, v) in existing {
                                    if k.as_ref() != "StartLine" && k.as_ref() != "EndLine" {
                                        new_args.push((k.clone(), v.clone()));
                                    }
                                }
                            }
                            if !new_args.iter().any(|(k, _)| k.as_ref() == path_key) {
                                new_args
                                    .push((Cow::Borrowed(path_key), Json::Str(raw_path.to_string())));
                            }
                            new_args.push((Cow::Borrowed("StartLine"), Json::Int(1)));
                            new_args.push((Cow::Borrowed("EndLine"), Json::Int(lines as i64)));
                            return Json::obj(vec![
                                ("decision", Json::Str("ask".to_string())),
                                ("overwrite", Json::Obj(new_args)),
                            ]);
                        }
                    }
                }
            }
            return passthrough("agy", event);
        }

        if tool_name == "run_command" {
            if let Some(cmd) = args.get_str("CommandLine") {
                if let Some(broad_roots) = detect_broad_source_find(svc, cmd, cwd.as_deref()) {
                    let strike_key = format!(
                        "agy:{}:BroadFind:{:016x}",
                        conv_id,
                        fast_hash64(cmd.as_bytes())
                    );
                    if !svc.store.check_and_mark_dedup(&strike_key) {
                        let paths_json: Vec<String> = broad_roots
                            .iter()
                            .take(6)
                            .map(|r| format!("\"{}\"", r))
                            .collect();
                        let reason = format!(
                            "[RAM-Ctx] Broad `find` over >40 source files truncates >10KB output into `output.txt` and wastes a turn. Query the in-RAM index directly in 1 step via `mcp_agent_ctx_ctx_inspect({{\"paths\": [{}], \"max_files\": 80}})` / `mcp_agent_ctx_ctx_search({{\"query\": \"...\", \"roots\": [{}]}})` (or `call_mcp_tool(ServerName=\"agent_ctx\", ToolName=\"ctx_inspect\", Arguments={{\"paths\": [{}], \"max_files\": 80}})`). (Repeat this exact `find` once if raw filesystem paths are strictly required.)",
                            paths_json.join(", "),
                            paths_json.join(", "),
                            paths_json.join(", ")
                        );
                        return Json::obj(vec![
                            ("decision", Json::Str("deny".to_string())),
                            ("reason", Json::Str(reason)),
                        ]);
                    }
                }
                if let Some(hit) = detect_shell_file_slicing(svc, cmd, cwd.as_deref()) {
                    let outline = svc
                        .store
                        .get_outline_entry(&hit.target_path, Some(&hit.ws_root))
                        .map(|e| RamStore::format_outline_compact(&e, 10))
                        .unwrap_or_default();
                    let rel = display_workspace_path(&hit.target_path, Some(&hit.ws_root));
                    let reason = format!(
                        "[RAM-Ctx] Avoid shell file-slicing (`cat`/`sed`/`head`/`nl`) on `{}`. Use `read_file` (up to 800L / 46KB inline) or `ctx_symbols` (`{}#<Symbol>`). Cached outline: {}",
                        rel, rel, outline
                    );
                    return Json::obj(vec![
                        ("decision", Json::Str("deny".to_string())),
                        ("reason", Json::Str(reason)),
                    ]);
                }
            }
        }

        return passthrough("agy", event);
    }

    if event == "PostToolUse" {
        if let Some(err) = payload.get_str("error") {
            if !err.is_empty() {
                return Json::Obj(Vec::new());
            }
        }
        let Some(tc) = payload.get("toolCall") else {
            return Json::Obj(Vec::new());
        };
        let tool_name = tc.get_str("name").unwrap_or("");
        let call_id = tc.get_str("id").unwrap_or("");
        if !call_id.is_empty() {
            let dedup = format!("agy:{}:Post:{}", conv_id, call_id);
            if svc.store.check_and_mark_dedup(&dedup) {
                return Json::Obj(Vec::new());
            }
        }
        let empty_args = Json::Obj(Vec::new());
        let args = tc.get("args").unwrap_or(&empty_args);

        if matches!(
            tool_name,
            "edit_file"
                | "write_file"
                | "write_to_file"
                | "replace_file_content"
                | "multi_replace_file_content"
                | "create_file"
                | "delete_file"
                | "rename_file"
        ) {
            let mut any_invalidated = false;
            for key in &[
                "Path",
                "AbsolutePath",
                "TargetFile",
                "TargetPath",
                "file_path",
                "OldPath",
                "NewPath",
            ] {
                if let Some(raw_p) = args.get_str(key) {
                    let p = resolve_input_path(raw_p, cwd.as_deref());
                    svc.store.invalidate_path(&p);
                    any_invalidated = true;
                }
            }
            if matches!(
                tool_name,
                "write_file" | "write_to_file" | "create_file" | "delete_file" | "rename_file"
            ) || !any_invalidated
            {
                svc.store.invalidate_workspace_indices();
            }
        } else if tool_name == "run_command" {
            if let Some(cmd) = args.get_str("CommandLine") {
                if is_workspace_mutating_shell(cmd) {
                    svc.store.invalidate_workspace_indices();
                }
            }
        } else if tool_name == "read_file" || tool_name == "view_file" {
            let byte_off = args.get_usize("ByteOffset").unwrap_or(0);
            if byte_off == 0 {
                if let Some(raw_p) = args.get_str("Path").or_else(|| args.get_str("AbsolutePath"))
                {
                    let p = resolve_input_path(raw_p, cwd.as_deref());
                    if !is_internal_ide_path(&p)
                        && !is_multimodal_or_binary_ext(&p)
                        && !is_sensitive_path(&p)
                    {
                        if let Ok((canon, root)) = svc.allowlist.admit_file(&p, cwd.as_deref()) {
                            if let Ok(entry) = svc.store.get_full_entry(&canon, Some(&root)) {
                                let s = args.get_usize("StartLine").unwrap_or(1).max(1);
                                let req_end = args.get_usize("EndLine");
                                let delivered_end =
                                    compute_agy_delivered_end(&entry, s, req_end, byte_off);
                                svc.store.record_read(
                                    &sess_key,
                                    &canon,
                                    Some(&root),
                                    s,
                                    delivered_end,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Json::Obj(Vec::new())
}
