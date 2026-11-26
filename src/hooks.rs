// Sub-millisecond lifecycle hook router (`ctx hook <agy|codex|claude>`):
//   - Strict per-agent isolation (`agy:{conversationId}`, `codex:{session_id}:{agent_id}`,
//     `claude:{session_id}:{agent_id}`).
//   - Addressed `TaskCapsule` staging & claiming + `ctx_memo` digest injection.
//   - Antigravity turn-0 `PreInvocation` parsing paired swarm briefs from `transcript.jsonl` /
//     `transcript_full.jsonl` when `invocationNum` is omitted in protojson and `lastUserInput` is empty.
//   - Non-blocking `> 800L` `read_file` in Antigravity with exact `800 lines` / `46,080 bytes`
//     delivery accounting in `PostToolUse`, plus `WorkspaceIndex` moved-file auto-resolution.

use crate::capsule::{key_in_assignment, HostContext, Recipient, WorkspaceMode};
use crate::engine::walk_source_dir;
use crate::json::{self, Json};
use crate::protocol::BrokerService;
use crate::security::is_sensitive_path;
use crate::store::{
    display_workspace_path, fnv1a_64, is_multimodal_or_binary_ext, norm_key_from_canon,
    resolve_input_path, restore_caller_path_style, CachedFile, MissingResolution, RamStore,
    MAX_SINGLE_FILE_CACHE_BYTES,
};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const AGY_NATIVE_LINE_CAP: usize = 800;
const AGY_NATIVE_DELIVERY_BYTE_CAP: usize = 46_080;
const AGY_WIDEN_MAX_BYTES: u32 = 44_000;
const STARTUP_BUDGET_BYTES: usize = 2500;

const SUBAGENT_REPORT_DIGEST: &str = "Subagent report (skip ReportFormat.md): \
Outcome (answer/change + paths), Evidence (symbols/lines; `static-only` if unrun), \
Boundaries (callers/shared files), Integration (risks). \
Batch calls: ctx_inspect (dirs), ctx_search (`q`: 1-4 `Mod:pat`), ctx_symbols (`compact=true`), ctx_read (slices >800L in AGY or full files <=1MiB in Codex); use CLI `ctx inspect|search|outline|sym` if MCP is absent (e.g., swarm workers). Finish from search/symbols when sufficient.";

const AGY_LAZY_MCP_SIGNATURES: &str = "In Antigravity: call eager mcp_agent_ctx_* tools directly (`ctx_search`, `ctx_inspect`, `ctx_read`, `ctx_symbols`) and prefer parallel native `read_file` (<=800L/46KB inline) for full files; use `call_mcp_tool` for lazy tools (`ctx_outline`, `ctx_memo`, `ctx_elf_audit`) or CLI `ctx` when MCP is absent.";

#[inline]
fn capsule_auto_stage_enabled() -> bool {
    std::env::var("AGENT_CTX_ENABLE_CAPSULE").ok().as_deref() == Some("1")
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum HostFlavor {
    Agy = 1,
    Codex = 2,
    Claude = 3,
}

impl HostFlavor {
    #[inline]
    fn parse(s: &str) -> Option<Self> {
        match s {
            "agy" | "antigravity" => Some(Self::Agy),
            "codex" => Some(Self::Codex),
            "claude" => Some(Self::Claude),
            _ => None,
        }
    }
}

pub fn handle_hook(svc: &BrokerService, flavor: &str, raw_stdin: &str) -> Json {
    let Ok(payload) = json::parse(raw_stdin) else {
        return passthrough_raw(flavor, raw_stdin);
    };
    match HostFlavor::parse(flavor) {
        Some(HostFlavor::Agy) => handle_agy(svc, &payload),
        Some(HostFlavor::Codex) => handle_codex(svc, &payload),
        Some(HostFlavor::Claude) => handle_claude(svc, &payload),
        None => Json::Obj(Vec::new()),
    }
}

pub fn passthrough(flavor: &str, event: &str) -> Json {
    if (flavor == "agy" || flavor == "antigravity") && event == "PreToolUse" {
        Json::obj(vec![("decision", Json::Str("allow".to_string()))])
    } else {
        Json::Obj(Vec::new())
    }
}

pub fn passthrough_raw(flavor: &str, raw_stdin: &str) -> Json {
    if (flavor == "agy" || flavor == "antigravity") && raw_stdin.contains("\"PreToolUse\"") {
        Json::obj(vec![("decision", Json::Str("ask".to_string()))])
    } else {
        Json::Obj(Vec::new())
    }
}

pub fn should_skip_global_duplicate(flavor: &str, raw_stdin: &str) -> bool {
    let Ok(payload) = json::parse(raw_stdin) else {
        return false;
    };
    let cwd = extract_cwd(&payload);
    let Some(base) = cwd.as_deref() else {
        return false;
    };
    let mut cur: Option<&Path> = Some(base);
    while let Some(dir) = cur {
        let marker = match flavor {
            "agy" | "antigravity" => dir.join(".agents").join("hooks.json"),
            "codex" => dir.join(".codex").join("hooks.json"),
            _ => PathBuf::new(),
        };
        if !marker.as_os_str().is_empty() && marker.is_file() {
            if let Ok(txt) = fs::read_to_string(&marker) {
                if txt.contains("agent-context")
                    || txt.contains("cxet-agent-context")
                    || txt.contains("hook agy")
                    || txt.contains("hook codex")
                    || txt.contains("run_ctx.py")
                {
                    return true;
                }
            }
        }
        cur = dir.parent();
    }
    false
}

fn extract_cwd(payload: &Json) -> Option<PathBuf> {
    if let Some(s) = payload.get_str("cwd") {
        if !s.trim().is_empty() {
            return Some(resolve_input_path(s, None));
        }
    }
    if let Some(arr) = payload.get("workspacePaths").and_then(|v| v.as_arr()) {
        if let Some(first) = arr.first().and_then(|v| v.as_str()) {
            if !first.trim().is_empty() {
                return Some(resolve_input_path(first, None));
            }
        }
    }
    None
}

fn register_payload_workspaces(svc: &BrokerService, payload: &Json) -> Option<PathBuf> {
    let mut primary_ws = None;
    if let Some(arr) = payload.get("workspacePaths").and_then(|v| v.as_arr()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                if !s.trim().is_empty() {
                    let resolved = resolve_input_path(s, None);
                    if let Some(r) = svc.allowlist.register_hint(&resolved, false) {
                        if primary_ws.is_none() {
                            primary_ws = Some(r);
                        }
                    }
                }
            }
        }
    }
    if let Some(c) = extract_cwd(payload) {
        if let Some(r) = svc.allowlist.register_hint(&c, false) {
            primary_ws = Some(r);
        }
    }
    primary_ws
}

fn extract_child_agent_scope(payload: &Json) -> Option<String> {
    for key in &["agent_id", "subagent_id", "thread_id", "agentId", "subagentId"] {
        if let Some(v) = payload.get_str(key) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    for tkey in &["agent_transcript_path", "subagent_transcript_path"] {
        if let Some(tp) = payload.get_str(tkey) {
            if let Some(stem) = Path::new(tp).file_stem().and_then(|s| s.to_str()) {
                if !stem.is_empty() {
                    return Some(stem.to_string());
                }
            }
        }
    }
    None
}

fn build_scoped_session_key(flavor: &str, payload: &Json) -> (String, Option<String>) {
    let session_id = payload.get_str("session_id").unwrap_or("default");
    let scope_opt = extract_child_agent_scope(payload);
    let scope = scope_opt.as_deref().unwrap_or("root");
    (format!("{}:{}:{}", flavor, session_id, scope), scope_opt)
}

fn host_context(host: &'static str, payload: &Json, root: Option<&Path>) -> Option<HostContext> {
    let session = payload.get_str(if host == "agy" { "conversationId" } else { "session_id" })?;
    if session.is_empty() {
        return None;
    }
    let root = root?;
    if payload.get_str("cwd").is_none()
        && payload.get("workspacePaths").and_then(Json::as_arr).is_some_and(|paths| paths.len() != 1)
    {
        return None;
    }
    if !fs::canonicalize(extract_cwd(payload)?).ok()?.starts_with(root) {
        return None;
    }
    let agent = if host == "agy" { Some(session) } else { payload.get_str("agent_id") }
        .filter(|id| !id.is_empty()).map(str::to_owned);
    Some(HostContext { host, session: session.into(), agent, workspace: root.to_path_buf(), codex_origin: None })
}

fn replace_field(args: &Json, field: &str, value: Json) -> Json {
    let mut fields = args.as_obj().unwrap_or_default().to_vec();
    fields.retain(|(name, _)| name != field);
    fields.push((field.into(), value));
    Json::Obj(fields)
}

fn rewrite_input(host: &str, args: Json) -> Json {
    if host == "agy" {
        return Json::obj(vec![("decision", Json::Str("allow".into())), ("overwrite", args)]);
    }
    let mut output = vec![
        ("hookEventName", Json::Str("PreToolUse".into())),
        ("updatedInput", args),
    ];
    // Claude's "allow" skips its permission prompt. Keep the native decision.
    if host == "codex" {
        output.push(("permissionDecision", Json::Str("allow".into())));
    }
    Json::obj(vec![("hookSpecificOutput", Json::obj(output))])
}

fn delivery_notice(host: &str, reason: &str) -> Json {
    let reason = format!("[RAM-Ctx] {reason}");
    if host == "agy" {
        Json::obj(vec![("decision", Json::Str("allow".into())), ("reason", Json::Str(reason))])
    } else {
        Json::obj(vec![("systemMessage", Json::Str(reason))])
    }
}

fn startup_reply(svc: &BrokerService, payload: &Json, cwd: Option<&Path>, root: Option<&Path>) -> Json {
    let brief = payload.get_str("prompt").unwrap_or_default();
    let context = prewarm_and_build_startup_capsule(svc, brief, cwd, root, false);
    Json::obj(vec![("hookSpecificOutput", Json::obj(vec![
        ("hookEventName", Json::Str("SubagentStart".into())),
        ("additionalContext", Json::Str(context)),
    ]))])
}

fn codex_capsule_rewrite(svc: &BrokerService, parent: &HostContext, payload: &Json, args: &Json) -> Json {
    let Some(call_id) = payload.get_str("tool_use_id").filter(|value| !value.is_empty()) else {
        return delivery_notice("codex", "launch receipt unavailable; using the original assignment");
    };
    let Some((field, brief)) = ["message", "prompt", "instructions"].iter()
        .find_map(|&field| args.get_str(field).map(|brief| (field, brief)))
    else {
        return Json::obj(vec![]);
    };
    match svc.broker.capsules.prepare(parent, WorkspaceMode::Inherit, brief, Some(call_id), 0) {
        Ok(assignment) => rewrite_input("codex", replace_field(args, field, Json::Str(assignment))),
        Err(reason) => delivery_notice("codex", &reason),
    }
}

fn apply_launch_receipt(svc: &BrokerService, host: &'static str, payload: &Json, root: Option<&Path>) {
    let Some(parent) = host_context(host, payload, root) else { return };
    let Some(call_id) = payload.get_str("tool_use_id") else { return };
    let Some(output) = payload.get("tool_response") else { return };
    let decoded = output.as_str().and_then(|value| json::parse(value).ok());
    let resolved = decoded.as_ref().unwrap_or(output);
    let field = if host == "claude" { "agentId" } else { "agent_id" };
    // Only the native tool's structured result is a receipt. Never scan model text.
    if let Some(id) = resolved.get_str(field).filter(|id| !id.is_empty()) {
        svc.broker.capsules.bind_receipt(&parent, call_id, Recipient::Agent(id.into()));
    } else if host == "codex" {
        if let Some(path) = resolved.get_str("task_name").filter(|path| path.starts_with('/')) {
            svc.broker.capsules.bind_receipt(&parent, call_id, Recipient::CodexPath(path.into()));
        }
    }
}

fn agy_capsule_rewrite(svc: &BrokerService, parent: &HostContext, call_id: &str, name: &str, args: &Json) -> Json {
    if call_id.is_empty() {
        return delivery_notice("agy", "launch receipt unavailable; using the original assignment");
    }
    let mut reason = None;
    let mut prepare = |index, mode_value: &str, brief: &str| {
        let result = WorkspaceMode::parse(mode_value).map_err(str::to_owned)
            .and_then(|mode| svc.broker.capsules.prepare(parent, mode, brief, Some(call_id), index));
        result.map_err(|err| { reason = Some(err) }).ok()
    };
    let workspace_mode = args.get_str("Workspace").or_else(|| args.get_str("workspace")).unwrap_or("inherit");
    let mut changed = None;
    if name == "invoke_subagent" {
        if let Some((field, items)) = ["Subagents", "subagents"].iter()
            .find_map(|&field| args.get(field).and_then(Json::as_arr).map(|items| (field, items)))
        {
            let updated = items.iter().enumerate().map(|(index, item)| {
                let mode = item.get_str("Workspace").or_else(|| item.get_str("workspace")).unwrap_or(workspace_mode);
                let brief = ["Prompt", "prompt", "Brief", "brief"].iter()
                    .find_map(|&key| item.get_str(key).map(|value| (key, value)));
                match brief.and_then(|(key, value)| prepare(index, mode, value).map(|text| (key, text))) {
                    Some((key, text)) => replace_field(item, key, Json::Str(text)),
                    None => item.clone(),
                }
            }).collect();
            changed = Some((field, Json::Arr(updated)));
        }
    } else if let Some(items) = args.get("tasks").and_then(Json::as_arr).filter(|items| !items.is_empty()) {
        let updated = items.iter().enumerate().map(|(index, item)| {
            item.as_str().and_then(|brief| prepare(index, workspace_mode, brief))
                .map(Json::Str).unwrap_or_else(|| item.clone())
        }).collect();
        changed = Some(("tasks", Json::Arr(updated)));
    } else if args.get_usize("n").unwrap_or(1) == 1 {
        changed = args.get_str("brief").and_then(|brief| prepare(0, workspace_mode, brief))
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
        delivery_notice("agy", reason.as_deref().unwrap_or("unsupported dispatch shape; using the original assignment"))
    }
}

fn bind_agy_inbound(svc: &BrokerService, payload: &Json, child: &HostContext) {
    for directory in candidate_agy_messages_dirs(payload, &child.session) {
        let Ok(files) = fs::read_dir(directory) else { continue };
        let mut paths: Vec<_> = files.flatten().map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .take(64).collect();
        paths.sort();
        for path in paths {
            if !fs::metadata(&path).is_ok_and(|entry| entry.is_file() && entry.len() <= 96 * 1024) {
                continue;
            }
            let Some(message) = fs::read_to_string(path).ok().and_then(|raw| json::parse(&raw).ok()) else {
                continue;
            };
            let (Some(sender), Some(brief)) = (message.get_str("sender"), message.get_str("content")) else {
                continue;
            };
            if message.get_str("recipient") != Some(&child.session) || sender == "system" || sender == child.session {
                continue;
            }
            if !brief.starts_with("[swarm] new board message") {
                svc.broker.capsules.bind_assignment(child, sender, brief);
                return;
            }
        }
    }
}

fn bind_explicit_child_transcript(svc: &BrokerService, payload: &Json, child: &HostContext) {
    let Some(id) = child.agent.as_deref() else { return };
    if !id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
        return;
    }
    let path = payload.get_str("agent_transcript_path").map(PathBuf::from).or_else(|| {
        let parent = Path::new(payload.get_str("transcript_path")?);
        Some(parent.parent()?.join(parent.file_stem()?).join("subagents").join(format!("agent-{id}.jsonl")))
    });
    let Some(path) = path else { return };
    if path.file_stem().and_then(|stem| stem.to_str()) != Some(&format!("agent-{id}")) {
        return;
    }
    let transcript = read_first_transcript_entries(&path, 16);
    if let Some(message) = transcript.iter().find(|record| record.get_str("type") == Some("user")) {
        if let Some(content) = message.get("message").and_then(|value| value.get("content")) {
            let text = content.as_str().or_else(|| {
                let parts = content.as_arr()?;
                (parts.len() == 1).then(|| parts[0].get_str("text")).flatten()
            });
            if let Some(text) = text {
                svc.broker.capsules.bind_assignment(child, &child.session, text);
            }
        }
    }
}

fn codex_launch_origin(payload: &Json, agent: &str) -> Option<(String, String)> {
    let path = Path::new(payload.get_str("transcript_path")?);
    // Read the host's session header only, never inherited conversation entries.
    let first = read_first_transcript_entries(path, 1).into_iter().next()?;
    if first.get_str("type") != Some("session_meta") {
        return None;
    }
    let meta = first.get("payload")?;
    if meta.get_str("id") != Some(agent) {
        return None;
    }
    let spawn = meta.get("source")?.get("subagent")?.get("thread_spawn")?;
    Some((spawn.get_str("parent_thread_id")?.into(), spawn.get_str("agent_path")?.into()))
}

fn mcp_context_rewrite(svc: &BrokerService, payload: &Json, context: &HostContext, name: &str, args: &Json) -> Option<Json> {
    let (op, inner_args, wrapped_str) = if name == "call_mcp_tool" {
        if args.get_str("ServerName") != Some("agent_ctx") {
            return None;
        }
        let tool = args.get_str("ToolName")?;
        let op = tool.strip_prefix("ctx_")?;
        match args.get("Arguments") {
            Some(Json::Obj(fields)) => (op, Json::Obj(fields.clone()), false),
            Some(Json::Str(raw)) => {
                let parsed = json::parse(raw).ok().filter(|v| v.as_obj().is_some())?;
                (op, parsed, true)
            }
            None => (op, Json::Obj(Vec::new()), false),
            _ => return None,
        }
    } else {
        let op = name.strip_prefix("mcp__agent_ctx__ctx_")
            .or_else(|| name.strip_prefix("mcp_agent_ctx_ctx_"))?;
        (op, args.clone(), false)
    };
    // Only bind host/session tickets for operations that actually consume `scoped_session` or
    // host-aware budgets (`read`, `symbols`, `memo` mutations, `capsule`). Stateless read-only
    // ops (`search`, `inspect`, `outline`, `elf_audit`, `memo` list/get) skip argument rewrites.
    let needs_context = match op {
        "capsule" | "read" | "symbols" => true,
        "memo" => matches!(inner_args.get_str("action"), Some("put" | "clear")),
        _ => false,
    };
    if !needs_context {
        return None;
    }
    let mut context = context.clone();
    if op == "capsule" && inner_args.get_str("action") == Some("claim") {
        if context.host == "agy" {
            bind_agy_inbound(svc, payload, &context);
        } else if context.host == "claude" {
            bind_explicit_child_transcript(svc, payload, &context);
        } else if let Some(agent) = context.agent.as_deref() {
            context.codex_origin = codex_launch_origin(payload, agent);
        }
    }
    let host = context.host;
    let ticket = svc.broker.capsules.issue_mcp_ticket(context, op);
    Some(match ticket {
        Ok(ticket) => {
            let updated_inner = replace_field(&inner_args, "ctx_context", Json::Str(ticket));
            let rewritten = if name == "call_mcp_tool" {
                let arg_val = if wrapped_str {
                    Json::Str(updated_inner.to_json_string())
                } else {
                    updated_inner
                };
                replace_field(args, "Arguments", arg_val)
            } else {
                updated_inner
            };
            rewrite_input(host, rewritten)
        }
        Err(reason) => delivery_notice(host, &reason),
    })
}

fn is_internal_ide_path(path: &Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/");
    s.contains("/.gemini/")
        || s.contains("/antigravity-cli/mcp/")
        || s.contains("/antigravity/mcp/")
        || s.contains("/antigravity-ide/mcp/")
        || s.contains("/.system_generated/")
        || s.contains("/brain/")
        || s.contains("/.codex/skills/.system/")
}

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

fn is_workspace_mutating_shell(cmd: &str) -> bool {
    let c = cmd.trim();
    c.contains("apply_patch")
        || c.contains("git checkout")
        || c.contains("git switch")
        || c.contains("git restore")
        || c.contains("git merge")
        || c.contains("git rebase")
        || c.contains("git pull")
        || c.contains("mv ")
        || c.contains("rm ")
        || c.starts_with("mv\t")
        || c.starts_with("rm\t")
}

// --- Antigravity Transcript Turn-0 Worker Brief Parser ---

fn unwrap_system_tag(raw: &str) -> &str {
    if let Some(s_idx) = raw.find("<SYSTEM_MESSAGE>") {
        let after = &raw[s_idx + "<SYSTEM_MESSAGE>".len()..];
        if let Some(e_idx) = after.rfind("</SYSTEM_MESSAGE>") {
            return after[..e_idx].trim();
        }
        return after.trim();
    }
    raw.trim()
}

fn strip_message_header(inner: &str) -> &str {
    let trimmed = inner.trim_start();
    if trimmed.starts_with("[Message]") {
        if let Some(c_idx) = trimmed.find("content=") {
            return &trimmed[c_idx + "content=".len()..];
        }
    }
    trimmed
}

fn is_narrator_or_monitor(header_low: &str) -> bool {
    header_low.contains("swarm_pane")
        || header_low.contains("swarm_monitor")
        || header_low.contains("you are the monitor")
        || header_low.contains("you are `@narrator`")
        || header_low.contains("you are @narrator")
}

fn read_first_transcript_entries(path: &Path, max_lines: usize) -> Vec<Json> {
    let parse_file = |p: &Path| -> (Vec<Json>, bool) {
        let Ok(f) = File::open(p) else {
            return (Vec::new(), false);
        };
        let mut reader = BufReader::new(f);
        let mut entries = Vec::new();
        let mut has_truncated = false;
        let mut line = String::new();
        for _ in 0..max_lines {
            line.clear();
            let Ok(n) = reader.read_line(&mut line) else {
                break;
            };
            if n == 0 {
                break;
            }
            if let Ok(parsed) = json::parse(line.trim()) {
                if parsed.get("truncated_fields").is_some() {
                    has_truncated = true;
                }
                entries.push(parsed);
            }
        }
        (entries, has_truncated)
    };

    let (entries, has_truncated) = parse_file(path);
    if has_truncated && path.file_name().and_then(|s| s.to_str()) != Some("transcript_full.jsonl") {
        let full_path = path.with_file_name("transcript_full.jsonl");
        if full_path.is_file() {
            let (full_entries, _) = parse_file(&full_path);
            if !full_entries.is_empty() {
                return full_entries;
            }
        }
    }
    entries
}

enum AgyStartupKind {
    RootUser,
    IgnoreAux,
    Worker {
        brief: String,
    },
    Undetermined,
}

fn candidate_agy_messages_dirs(payload: &Json, conv_id: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut push_unique = |p: PathBuf| {
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    };
    if let Some(tp_str) = payload.get_str("transcriptPath").filter(|s| !s.trim().is_empty()) {
        // `<brain>/<conv_id>/.system_generated/logs/transcript.jsonl` -> `.system_generated/messages`
        let tp_resolved = resolve_input_path(tp_str, None);
        if let Some(sys_gen) = tp_resolved.parent().and_then(|p| p.parent()) {
            push_unique(sys_gen.join("messages"));
        }
    }
    if let Some(art_str) = payload
        .get_str("artifactDirectoryPath")
        .filter(|s| !s.trim().is_empty())
    {
        let art_resolved = resolve_input_path(art_str, None);
        push_unique(art_resolved.join(".system_generated").join("messages"));
    }
    if let Ok(home) = std::env::var("AGENT_CTX_HOME")
        .or_else(|_| std::env::var("HOME"))
        .or_else(|_| std::env::var("USERPROFILE"))
    {
        if !home.trim().is_empty() && !conv_id.contains('/') && !conv_id.contains('\\') {
            let h = Path::new(&home).join(".gemini");
            for surface in ["antigravity-cli", "antigravity", "antigravity-ide"] {
                push_unique(
                    h.join(surface)
                        .join("brain")
                        .join(conv_id)
                        .join(".system_generated")
                        .join("messages"),
                );
            }
        }
    }
    dirs
}

fn inspect_agy_inbox_messages(payload: &Json, conv_id: &str) -> AgyStartupKind {
    for msg_dir in candidate_agy_messages_dirs(payload, conv_id) {
        let Ok(rd) = fs::read_dir(&msg_dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension().and_then(|s| s.to_str()) == Some("json")
                    && p.file_name().and_then(|s| s.to_str()) != Some("read.json")
            })
            .take(16)
            .collect();
        files.sort();

        let mut best_brief = None;
        for fp in files {
            let Ok(raw) = fs::read_to_string(&fp) else {
                continue;
            };
            let Ok(obj) = json::parse(raw.trim()) else {
                continue;
            };
            if let Some(rec) = obj.get_str("recipient") {
                if !rec.is_empty() && rec != conv_id {
                    continue;
                }
            }
            let sender = obj.get_str("sender").unwrap_or("");
            let content = obj.get_str("content").unwrap_or("").trim();
            if content.is_empty() || sender == conv_id {
                continue;
            }
            if obj.get_bool("hideFromUser") == Some(true)
                && content.starts_with("[swarm] new board message")
            {
                continue;
            }
            let low_hdr: String = content.chars().take(500).collect::<String>().to_ascii_lowercase();
            if is_narrator_or_monitor(&low_hdr) {
                return AgyStartupKind::IgnoreAux;
            }
            if sender != "system"
                || content.contains("You have just started.")
                || content.contains("Your assignment")
            {
                best_brief = Some(content.to_string());
                break;
            }
        }
        if let Some(brief) = best_brief {
            return AgyStartupKind::Worker { brief };
        }
    }
    AgyStartupKind::Undetermined
}

fn classify_agy_startup(payload: &Json, conv_id: &str) -> AgyStartupKind {
    // 1. Check transcript entries if already flushed to disk
    if let Some(tp_str) = payload.get_str("transcriptPath").filter(|s| !s.trim().is_empty()) {
        let tp = resolve_input_path(tp_str, None);
        if tp.is_file() {
            let entries = read_first_transcript_entries(&tp, 16);
            let mut idx = 0usize;
            while idx < entries.len() {
                let e = &entries[idx];
                let is_sess_start = e.get_str("type") == Some("SYSTEM_MESSAGE")
                    && (e.get_str("source") == Some("SYSTEM_SDK")
                        || e.get_str("content")
                            .map(|c| {
                                let inner = unwrap_system_tag(c);
                                inner.starts_with(
                                    "The following system message was injected by a SessionStart hook:",
                                ) || inner.starts_with(
                                    "The following system message was injected by a PreInvocation hook:",
                                )
                            })
                            .unwrap_or(false));
                if is_sess_start {
                    idx += 1;
                } else {
                    break;
                }
            }

            if let Some(first) = entries.get(idx) {
                if first.get_str("type") == Some("USER_INPUT")
                    && first.get_str("source") == Some("USER_EXPLICIT")
                {
                    return AgyStartupKind::RootUser;
                }
                if first.get_str("source") == Some("SYSTEM") {
                    let raw1 = first.get_str("content").unwrap_or("");
                    let body1 = strip_message_header(unwrap_system_tag(raw1)).trim();
                    let mut combined = body1.to_string();

                    if body1.starts_with("[swarm] new board message") {
                        if let Some(second) = entries.get(idx + 1) {
                            if second.get_str("source") == Some("SYSTEM")
                                && second.get_str("type") == Some("SYSTEM_MESSAGE")
                            {
                                let raw2 = second.get_str("content").unwrap_or("");
                                let body2 = strip_message_header(unwrap_system_tag(raw2)).trim();
                                combined.push('\n');
                                combined.push_str(body2);
                            }
                        }
                    }

                    let low_hdr: String = combined.chars().take(500).collect::<String>().to_ascii_lowercase();
                    if is_narrator_or_monitor(&low_hdr) {
                        return AgyStartupKind::IgnoreAux;
                    }

                    let is_swarm = raw1.contains("[swarm]")
                        || combined.contains("[swarm]")
                        || combined.contains("<swarm_worker>")
                        || combined.contains("You have just started.")
                        || combined.contains("Your assignment")
                        || combined.contains("recorded on the board as #");
                    let is_subagent =
                        raw1.contains("sender=") && !raw1.contains(&format!("sender={}", conv_id));

                    if is_swarm || is_subagent {
                        return AgyStartupKind::Worker { brief: combined };
                    }
                }
            }
        }
    }

    // 2. Check `.system_generated/messages/*.json` (populated BEFORE `SessionStart` on swarm / subagent spawn!)
    match inspect_agy_inbox_messages(payload, conv_id) {
        AgyStartupKind::Undetermined => {}
        other => return other,
    }

    // 3. Fallback when `transcriptPath` and inbox dir are omitted (e.g. direct unit test payloads)
    let last_input = payload.get_str("lastUserInput").unwrap_or("");
    if last_input.contains("<USER_REQUEST>") {
        return AgyStartupKind::RootUser;
    }
    let is_worker = last_input.contains("[swarm]")
        || last_input.contains("<swarm_worker>")
        || (last_input.contains("[Message]") && last_input.contains("sender="));
    if is_worker {
        let low = last_input.to_ascii_lowercase();
        if is_narrator_or_monitor(&low) {
            return AgyStartupKind::IgnoreAux;
        }
        return AgyStartupKind::Worker { brief: last_input.to_string() };
    }
    AgyStartupKind::Undetermined
}

// --- Startup Outline & Memo Capsule Builder ---

fn extract_candidate_paths_from_text(
    svc: &BrokerService,
    text: &str,
    cwd: Option<&Path>,
    ws_root: Option<&Path>,
) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for raw_tok in text.split(|c: char| {
        c.is_whitespace() || matches!(c, '`' | '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';' | '{' | '}')
    }) {
        let mut tok = raw_tok
            .trim_matches(|c: char| matches!(c, '.' | ':' | '#'))
            .split('#')
            .next()
            .unwrap_or("");
        while let Some(stripped) = tok
            .strip_suffix("/**")
            .or_else(|| tok.strip_suffix("/*"))
            .or_else(|| tok.strip_suffix('/'))
        {
            tok = stripped;
        }
        if tok.contains('*') {
            if let Some((dir_prefix, _)) = tok.rsplit_once('/') {
                tok = dir_prefix;
            } else {
                continue;
            }
        }
        if tok.len() < 3 || tok.len() > 240 {
            continue;
        }
        let looks_like_path = tok.contains('/')
            || tok.contains('\\')
            || tok.ends_with(".hpp")
            || tok.ends_with(".h")
            || tok.ends_with(".cpp")
            || tok.ends_with(".py")
            || tok.ends_with(".rs")
            || tok.ends_with(".toml");
        if !looks_like_path
            || tok.starts_with("http://")
            || tok.starts_with("https://")
            || tok.starts_with("file://")
            || tok.starts_with("conversation://")
            || tok.starts_with("docs/Agents/")
        {
            continue;
        }
        let p = resolve_input_path(tok, cwd);
        let target = if p.exists() {
            Some(p)
        } else if let Some(root) = ws_root {
            let alt1 = root.join("src").join("src").join(tok);
            let alt2 = root.join("src").join(tok);
            if alt1.exists() {
                Some(alt1)
            } else if alt2.exists() {
                Some(alt2)
            } else {
                match svc.store.resolve_missing_path(&p, root) {
                    MissingResolution::Unique(real) => Some(real),
                    _ => None,
                }
            }
        } else {
            None
        };
        if let Some(real_p) = target {
            if !is_sensitive_path(&real_p) && !is_internal_ide_path(&real_p) && !found.contains(&real_p) {
                found.push(real_p);
                if found.len() >= 12 {
                    break;
                }
            }
        }
    }
    found
}

fn prewarm_and_build_startup_capsule(
    svc: &BrokerService,
    brief: &str,
    cwd: Option<&Path>,
    ws_root: Option<&Path>,
    include_agy_mcp: bool,
) -> String {
    let candidates = extract_candidate_paths_from_text(svc, brief, cwd, ws_root);
    let mut files: Vec<(PathBuf, PathBuf)> = Vec::new();
    for c in candidates {
        if files.len() >= 10 {
            break;
        }
        if c.is_dir() {
            if let Ok((canon_dir, root)) = svc.allowlist.admit_dir(&c, cwd) {
                let mut sub = Vec::new();
                walk_source_dir(&canon_dir, &mut sub, 6);
                for f in sub {
                    if files.len() < 10 && !files.iter().any(|(x, _)| x == &f) {
                        files.push((f, root.clone()));
                    }
                }
            }
        } else if let Ok((canon_f, root)) = svc.allowlist.admit_file(&c, cwd) {
            if canon_f.is_file()
                && !is_multimodal_or_binary_ext(&canon_f)
                && !files.iter().any(|(x, _)| x == &canon_f)
            {
                files.push((canon_f, root));
            }
        }
    }

    let mut msg = String::with_capacity(1200);
    msg.push_str("[RAM-Ctx Startup] ");
    msg.push_str(SUBAGENT_REPORT_DIGEST);
    if include_agy_mcp {
        msg.push(' ');
        msg.push_str(AGY_LAZY_MCP_SIGNATURES);
    }

    if let Some(root) = ws_root {
        let ws_norm = norm_key_from_canon(root);
        let abs_files: Vec<PathBuf> = files.iter().map(|(f, _)| f.clone()).collect();
        let memo_digest = svc.broker.startup_memo_digest(
            &ws_norm,
            Some(root),
            brief,
            &abs_files,
            &svc.store,
            500,
        );
        if !memo_digest.is_empty() && msg.len() + memo_digest.len() + 24 <= STARTUP_BUDGET_BYTES {
            msg.push_str("\nShared workspace memos:\n");
            msg.push_str(&memo_digest);
        }
    }

    if !files.is_empty() {
        msg.push_str("\nPre-warmed file outlines:\n");
        for (f, root) in files {
            if let Ok(entry) = svc.store.get_outline_entry(&f, Some(&root)) {
                let line = format!("- {}\n", RamStore::format_outline_compact(&entry, 8));
                if msg.len() + line.len() > STARTUP_BUDGET_BYTES {
                    break;
                }
                msg.push_str(&line);
            }
        }
    }
    msg
}

// --- Shell File-Slicing Detector ---

struct ShellFileRead {
    target_path: PathBuf,
    ws_root: PathBuf,
    is_report_format_doc: bool,
    start_line: Option<usize>,
    end_line: Option<usize>,
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

fn detect_shell_file_slicing(
    svc: &BrokerService,
    cmd: &str,
    cwd: Option<&Path>,
) -> Option<ShellFileRead> {
    let trimmed = cmd.trim();
    if trimmed.is_empty()
        || trimmed.contains("<<")
        || trimmed.contains(" >")
        || trimmed.contains(">>")
        || trimmed.starts_with("ctx ")
        || trimmed.contains("/ctx ")
    {
        return None;
    }

    if trimmed.contains("&&") || trimmed.contains("||") || trimmed.contains(';') {
        return None;
    }

    let stages: Vec<&str> = trimmed.split('|').map(|s| s.trim()).collect();
    if stages.is_empty() || stages.len() > 2 {
        return None;
    }

    let first_tokens: Vec<&str> = stages[0]
        .split_whitespace()
        .map(|t| t.trim_matches('"').trim_matches('\''))
        .collect();
    if first_tokens.is_empty() {
        return None;
    }
    let prog = Path::new(first_tokens[0])
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first_tokens[0]);

    if !matches!(prog, "cat" | "sed" | "nl" | "head" | "tail" | "Get-Content" | "gc") {
        return None;
    }
    if stages.len() == 2 {
        let second_prog = stages[1]
            .split_whitespace()
            .next()
            .and_then(|t| Path::new(t).file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !matches!(second_prog, "sed" | "head" | "tail") {
            return None;
        }
    }

    let mut range: Option<(usize, usize)> = None;
    for st in &stages {
        if st.starts_with("sed ") {
            for tok in st.split_whitespace() {
                let clean = tok.trim_matches('\'').trim_matches('"');
                if let Some(body) = clean.strip_suffix('p') {
                    if let Some((a, b)) = body.split_once(',') {
                        if let (Ok(s), Ok(e)) = (a.parse::<usize>(), b.parse::<usize>()) {
                            range = Some((s.max(1), e.max(s.max(1))));
                        }
                    }
                }
            }
        }
    }

    for &tok in first_tokens[1..].iter().rev() {
        if tok.starts_with('-')
            || (prog == "sed"
                && tok.ends_with('p')
                && tok.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
        {
            continue;
        }
        let p = resolve_input_path(tok, cwd);
        if is_sensitive_path(&p) || is_internal_ide_path(&p) || is_multimodal_or_binary_ext(&p) {
            return None;
        }
        if let Ok((canon, ws_root)) = svc.allowlist.admit_file(&p, cwd) {
            if let Ok(meta) = fs::metadata(&canon) {
                if meta.is_file() && (meta.len() as usize) <= MAX_SINGLE_FILE_CACHE_BYTES {
                    let norm_disp = canon.to_string_lossy().replace('\\', "/");
                    let is_rf = norm_disp.ends_with("docs/Agents/ReportFormat.md");
                    return Some(ShellFileRead {
                        target_path: canon,
                        ws_root,
                        is_report_format_doc: is_rf,
                        start_line: range.map(|r| r.0),
                        end_line: range.map(|r| r.1),
                    });
                }
            }
        }
    }
    None
}

fn extract_codex_exec_commands(tool_name: &str, tool_input: &Json) -> Vec<String> {
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

// --- Antigravity Handler ---

fn handle_agy(svc: &BrokerService, payload: &Json) -> Json {
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
            let path_key = if args.get("AbsolutePath").is_some() {
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
                                let mut new_args = Vec::new();
                                if let Some(existing) = args.as_obj() {
                                    for (k, v) in existing {
                                        if k != path_key {
                                            new_args.push((k.clone(), v.clone()));
                                        }
                                    }
                                }
                                new_args.push((
                                    path_key.to_string(),
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
                            let mut new_args = Vec::new();
                            if let Some(existing) = args.as_obj() {
                                for (k, v) in existing {
                                    if k != "StartLine" && k != "EndLine" {
                                        new_args.push((k.clone(), v.clone()));
                                    }
                                }
                            }
                            if !new_args.iter().any(|(k, _)| k == path_key) {
                                new_args
                                    .push((path_key.to_string(), Json::Str(raw_path.to_string())));
                            }
                            new_args.push(("StartLine".to_string(), Json::Int(1)));
                            new_args.push(("EndLine".to_string(), Json::Int(lines as i64)));
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
                    let strike_key =
                        format!("agy:{}:BroadFind:{:016x}", conv_id, fnv1a_64(cmd.as_bytes()));
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
                    if hit.is_report_format_doc {
                        if matches!(
                            classify_agy_startup(payload, conv_id),
                            AgyStartupKind::Worker { .. }
                        ) {
                            return Json::obj(vec![
                                ("decision", Json::Str("deny".to_string())),
                                (
                                    "reason",
                                    Json::Str(format!("[RAM-Ctx] {}", SUBAGENT_REPORT_DIGEST)),
                                ),
                            ]);
                        }
                        return passthrough("agy", event);
                    }
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

// --- Codex CLI Handler ---

fn parse_tool_input_field(payload: &Json) -> Json {
    match payload.get("tool_input") {
        Some(Json::Str(s)) => json::parse(s).unwrap_or_else(|_| Json::Str(s.clone())),
        Some(other) => other.clone(),
        None => Json::Obj(Vec::new()),
    }
}

fn handle_codex(svc: &BrokerService, payload: &Json) -> Json {
    let event = payload.get_str("hook_event_name").unwrap_or("");
    let ws_root = register_payload_workspaces(svc, payload);
    let cwd = extract_cwd(payload);
    let (sess_key, agent_scope) = build_scoped_session_key("codex", payload);

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
            if let Some(reply) = mcp_context_rewrite(svc, payload, &context, tool_name, &tool_input) {
                return reply;
            }
            if capsule_auto_stage_enabled() && matches!(tool_name, "spawn_agent" | "Agent") {
                return codex_capsule_rewrite(svc, &context, payload, &tool_input);
            }
        }

        let cmds = extract_codex_exec_commands(tool_name, &tool_input);
        for cmd in cmds {
            if let Some(hit) = detect_shell_file_slicing(svc, &cmd, cwd.as_deref()) {
                if hit.is_report_format_doc {
                    if agent_scope.is_some() {
                        return codex_deny(&format!("[RAM-Ctx] {}", SUBAGENT_REPORT_DIGEST));
                    }
                    continue;
                }
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
                    if let Ok(entry) = svc.store.get_outline_entry(&hit.target_path, Some(&hit.ws_root)) {
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
                if let Ok(entry) = svc.store.get_outline_entry(&hit.target_path, Some(&hit.ws_root))
                {
                    let total_l = entry.line_count as usize;
                    let s = hit.start_line.unwrap_or(1).max(1);
                    let e = hit
                        .end_line
                        .unwrap_or(total_l)
                        .min(total_l)
                        .max(s);
                    svc.store
                        .record_read(&sess_key, &hit.target_path, Some(&hit.ws_root), s, e);
                }
            }
        }
    }

    Json::Obj(Vec::new())
}

fn codex_deny(reason: &str) -> Json {
    Json::obj(vec![(
        "hookSpecificOutput",
        Json::obj(vec![
            ("hookEventName", Json::Str("PreToolUse".to_string())),
            ("permissionDecision", Json::Str("deny".to_string())),
            ("permissionDecisionReason", Json::Str(reason.to_string())),
        ]),
    )])
}

// --- Claude Code Handler ---

fn handle_claude(svc: &BrokerService, payload: &Json) -> Json {
    let event = payload.get_str("hook_event_name").unwrap_or("");
    let ws_root = register_payload_workspaces(svc, payload);
    let cwd = extract_cwd(payload);
    let (sess_key, agent_scope) = build_scoped_session_key("claude", payload);

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
            if let Some(reply) = mcp_context_rewrite(svc, payload, &context, tool_name, &tool_input) {
                return reply;
            }
            if matches!(tool_name, "Agent" | "Task") {
                if let (Some(key), Some(call_id)) = (
                    tool_input.get_str("prompt").and_then(key_in_assignment),
                    payload.get_str("tool_use_id"),
                ) {
                    svc.broker.capsules.record_launch(&context, key, call_id);
                }
                return Json::obj(vec![]);
            }
        }

        if tool_name == "Read" {
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
        } else if tool_name == "Bash" {
            if let Some(cmd) = tool_input.get_str("command") {
                if let Some(hit) = detect_shell_file_slicing(svc, cmd, cwd.as_deref()) {
                    if hit.is_report_format_doc && agent_scope.is_some() {
                        return codex_deny(&format!("[RAM-Ctx] {}", SUBAGENT_REPORT_DIGEST));
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
