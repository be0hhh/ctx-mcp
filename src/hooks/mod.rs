//! Sub-millisecond lifecycle hook router (`ctx hook <agy|codex|claude>`):
//!   - Strict per-agent isolation (`agy:{conversationId}`, `codex:{session_id}:{agent_id}`,
//!     `claude:{session_id}:{agent_id}`).
//!   - Opt-in addressed `TaskCapsule` staging & claiming (`AGENT_CTX_ENABLE_CAPSULE=1`) +
//!     `ctx_memo` digest injection.
//!   - Antigravity turn-0 `SessionStart`/`PreInvocation` parsing paired swarm briefs from
//!     `transcript.jsonl` / `transcript_full.jsonl` and `.system_generated/messages/*.json`.
//!   - Non-blocking `> 800L` `read_file` in Antigravity with exact `800 lines` / `46,080 bytes`
//!     delivery accounting in `PostToolUse`, plus `WorkspaceIndex` moved-file auto-resolution.

mod agy;
mod claude;
mod codex;
mod startup;

use crate::base::json::{self, Json};
use crate::base::security::is_sensitive_path;
use crate::base::simd::fast_hash64;
use crate::broker::{HostContext, Recipient};
use crate::rpc::BrokerService;
use crate::store::{
    display_workspace_path, is_multimodal_or_binary_ext, resolve_input_path,
    MAX_SINGLE_FILE_CACHE_BYTES,
};
use agy::handle_agy;
use claude::handle_claude;
use codex::handle_codex;
use startup::{bind_agy_inbound, bind_explicit_child_transcript, codex_launch_origin};
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};

const AGY_NATIVE_LINE_CAP: usize = 800;
const AGY_NATIVE_DELIVERY_BYTE_CAP: usize = 46_080;
const AGY_WIDEN_MAX_LINES: usize = 300;
const AGY_WIDEN_MAX_BYTES: u32 = 16_384;
const STARTUP_BUDGET_BYTES: usize = 4_000;

const SUBAGENT_STARTUP_DIGEST: &str = "CTX-first & symbol-first: ctx_search (`q`: 1-6 `Mod:pat`), ctx_inspect (dirs), ctx_symbols (prefer for >=350L code files; full body or `compact=true` <=48L), ctx_impact (callers/tests before edits), ctx_read (slices or <=1MiB in Codex/CLI), ctx_git (diff/status/log/show), ctx_edit, ctx_memo (memos/changes/packs). Finish from search/symbols when sufficient.";

const AGY_LAZY_MCP_SIGNATURES: &str = "In Antigravity: call the 8 eager mcp_agent_ctx_* tools directly (`ctx_search`, `ctx_inspect`, `ctx_read`, `ctx_symbols`, `ctx_impact`, `ctx_memo`, `ctx_git`, `ctx_edit`); use `call_mcp_tool` only for lazy tools (`ctx_outline`, `ctx_elf_audit`, `ctx_capsule`). For >=350L code files use `ctx_symbols` first; in swarm workers without MCP use CLI `ctx search|inspect|sym|impact|read|git|edit|memo|diag` directly.";

const AGY_WORKER_STARTUP_DIGEST: &str = "CTX CLI-first & symbol-first (swarm workers have no MCP): use `ctx search -q 'Mod:pat'` (1-6 queries, 12-14 KiB batch), `ctx inspect <dirs>`, `ctx sym 'Mod#Sym'` (prefer for >=350L code files), `ctx impact 'Mod#Sym'`, `ctx read <path[:s-e]>`, `ctx git diff|status|log|show`, `ctx edit`, `ctx memo put|list|pack|pack-get|changes`, `ctx diag -- <cmd>`. Finish from search/symbols when sufficient.";

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
                    || txt.contains("hook agy")
                    || txt.contains("hook codex")
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
    for key in &[
        "agent_id",
        "subagent_id",
        "thread_id",
        "agentId",
        "subagentId",
    ] {
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

fn build_scoped_session_key(flavor: &str, payload: &Json) -> String {
    let session_id = payload.get_str("session_id").unwrap_or("default");
    let scope_opt = extract_child_agent_scope(payload);
    let scope = scope_opt.as_deref().unwrap_or("root");
    format!("{}:{}:{}", flavor, session_id, scope)
}

fn host_context(host: &'static str, payload: &Json, root: Option<&Path>) -> Option<HostContext> {
    let session = payload.get_str(if host == "agy" {
        "conversationId"
    } else {
        "session_id"
    })?;
    if session.is_empty() {
        return None;
    }
    let root = root?;
    if payload.get_str("cwd").is_none()
        && payload
            .get("workspacePaths")
            .and_then(Json::as_arr)
            .is_some_and(|paths| paths.len() != 1)
    {
        return None;
    }
    if !fs::canonicalize(extract_cwd(payload)?).ok()?.starts_with(root) {
        return None;
    }
    let agent = if host == "agy" {
        Some(session)
    } else {
        payload.get_str("agent_id")
    }
    .filter(|id| !id.is_empty())
    .map(str::to_owned);
    Some(HostContext {
        host,
        session: session.into(),
        agent,
        workspace: root.to_path_buf(),
        codex_origin: None,
    })
}

fn replace_field(args: &Json, field: &'static str, value: Json) -> Json {
    let mut fields = args.as_obj().unwrap_or_default().to_vec();
    fields.retain(|(name, _)| name.as_ref() != field);
    fields.push((Cow::Borrowed(field), value));
    Json::Obj(fields)
}

fn rewrite_input(host: &str, args: Json) -> Json {
    if host == "agy" {
        return Json::obj(vec![
            ("decision", Json::Str("allow".into())),
            ("overwrite", args),
        ]);
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
        Json::obj(vec![
            ("decision", Json::Str("allow".into())),
            ("reason", Json::Str(reason)),
        ])
    } else {
        Json::obj(vec![("systemMessage", Json::Str(reason))])
    }
}

fn apply_launch_receipt(
    svc: &BrokerService,
    host: &'static str,
    payload: &Json,
    root: Option<&Path>,
) {
    let Some(parent) = host_context(host, payload, root) else {
        return;
    };
    let Some(call_id) = payload.get_str("tool_use_id") else {
        return;
    };
    let Some(output) = payload.get("tool_response") else {
        return;
    };
    let decoded = output.as_str().and_then(|value| json::parse(value).ok());
    let resolved = decoded.as_ref().unwrap_or(output);
    let field = if host == "claude" {
        "agentId"
    } else {
        "agent_id"
    };
    // Only the native tool's structured result is a receipt. Never scan model text.
    if let Some(id) = resolved.get_str(field).filter(|id| !id.is_empty()) {
        svc.broker
            .capsules
            .bind_receipt(&parent, call_id, Recipient::Agent(id.into()));
    } else if host == "codex" {
        if let Some(path) = resolved
            .get_str("task_name")
            .filter(|path| path.starts_with('/'))
        {
            svc.broker
                .capsules
                .bind_receipt(&parent, call_id, Recipient::CodexPath(path.into()));
        }
    }
}

fn mcp_context_rewrite(
    svc: &BrokerService,
    payload: &Json,
    context: &HostContext,
    name: &str,
    args: &Json,
) -> Option<Json> {
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
        let op = name
            .strip_prefix("mcp__agent_ctx__ctx_")
            .or_else(|| name.strip_prefix("mcp_agent_ctx_ctx_"))?;
        (op, args.clone(), false)
    };
    // Only bind host/session tickets for operations that actually consume `scoped_session` or
    // host-aware budgets (`read`, `symbols`, `memo` mutations, `capsule`). Stateless read-only
    // ops (`search`, `inspect`, `outline`, `elf_audit`, `memo` list/get) skip argument rewrites.
    let needs_context = match op {
        "capsule" | "read" | "symbols" | "impact" | "edit" | "git" => true,
        "memo" => matches!(
            inner_args.get_str("action"),
            Some("put" | "clear" | "pack" | "pack_get")
        ),
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

struct ShellFileRead {
    target_path: PathBuf,
    ws_root: PathBuf,
    start_line: Option<usize>,
    end_line: Option<usize>,
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

    if !matches!(
        prog,
        "cat" | "sed" | "nl" | "head" | "tail" | "Get-Content" | "gc"
    ) {
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
                && tok
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false))
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
                    return Some(ShellFileRead {
                        target_path: canon,
                        ws_root,
                        start_line: range.map(|r| r.0),
                        end_line: range.map(|r| r.1),
                    });
                }
            }
        }
    }
    None
}

pub(super) fn is_env_assignment_token(tok: &str) -> bool {
    let bytes = tok.as_bytes();
    let Some(eq_idx) = bytes.iter().position(|&b| b == b'=') else {
        return false;
    };
    let name = &bytes[..eq_idx];
    !name.is_empty()
        && (name[0].is_ascii_alphabetic() || name[0] == b'_')
        && name[1..]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

pub(super) fn command_basename(tok: &str) -> &str {
    let after_slash = tok.rsplit('/').next().unwrap_or(tok);
    after_slash.rsplit('\\').next().unwrap_or(after_slash)
}

pub(super) fn split_shell_tokens(raw: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    let mut ansi_c = false;
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            if ch == '\\' && (q == '"' || ansi_c) {
                if q == '"' && chars.peek() == Some(&'\n') {
                    chars.next();
                    continue;
                }
                if q == '"' && chars.peek() == Some(&'\r') {
                    chars.next();
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                        continue;
                    }
                    cur.push('\r');
                    continue;
                }
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            } else if ch == q {
                quote = None;
                ansi_c = false;
            } else {
                cur.push(ch);
            }
            continue;
        }
        match ch {
            '$' if chars.peek() == Some(&'\'') => {
                chars.next();
                quote = Some('\'');
                ansi_c = true;
                in_token = true;
            }
            '\'' | '"' => {
                quote = Some(ch);
                ansi_c = false;
                in_token = true;
            }
            c if c.is_whitespace() => {
                if in_token {
                    out.push(std::mem::take(&mut cur));
                    in_token = false;
                }
            }
            '\\' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                    if in_token {
                        out.push(std::mem::take(&mut cur));
                        in_token = false;
                    }
                } else if chars.peek() == Some(&'\r') {
                    chars.next();
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                        if in_token {
                            out.push(std::mem::take(&mut cur));
                            in_token = false;
                        }
                    } else {
                        in_token = true;
                        cur.push('\r');
                    }
                } else {
                    in_token = true;
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                }
            }
            c => {
                cur.push(c);
                in_token = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if in_token {
        out.push(cur);
    }
    Some(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuoteMode {
    Unquoted,
    Single,
    AnsiC,
    Double,
}

fn scan_segment_shell_ops(seg: &str, allow_single_pipe: bool) -> bool {
    let bytes = seg.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut mode = QuoteMode::Unquoted;
    while i < len {
        let b = bytes[i];
        match mode {
            QuoteMode::Single => {
                if b == b'\'' {
                    mode = QuoteMode::Unquoted;
                }
                i += 1;
            }
            QuoteMode::AnsiC => {
                if b == b'\\' && i + 1 < len {
                    i += 2;
                    while i < len && bytes[i] >= 0x80 && (bytes[i] & 0xC0) == 0x80 {
                        i += 1;
                    }
                    continue;
                }
                if b == b'\'' {
                    mode = QuoteMode::Unquoted;
                }
                i += 1;
            }
            QuoteMode::Double => {
                if b == b'\\' && i + 1 < len {
                    i += 2;
                    while i < len && bytes[i] >= 0x80 && (bytes[i] & 0xC0) == 0x80 {
                        i += 1;
                    }
                    continue;
                }
                if b == b'"' {
                    mode = QuoteMode::Unquoted;
                    i += 1;
                    continue;
                }
                if b == b'`' || (b == b'$' && bytes.get(i + 1) == Some(&b'(')) {
                    return true;
                }
                i += 1;
            }
            QuoteMode::Unquoted => {
                if b == b'\\' && i + 1 < len {
                    i += 2;
                    while i < len && bytes[i] >= 0x80 && (bytes[i] & 0xC0) == 0x80 {
                        i += 1;
                    }
                    continue;
                }
                if b == b'$' && bytes.get(i + 1) == Some(&b'\'') {
                    mode = QuoteMode::AnsiC;
                    i += 2;
                    continue;
                }
                if b == b'\'' {
                    mode = QuoteMode::Single;
                    i += 1;
                    continue;
                }
                if b == b'"' {
                    mode = QuoteMode::Double;
                    i += 1;
                    continue;
                }
                if b == b'|' {
                    if !allow_single_pipe || bytes.get(i + 1) == Some(&b'|') {
                        return true;
                    }
                    i += 1;
                    continue;
                }
                if matches!(b, b'>' | b'<' | b'`')
                    || (b == b'$' && bytes.get(i + 1) == Some(&b'('))
                {
                    return true;
                }
                i += 1;
            }
        }
    }
    false
}

pub(super) fn segment_has_unsafe_shell_ops(seg: &str) -> bool {
    scan_segment_shell_ops(seg, false)
}

pub(super) fn segment_has_redirects_or_subshell(seg: &str) -> bool {
    scan_segment_shell_ops(seg, true)
}

fn split_pipes_quote_aware(seg: &str, allow_or_or: bool) -> Option<Vec<&str>> {
    let bytes = seg.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut start = 0usize;
    let mut mode = QuoteMode::Unquoted;
    let mut stages = Vec::new();

    while i < len {
        let b = bytes[i];
        match mode {
            QuoteMode::Single => {
                if b == b'\'' {
                    mode = QuoteMode::Unquoted;
                }
                i += 1;
            }
            QuoteMode::AnsiC => {
                if b == b'\\' && i + 1 < len {
                    i += 2;
                    while i < len && bytes[i] >= 0x80 && (bytes[i] & 0xC0) == 0x80 {
                        i += 1;
                    }
                    continue;
                }
                if b == b'\'' {
                    mode = QuoteMode::Unquoted;
                }
                i += 1;
            }
            QuoteMode::Double => {
                if b == b'\\' && i + 1 < len {
                    i += 2;
                    while i < len && bytes[i] >= 0x80 && (bytes[i] & 0xC0) == 0x80 {
                        i += 1;
                    }
                    continue;
                }
                if b == b'"' {
                    mode = QuoteMode::Unquoted;
                }
                i += 1;
            }
            QuoteMode::Unquoted => {
                if b == b'\\' && i + 1 < len {
                    i += 2;
                    while i < len && bytes[i] >= 0x80 && (bytes[i] & 0xC0) == 0x80 {
                        i += 1;
                    }
                    continue;
                }
                if b == b'$' && bytes.get(i + 1) == Some(&b'\'') {
                    mode = QuoteMode::AnsiC;
                    i += 2;
                    continue;
                }
                if b == b'\'' {
                    mode = QuoteMode::Single;
                    i += 1;
                    continue;
                }
                if b == b'"' {
                    mode = QuoteMode::Double;
                    i += 1;
                    continue;
                }
                if b == b'|' {
                    let is_or_or = bytes.get(i + 1) == Some(&b'|');
                    if is_or_or && !allow_or_or {
                        return None;
                    }
                    let piece = seg[start..i].trim();
                    if piece.is_empty() {
                        if !allow_or_or {
                            return None;
                        }
                    } else {
                        stages.push(piece);
                    }
                    i += if is_or_or { 2 } else { 1 };
                    start = i;
                    continue;
                }
                i += 1;
            }
        }
    }
    if !allow_or_or && mode != QuoteMode::Unquoted {
        return None;
    }
    let tail = seg[start..].trim();
    if tail.is_empty() {
        if !allow_or_or {
            return None;
        }
    } else {
        stages.push(tail);
    }
    Some(stages)
}

pub(super) fn split_unquoted_pipes(seg: &str) -> Option<Vec<&str>> {
    split_pipes_quote_aware(seg, false)
}

fn is_harmless_banner_segment(seg: &str) -> bool {
    if segment_has_unsafe_shell_ops(seg) {
        return false;
    }
    let Some(tokens) = split_shell_tokens(seg) else {
        return false;
    };
    let Some(cmd_idx) = tokens.iter().position(|t| !is_env_assignment_token(t)) else {
        return false;
    };
    let prog = command_basename(&tokens[cmd_idx]);
    if prog == "echo" {
        return true;
    }
    if prog == "printf" {
        // `printf -v VAR ...` mutates a shell variable and is not a pure banner.
        return !tokens[cmd_idx + 1..]
            .iter()
            .any(|t| t == "-v" || t.starts_with("-v"));
    }
    false
}

fn push_non_ascii_run(cmd: &str, bytes: &[u8], i: &mut usize, dst: &mut String) {
    let start = *i;
    while *i < bytes.len() && bytes[*i] >= 0x80 {
        *i += 1;
    }
    dst.push_str(&cmd[start..*i]);
}

/// Quote-aware POSIX shell splitter that joins `\\\n` / `\\\r\n` continuations, splits on
/// unquoted `\n`, `;`, and `&&`, and drops empty lines, `#`-comments, and harmless `echo`/`printf`
/// banner segments (with no unquoted pipes, redirects, `$(`, or backticks).
pub(super) fn extract_shell_segments_ignoring_echo(cmd: &str) -> Vec<String> {
    let bytes = cmd.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut cur = String::new();
    let mut at_word_start = true;
    let mut segments = Vec::new();

    let flush = |cur: &mut String, segments: &mut Vec<String>| {
        let trimmed = cur.trim();
        if !trimmed.is_empty() && !is_harmless_banner_segment(trimmed) {
            segments.push(trimmed.to_string());
        }
        cur.clear();
    };

    while i < len {
        let b = bytes[i];
        if b >= 0x80 {
            push_non_ascii_run(cmd, bytes, &mut i, &mut cur);
            at_word_start = false;
            continue;
        }
        if b == b'#' && at_word_start {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'\n' || b == b';' {
            flush(&mut cur, &mut segments);
            at_word_start = true;
            i += 1;
            continue;
        }
        if b == b'&' && bytes.get(i + 1) == Some(&b'&') {
            flush(&mut cur, &mut segments);
            at_word_start = true;
            i += 2;
            continue;
        }
        if b == b'$' && bytes.get(i + 1) == Some(&b'\'') {
            cur.push_str("$'");
            i += 2;
            while i < len {
                let c = bytes[i];
                if c >= 0x80 {
                    push_non_ascii_run(cmd, bytes, &mut i, &mut cur);
                    continue;
                }
                if c == b'\\' && i + 1 < len {
                    cur.push('\\');
                    i += 1;
                    if bytes[i] >= 0x80 {
                        push_non_ascii_run(cmd, bytes, &mut i, &mut cur);
                    } else {
                        cur.push(bytes[i] as char);
                        i += 1;
                    }
                    continue;
                }
                cur.push(c as char);
                i += 1;
                if c == b'\'' {
                    break;
                }
            }
            at_word_start = false;
            continue;
        }
        if b == b'\'' {
            cur.push('\'');
            i += 1;
            while i < len {
                let c = bytes[i];
                if c >= 0x80 {
                    push_non_ascii_run(cmd, bytes, &mut i, &mut cur);
                    continue;
                }
                cur.push(c as char);
                i += 1;
                if c == b'\'' {
                    break;
                }
            }
            at_word_start = false;
            continue;
        }
        if b == b'"' {
            cur.push('"');
            i += 1;
            while i < len {
                let c = bytes[i];
                if c >= 0x80 {
                    push_non_ascii_run(cmd, bytes, &mut i, &mut cur);
                    continue;
                }
                if c == b'\\' {
                    if bytes.get(i + 1) == Some(&b'\n') {
                        i += 2;
                        continue;
                    }
                    if bytes.get(i + 1) == Some(&b'\r') && bytes.get(i + 2) == Some(&b'\n') {
                        i += 3;
                        continue;
                    }
                    if i + 1 < len {
                        cur.push('\\');
                        i += 1;
                        if bytes[i] >= 0x80 {
                            push_non_ascii_run(cmd, bytes, &mut i, &mut cur);
                        } else {
                            cur.push(bytes[i] as char);
                            i += 1;
                        }
                        continue;
                    }
                }
                cur.push(c as char);
                i += 1;
                if c == b'"' {
                    break;
                }
            }
            at_word_start = false;
            continue;
        }
        if b == b'\\' {
            if bytes.get(i + 1) == Some(&b'\n') {
                cur.push(' ');
                i += 2;
                at_word_start = true;
                continue;
            }
            if bytes.get(i + 1) == Some(&b'\r') && bytes.get(i + 2) == Some(&b'\n') {
                cur.push(' ');
                i += 3;
                at_word_start = true;
                continue;
            }
            if i + 1 < len {
                cur.push('\\');
                i += 1;
                if bytes[i] >= 0x80 {
                    push_non_ascii_run(cmd, bytes, &mut i, &mut cur);
                } else {
                    cur.push(bytes[i] as char);
                    i += 1;
                }
                at_word_start = false;
                continue;
            }
        }
        cur.push(b as char);
        at_word_start = matches!(b, b' ' | b'\t' | b'\r');
        i += 1;
    }
    flush(&mut cur, &mut segments);
    segments
}

pub(super) fn segment_changes_cwd(seg: &str) -> bool {
    let Some(tokens) = split_shell_tokens(seg) else {
        return false;
    };
    let Some(first) = tokens.iter().find(|t| !is_env_assignment_token(t)) else {
        return false;
    };
    let clean = first.trim_start_matches('(');
    matches!(command_basename(clean), "cd" | "pushd" | "popd")
}

pub(super) fn extract_git_subcommand(args: &[String]) -> Option<&str> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if matches!(
            tok,
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env"
        ) {
            i += 2;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        return Some(tok);
    }
    None
}

fn segment_invokes_mutating_git(seg: &str) -> bool {
    let Some(parts) = split_pipes_quote_aware(seg, true) else {
        return false;
    };

    for part in parts {
        let Some(tokens) = split_shell_tokens(part) else {
            continue;
        };
        let mut idx = 0usize;
        while idx < tokens.len() {
            let t = tokens[idx].trim_start_matches('(');
            if is_env_assignment_token(t)
                || matches!(
                    t,
                    "time" | "!" | "then" | "do" | "else" | "elif" | "command" | "builtin"
                )
            {
                idx += 1;
                continue;
            }
            break;
        }
        let Some(cmd_tok) = tokens.get(idx) else {
            continue;
        };
        let prog = command_basename(cmd_tok.trim_start_matches('('));
        if !matches!(prog, "git" | "git.exe") {
            continue;
        }
        if let Some(sub) = extract_git_subcommand(&tokens[idx + 1..]) {
            if matches!(
                sub,
                "add"
                    | "commit"
                    | "push"
                    | "pull"
                    | "fetch"
                    | "checkout"
                    | "switch"
                    | "reset"
                    | "rebase"
                    | "merge"
                    | "cherry-pick"
                    | "stash"
                    | "tag"
                    | "branch"
                    | "rm"
                    | "mv"
                    | "restore"
                    | "clean"
                    | "apply"
                    | "am"
                    | "bisect"
                    | "init"
                    | "clone"
                    | "submodule"
            ) {
                return true;
            }
        }
    }
    false
}

fn has_single_colon(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b':' {
            if b.get(i + 1) == Some(&b':') {
                while i < b.len() && b[i] == b':' {
                    i += 1;
                }
                continue;
            }
            return true;
        }
        i += 1;
    }
    false
}

fn detect_single_workspace_shell_grep(
    svc: &BrokerService,
    seg: &str,
    cwd: Option<&Path>,
) -> Option<(String, String)> {
    let tokens = split_shell_tokens(seg)?;
    let cmd_idx = tokens.iter().position(|t| !is_env_assignment_token(t))?;
    if tokens.len() < cmd_idx + 2 {
        return None;
    }
    let prog = command_basename(&tokens[cmd_idx]);
    if !matches!(prog, "grep" | "egrep" | "fgrep" | "rg") {
        return None;
    }

    let mut pattern: Option<String> = None;
    let mut targets: Vec<String> = Vec::new();
    let mut after_dd = false;
    let mut i = cmd_idx + 1;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if !after_dd && tok == "--" {
            after_dd = true;
            i += 1;
            continue;
        }
        if !after_dd && tok.starts_with("--") {
            let flag = tok.split_once('=').map_or(tok, |(f, _)| f);
            if matches!(
                flag,
                "--files"
                    | "--count"
                    | "--files-with-matches"
                    | "--files-without-match"
                    | "--only-matching"
                    | "--invert-match"
                    | "--json"
                    | "--vimgrep"
                    | "--stats"
                    | "--version"
                    | "--help"
                    | "--replace"
                    | "--file"
                    | "--null"
                    | "--null-data"
                    | "--passthru"
                    | "--type-list"
            ) {
                return None;
            }
            if flag == "--regexp" {
                let val = if let Some((_, v)) = tok.split_once('=') {
                    v.to_string()
                } else {
                    i += 1;
                    tokens.get(i)?.clone()
                };
                if pattern.is_none() {
                    pattern = Some(val);
                }
            } else if !tok.contains('=')
                && matches!(
                    flag,
                    "--max-count"
                        | "--context"
                        | "--after-context"
                        | "--before-context"
                        | "--glob"
                        | "--type"
                        | "--type-not"
                        | "--include"
                        | "--exclude"
                        | "--exclude-dir"
                        | "--max-depth"
                        | "--color"
                        | "--colors"
                        | "--threads"
                )
            {
                i += 1;
            }
            i += 1;
            continue;
        }
        if !after_dd && tok.starts_with('-') && tok.len() > 1 {
            if let Some(rest) = tok.strip_prefix("-e") {
                let val = if rest.is_empty() {
                    i += 1;
                    tokens.get(i)?.clone()
                } else {
                    rest.to_string()
                };
                if pattern.is_none() {
                    pattern = Some(val);
                }
                i += 1;
                continue;
            }
            if matches!(tok, "-m" | "-A" | "-B" | "-C" | "-g" | "-t" | "-T" | "-j") {
                i += 2;
                continue;
            }
            let flags = &tok[1..];
            if flags.bytes().any(|b| {
                matches!(
                    b,
                    b'c' | b'e' | b'l' | b'L' | b'o' | b'v' | b'f' | b'q' | b'z' | b'h' | b'V'
                )
            }) {
                return None;
            }
            i += 1;
            continue;
        }
        if pattern.is_none() {
            pattern = Some(tok.to_string());
        } else {
            targets.push(tok.to_string());
        }
        i += 1;
    }

    let pat = pattern.filter(|p| !p.trim().is_empty())?;
    let scope_rel = if targets.is_empty() {
        let base = cwd?;
        if is_internal_ide_path(base) || is_sensitive_path(base) {
            return None;
        }
        let (canon, ws_root) = svc.allowlist.admit_dir(base, Some(base)).ok()?;
        if canon == ws_root {
            String::new()
        } else {
            display_workspace_path(&canon, Some(&ws_root))
        }
    } else {
        let mut first_rel: Option<String> = None;
        for raw_t in &targets {
            if raw_t.contains('*') || raw_t.contains('?') || raw_t.contains('[') {
                return None;
            }
            let p = resolve_input_path(raw_t, cwd);
            if is_sensitive_path(&p) || is_internal_ide_path(&p) || is_multimodal_or_binary_ext(&p)
            {
                return None;
            }
            let (canon, ws_root) = if p.is_dir() {
                svc.allowlist.admit_dir(&p, cwd).ok()?
            } else if p.is_file() {
                svc.allowlist.admit_file(&p, cwd).ok()?
            } else {
                return None;
            };
            if first_rel.is_none() {
                first_rel = Some(if canon == ws_root {
                    String::new()
                } else {
                    display_workspace_path(&canon, Some(&ws_root))
                });
            }
        }
        if targets.len() == 1 {
            first_rel.unwrap_or_default()
        } else {
            String::new()
        }
    };

    Some((scope_rel, pat))
}

fn segment_primary_prog(seg: &str) -> Option<String> {
    let tokens = split_shell_tokens(seg)?;
    let cmd_idx = tokens.iter().position(|t| !is_env_assignment_token(t))?;
    Some(command_basename(&tokens[cmd_idx]).to_string())
}

fn detect_workspace_shell_grep(
    svc: &BrokerService,
    cmd: &str,
    cwd: Option<&Path>,
) -> Option<(String, String)> {
    let segments = extract_shell_segments_ignoring_echo(cmd);
    if segments.is_empty() {
        return None;
    }
    if segments.iter().any(|seg| {
        segment_changes_cwd(seg)
            || !matches!(
                segment_primary_prog(seg).as_deref(),
                Some("grep" | "egrep" | "fgrep" | "rg" | "grep.exe" | "rg.exe")
            )
    }) {
        return None;
    }
    for seg in &segments {
        if segment_has_unsafe_shell_ops(seg) {
            continue;
        }
        if let Some(hit) = detect_single_workspace_shell_grep(svc, seg, cwd) {
            return Some(hit);
        }
    }
    None
}

pub(super) fn workspace_grep_redirect_reason(
    svc: &BrokerService,
    host: &str,
    sess_key: &str,
    cmd: &str,
    cwd: Option<&Path>,
) -> Option<String> {
    let (scope_rel, pat) = detect_workspace_shell_grep(svc, cmd, cwd)?;
    let strike_key = format!(
        "{}:{}:ShellGrep:{:016x}",
        host,
        sess_key,
        fast_hash64(cmd.trim().as_bytes())
    );
    if svc.store.check_and_mark_dedup(&strike_key) {
        return None;
    }
    let use_query_form = scope_rel.is_empty() && has_single_colon(&pat);
    let (mcp_args, cli_cmd) = if use_query_form {
        let escaped = pat.replace('\\', "\\\\").replace('"', "\\\"");
        (
            format!("{{\"query\": \"{escaped}\"}}"),
            format!("ctx search \"{escaped}\""),
        )
    } else {
        let q_arg = if scope_rel.is_empty() {
            pat
        } else {
            format!("{scope_rel}:{pat}")
        };
        let escaped = q_arg.replace('\\', "\\\\").replace('"', "\\\"");
        (
            format!("{{\"q\": [\"{escaped}\"]}}"),
            format!("ctx search -q \"{escaped}\""),
        )
    };
    let is_worker = svc.store.is_worker_session(sess_key);
    if host == "agy" && is_worker {
        Some(format!(
            "[RAM-Ctx] Use CLI `{cli_cmd}` for workspace search instead of shell `grep`/`rg` (ranked, in-RAM, 1-6 `-q` queries in 1 call). (Repeat this exact command once if raw grep/rg output is strictly required.)"
        ))
    } else if host == "agy" {
        Some(format!(
            "[RAM-Ctx] Use `ctx_search` for workspace search instead of shell `grep`/`rg`: `mcp_agent_ctx_ctx_search({mcp_args})` (or `call_mcp_tool(ServerName=\"agent_ctx\", ToolName=\"ctx_search\", Arguments={mcp_args})` / CLI `{cli_cmd}`). (Repeat this exact command once if raw grep/rg output is strictly required.)"
        ))
    } else {
        Some(format!(
            "[RAM-Ctx] Use `ctx_search` for workspace search instead of shell `grep`/`rg`: `ctx_search({mcp_args})` (CLI `{cli_cmd}`). (Repeat this exact command once if raw grep/rg output is strictly required.)"
        ))
    }
}

struct GitRedirectSpec {
    cli_cmd: String,
    mcp_args: String,
}

fn is_simple_git_rev(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && !s.contains("..")
        && !s.contains(':')
        && !s.contains('*')
        && !s.contains('?')
        && !s.contains('[')
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.' | b'~' | b'^')
        })
}

fn escape_json_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn admit_git_diff_path(
    svc: &BrokerService,
    cand: &Path,
    base: &Path,
    ws_root: &Path,
) -> Option<String> {
    if is_sensitive_path(cand) || is_internal_ide_path(cand) {
        return None;
    }
    if cand.is_dir() {
        let (canon, wr) = svc.allowlist.admit_dir(cand, Some(base)).ok()?;
        if wr != ws_root {
            return None;
        }
        Some(if canon == wr {
            ".".to_string()
        } else {
            display_workspace_path(&canon, Some(&wr))
        })
    } else if cand.is_file() {
        let (canon, wr) = svc.allowlist.admit_file(cand, Some(base)).ok()?;
        if wr != ws_root {
            return None;
        }
        Some(display_workspace_path(&canon, Some(&wr)))
    } else {
        None
    }
}

fn detect_single_workspace_readonly_git_spec(
    svc: &BrokerService,
    seg: &str,
    cwd: Option<&Path>,
) -> Option<GitRedirectSpec> {
    let tokens = split_shell_tokens(seg)?;
    if tokens.len() < 2 {
        return None;
    }
    let prog = command_basename(&tokens[0]);
    if !matches!(prog, "git" | "git.exe") {
        return None;
    }
    // Reject any global git flag (`-C`, `--git-dir`, `--work-tree`, `-c`, `--no-pager`, etc.)
    let sub = tokens[1].as_str();
    if sub.starts_with('-') {
        return None;
    }
    let base = cwd?;
    if is_internal_ide_path(base) || is_sensitive_path(base) {
        return None;
    }
    let (_canon_base, ws_root) = svc.allowlist.admit_dir(base, Some(base)).ok()?;

    match sub {
        "status" => {
            if tokens.len() != 2 {
                return None;
            }
            Some(GitRedirectSpec {
                cli_cmd: "ctx git status".to_string(),
                mcp_args: "{\"action\": \"status\"}".to_string(),
            })
        }
        "diff" => {
            let mut staged = false;
            let mut stat = false;
            let mut rev: Option<String> = None;
            let mut paths: Vec<String> = Vec::new();
            let mut after_dd = false;

            for tok in &tokens[2..] {
                let s = tok.as_str();
                if !after_dd {
                    if s == "--" {
                        after_dd = true;
                        continue;
                    }
                    if s == "--staged" || s == "--cached" {
                        staged = true;
                        continue;
                    }
                    if s == "--stat" {
                        stat = true;
                        continue;
                    }
                    if s.is_empty()
                        || s.starts_with('-')
                        || s.contains("..")
                        || s.contains(':')
                        || s.contains('*')
                        || s.contains('?')
                        || s.contains('[')
                    {
                        return None;
                    }
                    let cand = resolve_input_path(s, Some(base));
                    if is_sensitive_path(&cand) || is_internal_ide_path(&cand) {
                        return None;
                    }
                    if fs::symlink_metadata(&cand).is_ok() {
                        let rel = admit_git_diff_path(svc, &cand, base, &ws_root)?;
                        paths.push(rel);
                    } else {
                        // Allow a single simple revision before any path / `--`.
                        if !paths.is_empty() || rev.is_some() || !is_simple_git_rev(s) {
                            return None;
                        }
                        rev = Some(s.to_string());
                    }
                } else {
                    if s.is_empty()
                        || s.starts_with('-')
                        || s.contains("..")
                        || s.contains(':')
                        || s.contains('*')
                        || s.contains('?')
                        || s.contains('[')
                    {
                        return None;
                    }
                    let cand = resolve_input_path(s, Some(base));
                    let rel = admit_git_diff_path(svc, &cand, base, &ws_root)?;
                    paths.push(rel);
                }
            }

            let mut cli = String::from("ctx git diff");
            let mut mcp_parts = vec!["\"action\": \"diff\"".to_string()];
            if staged {
                cli.push_str(" --staged");
                mcp_parts.push("\"staged\": true".to_string());
            }
            if stat {
                cli.push_str(" --stat");
                mcp_parts.push("\"stat\": true".to_string());
            }
            if let Some(ref r) = rev {
                cli.push_str(" --rev ");
                cli.push_str(r);
                mcp_parts.push(format!("\"rev\": \"{}\"", escape_json_str(r)));
            }
            if !paths.is_empty() {
                for p in &paths {
                    cli.push(' ');
                    if p.contains(' ') {
                        cli.push('"');
                        cli.push_str(&escape_json_str(p));
                        cli.push('"');
                    } else {
                        cli.push_str(p);
                    }
                }
                let p_json: Vec<String> = paths
                    .iter()
                    .map(|p| format!("\"{}\"", escape_json_str(p)))
                    .collect();
                mcp_parts.push(format!("\"paths\": [{}]", p_json.join(", ")));
            }
            Some(GitRedirectSpec {
                cli_cmd: cli,
                mcp_args: format!("{{{}}}", mcp_parts.join(", ")),
            })
        }
        "log" => {
            let mut limit: Option<usize> = None;
            let mut i = 2usize;
            while i < tokens.len() {
                let s = tokens[i].as_str();
                if s == "--oneline" {
                    i += 1;
                    continue;
                }
                if s == "-n" {
                    if limit.is_some() || i + 1 >= tokens.len() {
                        return None;
                    }
                    let n = tokens[i + 1].parse::<usize>().ok()?;
                    if !(1..=40).contains(&n) {
                        return None;
                    }
                    limit = Some(n);
                    i += 2;
                    continue;
                }
                if let Some(rest) = s.strip_prefix("-n").filter(|r| !r.is_empty()) {
                    if limit.is_some() {
                        return None;
                    }
                    let n = rest.parse::<usize>().ok()?;
                    if !(1..=40).contains(&n) {
                        return None;
                    }
                    limit = Some(n);
                    i += 1;
                    continue;
                }
                if let Some(digits) = s
                    .strip_prefix('-')
                    .filter(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()))
                {
                    if limit.is_some() {
                        return None;
                    }
                    let n = digits.parse::<usize>().ok()?;
                    if !(1..=40).contains(&n) {
                        return None;
                    }
                    limit = Some(n);
                    i += 1;
                    continue;
                }
                return None;
            }
            let (cli_cmd, mcp_args) = match limit {
                Some(n) => (
                    format!("ctx git log -n {n}"),
                    format!("{{\"action\": \"log\", \"limit\": {n}}}"),
                ),
                None => (
                    "ctx git log".to_string(),
                    "{\"action\": \"log\"}".to_string(),
                ),
            };
            Some(GitRedirectSpec { cli_cmd, mcp_args })
        }
        "show" => {
            if tokens.len() != 3 {
                return None;
            }
            let rev = tokens[2].as_str();
            if !is_simple_git_rev(rev) {
                return None;
            }
            Some(GitRedirectSpec {
                cli_cmd: format!("ctx git show {rev}"),
                mcp_args: format!(
                    "{{\"action\": \"show\", \"rev\": \"{}\"}}",
                    escape_json_str(rev)
                ),
            })
        }
        _ => None,
    }
}

fn detect_workspace_readonly_git_spec(
    svc: &BrokerService,
    cmd: &str,
    cwd: Option<&Path>,
) -> Option<GitRedirectSpec> {
    let segments = extract_shell_segments_ignoring_echo(cmd);
    if segments.is_empty()
        || segments.iter().any(|seg| {
            segment_changes_cwd(seg)
                || segment_invokes_mutating_git(seg)
                || !matches!(segment_primary_prog(seg).as_deref(), Some("git" | "git.exe"))
        })
    {
        return None;
    }
    for seg in &segments {
        if segment_has_unsafe_shell_ops(seg) {
            continue;
        }
        if let Some(spec) = detect_single_workspace_readonly_git_spec(svc, seg, cwd) {
            return Some(spec);
        }
    }
    None
}

#[cfg(test)]
pub(super) fn detect_workspace_readonly_git(
    svc: &BrokerService,
    cmd: &str,
    cwd: Option<&Path>,
) -> Option<String> {
    detect_workspace_readonly_git_spec(svc, cmd, cwd).map(|s| s.cli_cmd)
}

pub(super) fn workspace_git_redirect_reason(
    svc: &BrokerService,
    host: &str,
    sess_key: &str,
    cmd: &str,
    cwd: Option<&Path>,
) -> Option<String> {
    let spec = detect_workspace_readonly_git_spec(svc, cmd, cwd)?;
    let strike_key = format!(
        "{}:{}:ShellGit:{:016x}",
        host,
        sess_key,
        fast_hash64(cmd.trim().as_bytes())
    );
    if svc.store.check_and_mark_dedup(&strike_key) {
        return None;
    }
    let is_worker = svc.store.is_worker_session(sess_key);
    if host == "agy" && is_worker {
        Some(format!(
            "[RAM-Ctx] Use CLI `{}` for compact read-only Git inspection (symbol-aware, secret-filtered, hash-anchored). (Repeat this exact command once if raw git output is strictly required.)",
            spec.cli_cmd
        ))
    } else if host == "agy" {
        Some(format!(
            "[RAM-Ctx] Use `ctx_git` for compact read-only Git inspection: `mcp_agent_ctx_ctx_git({})` (CLI `{}`). (Repeat this exact command once if raw git output is strictly required.)",
            spec.mcp_args, spec.cli_cmd
        ))
    } else {
        Some(format!(
            "[RAM-Ctx] Use `ctx_git` for compact read-only Git inspection: `ctx_git({})` (CLI `{}`). (Repeat this exact command once if raw git output is strictly required.)",
            spec.mcp_args, spec.cli_cmd
        ))
    }
}

fn parse_tool_input_field(payload: &Json) -> Json {
    match payload.get("tool_input") {
        Some(Json::Str(s)) => json::parse(s).unwrap_or_else(|_| Json::Str(s.clone())),
        Some(other) => other.clone(),
        None => Json::Obj(Vec::new()),
    }
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

#[cfg(test)]
mod tests {
    use super::codex::extract_codex_exec_commands;
    use super::startup::extract_candidate_paths_from_text;
    use super::*;
    use crate::engine::{AGY_MCP_DEFAULT_MAX_BYTES, AGY_MCP_INLINE_CAP};
    use crate::rpc::{execute_request, BrokerService};
    use crate::store::now_ms_u64;

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
            now_ms_u64()
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
                        (
                            "args",
                            Json::obj(vec![(
                                "paths",
                                Json::Arr(vec![Json::Str("Big.hpp".into())]),
                            )]),
                        ),
                    ]),
                ),
            ]);
            let reply = handle_hook(&svc, "agy", &req.to_json_string());
            assert!(
                reply.get("overwrite").is_none(),
                "{readonly_tool} should not rewrite ctx_context"
            );
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
                    (
                        "args",
                        Json::obj(vec![(
                            "paths",
                            Json::Arr(vec![Json::Str("Big.hpp".into())]),
                        )]),
                    ),
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

    #[test]
    fn startup_candidate_paths_resolve_nested_dirs_generically() {
        assert!(!SUBAGENT_STARTUP_DIGEST.contains("ReportFormat.md"));
        let workspace = std::env::temp_dir().join(format!(
            "ctx-hooks-dirs-{}-{}",
            std::process::id(),
            now_ms_u64()
        ));
        let nested = workspace.join("packages").join("Core").join("Math");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("Ops.hpp"), "inline int add(int a, int b) { return a + b; }\n")
            .unwrap();

        let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
        let root = svc.allowlist.register_hint(&workspace, true).unwrap();

        let found = extract_candidate_paths_from_text(
            &svc,
            "Audit `Core/Math/**` for integer divisions.",
            Some(&workspace),
            Some(&root),
        );
        assert_eq!(found, vec![root.join("packages").join("Core").join("Math")]);

        fs::remove_dir_all(&workspace).unwrap();
    }

    #[test]
    fn workspace_grep_redirect_is_one_strike_and_allows_external_pipes_and_count_flags() {
        let base = std::env::temp_dir().join(format!(
            "ctx-hooks-grep-{}-{}",
            std::process::id(),
            now_ms_u64()
        ));
        let ws = base.join("repo");
        let outside = base.join("outside.log");
        fs::create_dir_all(ws.join("backend")).unwrap();
        fs::write(ws.join("backend/views.py"), "LEGAL_DOCUMENT_VERSION = 2\n").unwrap();
        fs::write(&outside, "LEGAL_DOCUMENT_VERSION = 9\n").unwrap();

        let svc = BrokerService::new_ephemeral_inproc(base.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();

        // 1. Simple workspace grep/rg is redirected once, then allowed on repeat (1-strike escape).
        let cmd = "grep -n \"LEGAL_DOCUMENT_VERSION\" backend/views.py";
        let r1 = workspace_grep_redirect_reason(&svc, "agy", "agy:old-chat", cmd, Some(&ws))
            .expect("first workspace grep should redirect");
        assert!(r1.contains("backend/views.py:LEGAL_DOCUMENT_VERSION"), "{r1}");
        assert!(r1.contains("call_mcp_tool"), "{r1}");
        assert!(
            workspace_grep_redirect_reason(&svc, "agy", "agy:old-chat", cmd, Some(&ws)).is_none(),
            "repeat of exact grep must pass through"
        );

        // 2. External file outside workspace is NEVER blocked.
        let ext_cmd = format!("grep -n \"LEGAL_DOCUMENT_VERSION\" {}", outside.display());
        assert!(workspace_grep_redirect_reason(&svc, "claude", "claude:s1", &ext_cmd, Some(&ws)).is_none());

        // 3. Pipelines, count/list flags, and `rg --files` pass straight through.
        for ok_cmd in [
            "grep -c LEGAL_DOCUMENT_VERSION backend/views.py",
            "grep -n LEGAL_DOCUMENT_VERSION backend/views.py | head -n 5",
            "rg --files backend",
            "rg -l LEGAL_DOCUMENT_VERSION backend",
        ] {
            assert!(
                workspace_grep_redirect_reason(&svc, "codex", "codex:s1", ok_cmd, Some(&ws)).is_none(),
                "should not redirect `{ok_cmd}`"
            );
        }

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn extract_shell_segments_and_multiline_git_grep_redirects_respect_guards() {
        let segs = extract_shell_segments_ignoring_echo(concat!(
            "# leading comment\n",
            "echo \"=== DIFF; a && b ===\"\n",
            "printf 'section %s\\n' one && \\\n",
            "git diff \\\n",
            "  src/a.rs src/b.rs\n",
            "echo $'tail\\'s; ok'\n",
        ));
        assert_eq!(segs, vec!["git diff    src/a.rs src/b.rs".to_string()]);

        // Unsafe echo/printf (redirects, pipes, subshells) are NOT dropped as harmless banners.
        let kept = extract_shell_segments_ignoring_echo(
            "echo hi > out.txt; echo \"$(id)\"; echo ok | cat; printf -v x hi",
        );
        assert_eq!(kept.len(), 4, "{kept:?}");

        let base = std::env::temp_dir().join(format!(
            "ctx-hooks-multi-{}-{}",
            std::process::id(),
            now_ms_u64()
        ));
        let ws = base.join("repo");
        let outside = base.join("outside.rs");
        fs::create_dir_all(ws.join("src")).unwrap();
        fs::write(ws.join("src/a.rs"), "pub fn alpha() -> i32 { 1 }\n").unwrap();
        fs::write(ws.join("src/b.rs"), "pub fn beta() -> i32 { 2 }\n").unwrap();
        fs::write(ws.join(".env"), "API_KEY=secret\n").unwrap();
        fs::write(&outside, "pub fn ext() {}\n").unwrap();

        let svc = BrokerService::new_ephemeral_inproc(base.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();

        // 1. Multiline `echo ...\ngit diff src/a.rs src/b.rs` and single `git diff src/a.rs` (no `--`) redirect!
        assert_eq!(
            detect_workspace_readonly_git(
                &svc,
                "echo \"=== DIFF ===\"\ngit diff src/a.rs src/b.rs",
                Some(&ws),
            )
            .as_deref(),
            Some("ctx git diff src/a.rs src/b.rs")
        );
        assert_eq!(
            detect_workspace_readonly_git(&svc, "git diff src/a.rs", Some(&ws)).as_deref(),
            Some("ctx git diff src/a.rs")
        );
        assert_eq!(
            detect_workspace_readonly_git(&svc, "git diff --stat src", Some(&ws)).as_deref(),
            Some("ctx git diff --stat src")
        );
        assert_eq!(
            detect_workspace_readonly_git(&svc, "git diff HEAD src/a.rs", Some(&ws)).as_deref(),
            Some("ctx git diff --rev HEAD src/a.rs")
        );
        assert_eq!(
            detect_workspace_readonly_git(&svc, "echo \"=== LOG ===\" && git log -n 5", Some(&ws))
                .as_deref(),
            Some("ctx git log -n 5")
        );

        // 2. Mutating git flows, cwd shifts, rev ranges, sensitive/outside paths, and pipes MUST return None.
        let outside_diff = format!("git diff {}", outside.display());
        for pass_cmd in [
            "git add src/a.rs && git status",
            "git -C /other commit -m \"msg\" && git diff src/a.rs",
            "git status && git push",
            "git checkout main; git diff src/a.rs",
            "git reset --hard && git status",
            "cd src && git status",
            "git -C /other status",
            "git status --porcelain",
            "git diff HEAD~1..HEAD",
            "git diff HEAD main",
            "git diff src/a.rs HEAD",
            "git diff .env",
            outside_diff.as_str(),
            "git diff src/a.rs | grep alpha",
            "git diff src/a.rs > out.patch",
            "git status || true",
        ] {
            assert!(
                detect_workspace_readonly_git(&svc, pass_cmd, Some(&ws)).is_none(),
                "must NOT redirect `{pass_cmd}`"
            );
        }

        // 3. Multiline `echo ...\ngrep` and `echo ... && rg` redirect on 1-Strike, then allow on Strike 2.
        let mgrep = "echo \"=== CHECK ===\"\ngrep -rn alpha src/";
        let gr1 = workspace_grep_redirect_reason(&svc, "agy", "agy:g1", mgrep, Some(&ws))
            .expect("multiline grep must redirect on Strike 1");
        assert!(gr1.contains("src:alpha"), "{gr1}");
        assert!(
            workspace_grep_redirect_reason(&svc, "agy", "agy:g1", mgrep, Some(&ws)).is_none(),
            "multiline grep must pass on Strike 2"
        );

        let mrg = "echo \"=== RG ===\" && rg beta src/";
        let rg1 = workspace_grep_redirect_reason(&svc, "agy", "agy:g2", mrg, Some(&ws))
            .expect("echo && rg must redirect on Strike 1");
        assert!(rg1.contains("src:beta"), "{rg1}");

        // Piped or cwd-shifted grep stays unblocked.
        assert!(
            workspace_grep_redirect_reason(
                &svc,
                "agy",
                "agy:g3",
                "echo \"=== PIPE ===\"\ngrep -rn alpha src/ | head -n 5",
                Some(&ws),
            )
            .is_none()
        );
        assert!(
            workspace_grep_redirect_reason(
                &svc,
                "agy",
                "agy:g4",
                "cd /tmp && grep -rn alpha .",
                Some(&ws),
            )
            .is_none()
        );

        let _ = fs::remove_dir_all(&base);
    }
}
