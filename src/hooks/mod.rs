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
const AGY_WIDEN_MAX_BYTES: u32 = 44_000;
const STARTUP_BUDGET_BYTES: usize = 2500;

const SUBAGENT_STARTUP_DIGEST: &str = "Batch calls: ctx_inspect (dirs), ctx_search (`q`: 1-6 `Mod:pat`), ctx_symbols (full body; `compact=true` <=48L), ctx_read (slices >800L in AGY or full files <=1MiB in Codex); use CLI `ctx inspect|search|outline|sym` if MCP is absent. Finish from search/symbols when sufficient.";

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

fn split_shell_tokens(raw: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            if ch == '\\' && q == '"' {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            } else if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                in_token = true;
            }
            c if c.is_whitespace() => {
                if in_token {
                    out.push(std::mem::take(&mut cur));
                    in_token = false;
                }
            }
            '\\' => {
                in_token = true;
                if let Some(next) = chars.next() {
                    cur.push(next);
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

fn detect_workspace_shell_grep(
    svc: &BrokerService,
    cmd: &str,
    cwd: Option<&Path>,
) -> Option<(String, String)> {
    let trimmed = cmd.trim();
    if trimmed.is_empty()
        || trimmed.contains('\n')
        || trimmed.contains('|')
        || trimmed.contains("&&")
        || trimmed.contains(';')
        || trimmed.contains('>')
        || trimmed.contains('<')
        || trimmed.contains('`')
        || trimmed.contains("$(")
    {
        return None;
    }
    let tokens = split_shell_tokens(trimmed)?;
    if tokens.len() < 2 {
        return None;
    }
    let prog = Path::new(&tokens[0])
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(tokens[0].as_str());
    if !matches!(prog, "grep" | "egrep" | "fgrep" | "rg") {
        return None;
    }

    let mut pattern: Option<String> = None;
    let mut targets: Vec<String> = Vec::new();
    let mut after_dd = false;
    let mut i = 1usize;
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
            if is_sensitive_path(&p) || is_internal_ide_path(&p) || is_multimodal_or_binary_ext(&p) {
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
    if host == "agy" {
        Some(format!(
            "[RAM-Ctx] Use `ctx_search` for workspace search instead of shell `grep`/`rg`: `mcp_agent_ctx_ctx_search({mcp_args})` (or `call_mcp_tool(ServerName=\"agent_ctx\", ToolName=\"ctx_search\", Arguments={mcp_args})` / CLI `{cli_cmd}`). (Repeat this exact command once if raw grep/rg output is strictly required.)"
        ))
    } else {
        Some(format!(
            "[RAM-Ctx] Use `ctx_search` for workspace search instead of shell `grep`/`rg`: `ctx_search({mcp_args})` (CLI `{cli_cmd}`). (Repeat this exact command once if raw grep/rg output is strictly required.)"
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
}
