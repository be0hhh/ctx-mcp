//! Antigravity (`agy` / `antigravity`) hook handler:
//!   - `SessionStart` / `PreInvocation` turn-0 startup outline & memo injection.
//!   - `PreToolUse` MCP ticket binding, opt-in capsule staging, moved-file resolution,
//!     duplicate-read prevention with exact `800L / 46,080B` accounting, auto-widen for
//!     `<=800L & <=44KB` reads, and `BroadFind` / shell-slicing guards.
//!   - `PostToolUse` cache invalidation and exact delivered read-span recording.

use super::startup::{
    classify_agy_startup, prewarm_and_build_startup_capsule, AgyStartupKind, StartupChannel,
};
use super::{
    capsule_auto_stage_enabled, command_basename, delivery_notice, detect_shell_file_slicing,
    extract_cwd, extract_git_subcommand, extract_shell_segments_ignoring_echo, host_context,
    is_env_assignment_token, is_internal_ide_path, is_workspace_mutating_shell,
    mcp_context_rewrite, passthrough, register_payload_workspaces, replace_field,
    segment_changes_cwd, segment_has_redirects_or_subshell, split_shell_tokens,
    split_unquoted_pipes, workspace_git_redirect_reason, workspace_grep_redirect_reason,
    AGY_NATIVE_DELIVERY_BYTE_CAP, AGY_NATIVE_LINE_CAP, AGY_WIDEN_MAX_BYTES, AGY_WIDEN_MAX_LINES,
};
use crate::base::json::{Json, JsonKey};
use crate::base::security::{is_sensitive_path, is_sensitive_path_with_ws};
use crate::base::simd::fast_hash64;
use crate::broker::{HostContext, WorkspaceMode};
use crate::engine::walk_source_dir;
use crate::parser::{is_code_source_ext, SymbolKind};
use crate::rpc::BrokerService;
use crate::store::{
    display_workspace_path, is_multimodal_or_binary_ext, now_ms_u64, resolve_input_path,
    restore_caller_path_style, shared_repo_key, CachedFile, MissingResolution, RamStore,
};
use std::borrow::Cow;
use std::fs;
use std::path::{Component, Path, PathBuf};

const DEFAULT_LARGE_READ_LINES: usize = 350;

fn large_read_threshold() -> usize {
    match std::env::var("AGENT_CTX_LARGE_READ_LINES") {
        Ok(raw) => raw
            .trim()
            .parse::<usize>()
            .unwrap_or(DEFAULT_LARGE_READ_LINES),
        Err(_) => DEFAULT_LARGE_READ_LINES,
    }
}

#[cfg(any(unix, test))]
fn is_valid_cli_conv_id(conv_id: &str) -> bool {
    (1..=128).contains(&conv_id.len())
        && conv_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(any(unix, test))]
fn is_env_assignment_bytes(tok: &[u8]) -> bool {
    let Some(eq_idx) = tok.iter().position(|&b| b == b'=') else {
        return false;
    };
    let name = &tok[..eq_idx];
    !name.is_empty()
        && (name[0].is_ascii_alphabetic() || name[0] == b'_')
        && name[1..]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(any(unix, test))]
fn is_ctx_command_bytes(tok: &[u8]) -> bool {
    if tok == b"ctx" {
        return true;
    }
    match tok.iter().rposition(|&b| b == b'/') {
        Some(idx) => &tok[idx + 1..] == b"ctx",
        None => false,
    }
}

/// Quote-aware tokenizer that detects whether a POSIX shell command invokes `ctx`
/// (or `*/ctx`, optionally preceded by `VAR=val` env assignments) in command position.
/// Ignores single- and double-quoted strings and skips commands already setting `AGENT_CTX_SESSION=`.
#[cfg(any(unix, test))]
fn command_invokes_ctx(cmd: &str) -> bool {
    if cmd.contains("AGENT_CTX_SESSION=") {
        return false;
    }
    let bytes = cmd.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut expect_cmd = true;
    let mut tok: Vec<u8> = Vec::with_capacity(32);

    while i < len {
        while i < len && matches!(bytes[i], b' ' | b'\t' | b'\r') {
            i += 1;
        }
        if i >= len {
            break;
        }
        let b = bytes[i];
        if b == b'#' {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'\n' || b == b';' {
            expect_cmd = true;
            i += 1;
            continue;
        }
        if b == b'&' {
            expect_cmd = true;
            i += if bytes.get(i + 1) == Some(&b'&') { 2 } else { 1 };
            continue;
        }
        if b == b'|' {
            expect_cmd = true;
            i += if bytes.get(i + 1) == Some(&b'|') { 2 } else { 1 };
            continue;
        }
        if b == b'(' {
            expect_cmd = true;
            i += 1;
            continue;
        }
        if b == b'$' && bytes.get(i + 1) == Some(&b'(') {
            expect_cmd = true;
            i += 2;
            continue;
        }
        if b == b')' {
            expect_cmd = false;
            i += 1;
            continue;
        }

        tok.clear();
        let mut saw_any_quote = false;
        let mut saw_quote_before_eq = false;
        let mut saw_unquoted_eq = false;

        while i < len {
            let c = bytes[i];
            if c == b'$' && bytes.get(i + 1) == Some(&b'\'') {
                saw_any_quote = true;
                if !saw_unquoted_eq {
                    saw_quote_before_eq = true;
                }
                i += 2;
                while i < len && bytes[i] != b'\'' {
                    if bytes[i] == b'\\' && i + 1 < len {
                        i += 1;
                    }
                    tok.push(bytes[i]);
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
                continue;
            }
            if c == b'\'' {
                saw_any_quote = true;
                if !saw_unquoted_eq {
                    saw_quote_before_eq = true;
                }
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    tok.push(bytes[i]);
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
                continue;
            }
            if c == b'"' {
                saw_any_quote = true;
                if !saw_unquoted_eq {
                    saw_quote_before_eq = true;
                }
                i += 1;
                while i < len && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < len {
                        i += 1;
                    }
                    tok.push(bytes[i]);
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
                continue;
            }
            if c == b'\\' && i + 1 < len {
                i += 1;
                tok.push(bytes[i]);
                i += 1;
                continue;
            }
            if matches!(
                c,
                b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' | b'(' | b')'
            ) {
                break;
            }
            if c == b'$' && bytes.get(i + 1) == Some(&b'(') {
                break;
            }
            if c == b'=' && !saw_quote_before_eq {
                saw_unquoted_eq = true;
            }
            tok.push(c);
            i += 1;
        }

        if tok.is_empty() && !saw_any_quote {
            i += 1;
            continue;
        }
        if expect_cmd {
            if saw_unquoted_eq && !saw_quote_before_eq && is_env_assignment_bytes(&tok) {
                continue;
            }
            if !saw_any_quote
                && matches!(
                    tok.as_slice(),
                    b"time" | b"!" | b"then" | b"do" | b"else" | b"elif"
                )
            {
                continue;
            }
            if is_ctx_command_bytes(&tok) {
                return true;
            }
            expect_cmd = false;
        }
    }
    false
}

fn lexical_clean_path(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(seg) => out.push(seg),
        }
    }
    Some(out)
}

fn record_native_edit_change(
    svc: &BrokerService,
    p: &Path,
    cwd: Option<&Path>,
    ws_root: Option<&Path>,
    sess_key: &str,
) {
    if is_internal_ide_path(p) {
        return;
    }
    if p.exists() {
        let Ok((canon, root)) = svc.allowlist.admit_file(p, cwd) else {
            return;
        };
        if is_internal_ide_path(&canon) || is_sensitive_path_with_ws(&canon, Some(&root), false) {
            return;
        }
        let rel = display_workspace_path(&canon, Some(&root));
        let changed_syms: Vec<String> = svc
            .store
            .get_outline_entry(&canon, Some(&root))
            .map(|entry| {
                entry
                    .symbols
                    .iter()
                    .filter(|s| s.kind != SymbolKind::Namespace)
                    .take(8)
                    .map(|s| format!("@{}", s.name))
                    .collect()
            })
            .unwrap_or_default();
        let shared_key = shared_repo_key(&root);
        let _ = svc.broker.changes.record_change(
            &shared_key,
            &rel,
            changed_syms,
            sess_key,
            now_ms_u64(),
        );
    } else if let Some(root) = ws_root {
        let Some(clean_p) = lexical_clean_path(p) else {
            return;
        };
        let Ok(canon_root) = fs::canonicalize(root) else {
            return;
        };
        // Walk up to the nearest existing ancestor and canonicalize it first so symlinked
        // OS prefixes (e.g. macOS `/var` -> `/private/var`) resolve consistently while broken
        // symlinks and out-of-workspace ancestors fail closed.
        let mut canon_candidate: Option<PathBuf> = None;
        let mut anc = clean_p.parent();
        while let Some(dir) = anc {
            if fs::symlink_metadata(dir).is_ok() {
                let Ok(canon_anc) = fs::canonicalize(dir) else {
                    return;
                };
                if !canon_anc.starts_with(&canon_root) {
                    return;
                }
                let Ok(tail) = clean_p.strip_prefix(dir) else {
                    return;
                };
                canon_candidate = Some(canon_anc.join(tail));
                break;
            }
            anc = dir.parent();
        }
        let Some(candidate_in_root) = canon_candidate else {
            return;
        };
        let Ok(rel_path) = candidate_in_root.strip_prefix(&canon_root) else {
            return;
        };
        if rel_path.as_os_str().is_empty()
            || !rel_path
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
        {
            return;
        }
        if is_internal_ide_path(&candidate_in_root)
            || is_sensitive_path_with_ws(&candidate_in_root, Some(&canon_root), false)
            || is_sensitive_path_with_ws(&clean_p, Some(&canon_root), false)
        {
            return;
        }
        let Some(rel_str) = rel_path.to_str() else {
            return;
        };
        let rel = rel_str.replace('\\', "/");
        let shared_key = shared_repo_key(&canon_root);
        let _ = svc.broker.changes.record_change(
            &shared_key,
            &rel,
            Vec::new(),
            sess_key,
            now_ms_u64(),
        );
    }
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

    if !entry.has_body() {
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

fn push_utf8_non_ascii(cmd: &str, bytes: &[u8], i: &mut usize, dst: &mut String) {
    let start = *i;
    while *i < bytes.len() && bytes[*i] >= 0x80 {
        *i += 1;
    }
    dst.push_str(&cmd[start..*i]);
}

/// Quote-aware POSIX shell splitter for `MultiCtxChainGate`.
/// Joins `\\\n` / `\\\r\n` continuations, respects `'...'`, `"..."`, `$'...'`, `\`, and `#`-comments,
/// splits top-level commands on unquoted `\n`, `;`, `&&`, `||`, and keeps only the primary command
/// tokens of each segment (ignoring downstream pipe stages and redirect targets).
fn split_chain_commands(cmd: &str) -> Vec<Vec<String>> {
    let bytes = cmd.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut cmds: Vec<Vec<String>> = Vec::new();
    let mut cur_cmd: Vec<String> = Vec::new();
    let mut cur_tok = String::new();
    let mut in_tok = false;
    let mut skip_pipe_rest = false;
    let mut skip_next_tok = false;

    let flush_tok = |cur_tok: &mut String,
                     in_tok: &mut bool,
                     cur_cmd: &mut Vec<String>,
                     skip_pipe_rest: bool,
                     skip_next_tok: &mut bool| {
        if *in_tok {
            let tok = std::mem::take(cur_tok);
            *in_tok = false;
            if *skip_next_tok {
                *skip_next_tok = false;
            } else if !skip_pipe_rest {
                cur_cmd.push(tok);
            }
        }
    };

    let flush_cmd = |cur_cmd: &mut Vec<String>,
                     cmds: &mut Vec<Vec<String>>,
                     skip_pipe_rest: &mut bool,
                     skip_next_tok: &mut bool| {
        if !cur_cmd.is_empty() {
            cmds.push(std::mem::take(cur_cmd));
        }
        *skip_pipe_rest = false;
        *skip_next_tok = false;
    };

    while i < len {
        let b = bytes[i];
        if b >= 0x80 {
            push_utf8_non_ascii(cmd, bytes, &mut i, &mut cur_tok);
            in_tok = true;
            continue;
        }
        if matches!(b, b' ' | b'\t' | b'\r') {
            flush_tok(
                &mut cur_tok,
                &mut in_tok,
                &mut cur_cmd,
                skip_pipe_rest,
                &mut skip_next_tok,
            );
            i += 1;
            continue;
        }
        if b == b'#' && !in_tok {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'\n' || b == b';' {
            flush_tok(
                &mut cur_tok,
                &mut in_tok,
                &mut cur_cmd,
                skip_pipe_rest,
                &mut skip_next_tok,
            );
            flush_cmd(&mut cur_cmd, &mut cmds, &mut skip_pipe_rest, &mut skip_next_tok);
            i += 1;
            continue;
        }
        if b == b'&' && bytes.get(i + 1) == Some(&b'&') {
            flush_tok(
                &mut cur_tok,
                &mut in_tok,
                &mut cur_cmd,
                skip_pipe_rest,
                &mut skip_next_tok,
            );
            flush_cmd(&mut cur_cmd, &mut cmds, &mut skip_pipe_rest, &mut skip_next_tok);
            i += 2;
            continue;
        }
        if b == b'|' {
            flush_tok(
                &mut cur_tok,
                &mut in_tok,
                &mut cur_cmd,
                skip_pipe_rest,
                &mut skip_next_tok,
            );
            if bytes.get(i + 1) == Some(&b'|') {
                flush_cmd(&mut cur_cmd, &mut cmds, &mut skip_pipe_rest, &mut skip_next_tok);
                i += 2;
            } else {
                skip_pipe_rest = true;
                skip_next_tok = false;
                i += 1;
            }
            continue;
        }
        if b == b'(' && cur_cmd.is_empty() && !in_tok {
            i += 1;
            continue;
        }
        if b == b')' {
            flush_tok(
                &mut cur_tok,
                &mut in_tok,
                &mut cur_cmd,
                skip_pipe_rest,
                &mut skip_next_tok,
            );
            i += 1;
            continue;
        }
        if b == b'>' || b == b'<' || (b == b'&' && bytes.get(i + 1) == Some(&b'>')) {
            if in_tok && cur_tok.bytes().all(|d| d.is_ascii_digit()) {
                cur_tok.clear();
                in_tok = false;
            } else {
                flush_tok(
                    &mut cur_tok,
                    &mut in_tok,
                    &mut cur_cmd,
                    skip_pipe_rest,
                    &mut skip_next_tok,
                );
            }
            let leading_amp = b == b'&';
            if leading_amp {
                i += 1;
            }
            while i < len && matches!(bytes[i], b'>' | b'<') {
                i += 1;
            }
            if !leading_amp && bytes.get(i) == Some(&b'&') {
                i += 1;
                while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b'-') {
                    i += 1;
                }
            } else {
                skip_next_tok = true;
            }
            continue;
        }
        if b == b'$' && bytes.get(i + 1) == Some(&b'\'') {
            in_tok = true;
            i += 2;
            while i < len {
                let c = bytes[i];
                if c >= 0x80 {
                    push_utf8_non_ascii(cmd, bytes, &mut i, &mut cur_tok);
                    continue;
                }
                if c == b'\\' && i + 1 < len {
                    i += 1;
                    if bytes[i] >= 0x80 {
                        push_utf8_non_ascii(cmd, bytes, &mut i, &mut cur_tok);
                    } else {
                        cur_tok.push(bytes[i] as char);
                        i += 1;
                    }
                    continue;
                }
                if c == b'\'' {
                    i += 1;
                    break;
                }
                cur_tok.push(c as char);
                i += 1;
            }
            continue;
        }
        if b == b'\'' {
            in_tok = true;
            i += 1;
            while i < len {
                let c = bytes[i];
                if c >= 0x80 {
                    push_utf8_non_ascii(cmd, bytes, &mut i, &mut cur_tok);
                    continue;
                }
                if c == b'\'' {
                    i += 1;
                    break;
                }
                cur_tok.push(c as char);
                i += 1;
            }
            continue;
        }
        if b == b'"' {
            in_tok = true;
            i += 1;
            while i < len {
                let c = bytes[i];
                if c >= 0x80 {
                    push_utf8_non_ascii(cmd, bytes, &mut i, &mut cur_tok);
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
                        i += 1;
                        if bytes[i] >= 0x80 {
                            push_utf8_non_ascii(cmd, bytes, &mut i, &mut cur_tok);
                        } else {
                            cur_tok.push(bytes[i] as char);
                            i += 1;
                        }
                        continue;
                    }
                }
                if c == b'"' {
                    i += 1;
                    break;
                }
                cur_tok.push(c as char);
                i += 1;
            }
            continue;
        }
        if b == b'\\' {
            if bytes.get(i + 1) == Some(&b'\n') {
                flush_tok(
                    &mut cur_tok,
                    &mut in_tok,
                    &mut cur_cmd,
                    skip_pipe_rest,
                    &mut skip_next_tok,
                );
                i += 2;
                continue;
            }
            if bytes.get(i + 1) == Some(&b'\r') && bytes.get(i + 2) == Some(&b'\n') {
                flush_tok(
                    &mut cur_tok,
                    &mut in_tok,
                    &mut cur_cmd,
                    skip_pipe_rest,
                    &mut skip_next_tok,
                );
                i += 3;
                continue;
            }
            if i + 1 < len {
                in_tok = true;
                i += 1;
                if bytes[i] >= 0x80 {
                    push_utf8_non_ascii(cmd, bytes, &mut i, &mut cur_tok);
                } else {
                    cur_tok.push(bytes[i] as char);
                    i += 1;
                }
                continue;
            }
        }
        cur_tok.push(b as char);
        in_tok = true;
        i += 1;
    }

    flush_tok(
        &mut cur_tok,
        &mut in_tok,
        &mut cur_cmd,
        skip_pipe_rest,
        &mut skip_next_tok,
    );
    flush_cmd(&mut cur_cmd, &mut cmds, &mut skip_pipe_rest, &mut skip_next_tok);
    cmds
}

fn is_heavy_ctx_invocation(args: &[String]) -> bool {
    let mut idx = 0usize;
    while idx < args.len() && args[idx].starts_with('-') {
        idx += 1;
    }
    let Some(sub) = args.get(idx).map(String::as_str) else {
        return false;
    };
    if args[idx + 1..].iter().any(|a| a == "--help" || a == "-h") {
        return false;
    }
    match sub {
        "read" | "inspect" | "outline" | "sym" | "symbols" | "search" | "git" | "impact" => true,
        "memo" => {
            let mut midx = idx + 1;
            while midx < args.len() && args[midx].starts_with('-') {
                midx += 1;
            }
            match args.get(midx).map(String::as_str) {
                None => true,
                Some("changes" | "list" | "get" | "pack-get" | "pack_get" | "packs") => true,
                Some(_) => false,
            }
        }
        _ => false,
    }
}

fn is_raw_inspect_command(prog: &str, args: &[String]) -> bool {
    if matches!(prog, "grep" | "egrep" | "fgrep" | "rg" | "find") {
        return true;
    }
    if matches!(prog, "git" | "git.exe") {
        return matches!(
            extract_git_subcommand(args),
            Some("status" | "diff" | "log" | "show" | "grep")
        );
    }
    false
}

/// Detects chained heavy `ctx` commands (`heavy_ctx >= 2`) or a heavy `ctx` command combined with
/// a separate raw inspection command (`git` read-only / `grep` / `rg` / `find`) in one shell call.
fn detect_multi_ctx_chain(cmd: &str) -> Option<(usize, usize)> {
    let mut heavy_ctx = 0usize;
    let mut raw_inspect = 0usize;
    for tokens in split_chain_commands(cmd) {
        let mut idx = 0usize;
        while idx < tokens.len() {
            let tok = tokens[idx].as_str();
            if is_env_assignment_token(tok)
                || matches!(
                    tok,
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
        let prog = command_basename(cmd_tok);
        let args = &tokens[idx + 1..];
        if matches!(prog, "ctx" | "ctx.exe") {
            if is_heavy_ctx_invocation(args) {
                heavy_ctx += 1;
            }
        } else if is_raw_inspect_command(prog, args) {
            raw_inspect += 1;
        }
    }
    if heavy_ctx >= 2 || (heavy_ctx >= 1 && raw_inspect >= 1) {
        Some((heavy_ctx, raw_inspect))
    } else {
        None
    }
}

fn is_allowed_broad_find_pipe_stage(stage: &str) -> bool {
    let Some(tokens) = split_shell_tokens(stage) else {
        return false;
    };
    let Some(cmd_idx) = tokens.iter().position(|t| !is_env_assignment_token(t)) else {
        return false;
    };
    let pipe_prog = command_basename(&tokens[cmd_idx]);
    if pipe_prog == "sort" {
        return true;
    }
    if pipe_prog == "xargs" {
        let mut i = cmd_idx + 1;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            if tok == "--" {
                i += 1;
                break;
            }
            if matches!(
                tok,
                "-d" | "-E"
                    | "-I"
                    | "-L"
                    | "-l"
                    | "-n"
                    | "-P"
                    | "-s"
                    | "--delimiter"
                    | "--eof"
                    | "--replace"
                    | "--max-lines"
                    | "--max-args"
                    | "--max-procs"
                    | "--max-chars"
            ) {
                i += 2;
                continue;
            }
            if tok.starts_with('-') {
                i += 1;
                continue;
            }
            break;
        }
        return tokens
            .get(i)
            .is_some_and(|t| command_basename(t) == "wc");
    }
    false
}

fn detect_single_broad_source_find(
    svc: &BrokerService,
    seg: &str,
    cwd: Option<&Path>,
) -> Option<Vec<String>> {
    let trimmed = seg.trim();
    if trimmed.is_empty() || segment_has_redirects_or_subshell(trimmed) {
        return None;
    }

    let stages = split_unquoted_pipes(trimmed)?;
    if stages.is_empty() || stages.len() > 2 {
        return None;
    }
    if stages.len() == 2 && !is_allowed_broad_find_pipe_stage(&stages[1]) {
        return None;
    }

    let tokens = split_shell_tokens(&stages[0])?;
    if tokens.first().map(|t| command_basename(t)) != Some("find") {
        return None;
    }

    let mut idx = 1usize;
    while idx < tokens.len() {
        let tok = tokens[idx].as_str();
        if tok == "-delete" || tok.starts_with("-exec") || tok == "-ok" || tok == "-okdir" {
            return None;
        }
        if tok == "-maxdepth" {
            if let Some(depth) = tokens.get(idx + 1).map(String::as_str) {
                if matches!(depth, "0" | "1" | "2") {
                    return None;
                }
            }
            idx += 2;
            continue;
        }
        if matches!(tok, "-maxdepth0" | "-maxdepth1" | "-maxdepth2") {
            return None;
        }
        idx += 1;
    }

    let mut dir_roots: Vec<(String, PathBuf)> = Vec::new();
    for tok in &tokens[1..] {
        let tok = tok.as_str();
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

fn detect_broad_source_find(
    svc: &BrokerService,
    cmd: &str,
    cwd: Option<&Path>,
) -> Option<Vec<String>> {
    let segments = extract_shell_segments_ignoring_echo(cmd);
    if segments.is_empty() {
        return None;
    }
    for seg in &segments {
        if segment_changes_cwd(seg) {
            return None;
        }
        let first_stage = split_unquoted_pipes(seg)
            .and_then(|s| s.into_iter().next())
            .unwrap_or_default();
        let is_find = split_shell_tokens(&first_stage)
            .and_then(|toks| {
                let idx = toks.iter().position(|t| !is_env_assignment_token(t))?;
                Some(command_basename(&toks[idx]) == "find")
            })
            .unwrap_or(false);
        if !is_find {
            return None;
        }
    }
    for seg in &segments {
        if let Some(roots) = detect_single_broad_source_find(svc, seg, cwd) {
            return Some(roots);
        }
    }
    None
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
            AgyStartupKind::ForkedWorker => {
                svc.store.mark_worker_session(&sess_key);
                let _ = svc.store.try_mark_startup_injected(&sess_key);
                return Json::Obj(Vec::new());
            }
            AgyStartupKind::Undetermined => {
                return Json::Obj(Vec::new());
            }
            AgyStartupKind::Worker {
                brief: transcript_brief,
                cli_only,
            } => {
                if cli_only {
                    svc.store.mark_worker_session(&sess_key);
                }
                if svc.store.try_mark_startup_injected(&sess_key) {
                    let channel = if cli_only {
                        StartupChannel::AgyWorker
                    } else {
                        StartupChannel::AgyMcp
                    };
                    let msg = prewarm_and_build_startup_capsule(
                        svc,
                        &transcript_brief,
                        cwd.as_deref(),
                        ws_root.as_deref(),
                        Some(&sess_key),
                        channel,
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

                // 2. 1-Strike Large-Read Symbol-First Gate (`>=350L` code file or wide `>=350L` slice with `>=4` non-namespace symbols)
                let lines = (entry.line_count as usize).max(1);
                let threshold = large_read_threshold();
                let requested_span = match (req_start, req_end) {
                    (Some(s), Some(e)) => {
                        let start = s.max(1);
                        let end = e.min(lines);
                        if end >= start {
                            end - start + 1
                        } else {
                            0
                        }
                    }
                    (Some(s), None) => lines.saturating_sub(s.saturating_sub(1)),
                    (None, Some(e)) => e.min(lines),
                    (None, None) => lines,
                };
                if threshold > 0
                    && requested_span >= threshold
                    && is_code_source_ext(&canon)
                    && (entry.line_count as usize) >= threshold
                {
                    let non_ns_syms = entry
                        .symbols
                        .iter()
                        .filter(|sym| sym.kind != SymbolKind::Namespace)
                        .count();
                    if non_ns_syms >= 4
                        && !svc.store.check_and_mark_large_read_strike(
                            &sess_key,
                            entry.path_id,
                            entry.content_hash64,
                        )
                    {
                        let outline = RamStore::format_outline_compact(&entry, 24);
                        let mut non_ns_names = entry
                            .symbols
                            .iter()
                            .filter(|sym| sym.kind != SymbolKind::Namespace)
                            .map(|sym| sym.name.as_ref());
                        let sample_sym1 = non_ns_names.next().unwrap_or("Sym1");
                        let sample_sym2 = non_ns_names.next().unwrap_or("Sym2");
                        let cmd_hint = if svc.store.is_worker_session(&sess_key) {
                            format!(
                                "Batch symbols in one call via CLI `ctx sym \"{}#{}\" \"{}#{}\"` or `ctx impact \"{}#{}\"` (or a targeted `<{}L` `read_file` slice)",
                                entry.rel_path,
                                sample_sym1,
                                entry.rel_path,
                                sample_sym2,
                                entry.rel_path,
                                sample_sym1,
                                threshold
                            )
                        } else {
                            format!(
                                "Batch symbols via `mcp_agent_ctx_ctx_symbols({{\"requests\": [\"{}#{}\", \"{}#{}\"]}})` or `mcp_agent_ctx_ctx_impact({{\"targets\": [\"{}#{}\"]}})` (or a targeted `<{}L` `read_file` slice)",
                                entry.rel_path,
                                sample_sym1,
                                entry.rel_path,
                                sample_sym2,
                                entry.rel_path,
                                sample_sym1,
                                threshold
                            )
                        };
                        let shared_key = shared_repo_key(&root);
                        let memos = svc.broker.fresh_memos_for_file(
                            &shared_key,
                            &root,
                            &entry.rel_path,
                            &svc.store,
                            3,
                        );
                        let mut memo_block = String::new();
                        if !memos.is_empty() {
                            memo_block.push_str("\nMemos:");
                            for (topic, summary) in memos {
                                memo_block.push_str("\n- [untrusted memo] ");
                                memo_block.push_str(&topic);
                                memo_block.push_str(": ");
                                memo_block.push_str(&summary);
                            }
                        }
                        let reason = format!(
                            "[RAM-Ctx] Large code file `{}` ({}L, {} symbols). {}. Outline: {}{} (1-strike gate: re-run exact read_file if full text is needed.)",
                            entry.rel_path,
                            entry.line_count,
                            non_ns_syms,
                            cmd_hint,
                            outline,
                            memo_block,
                        );
                        return Json::obj(vec![
                            ("decision", Json::Str("deny".to_string())),
                            ("reason", Json::Str(reason)),
                        ]);
                    }
                }

                // 3. Auto-widen small top-of-file pagination chunks on <=300L & <=16KB workspace files
                let size_b = entry.size_bytes;
                if lines <= AGY_WIDEN_MAX_LINES && size_b <= AGY_WIDEN_MAX_BYTES {
                    if let (Some(1), Some(e)) = (req_start, req_end) {
                        if e < lines {
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
                if detect_multi_ctx_chain(cmd).is_some() {
                    let strike_key = format!(
                        "agy:{}:MultiCtxChain:{:016x}",
                        conv_id,
                        fast_hash64(cmd.trim().as_bytes())
                    );
                    if !svc.store.check_and_mark_dedup(&strike_key) {
                        return Json::obj(vec![
                            ("decision", Json::Str("deny".to_string())),
                            (
                                "reason",
                                Json::Str(
                                    "[RAM-Ctx] Avoid chaining multiple heavy `ctx` commands (`&&` / `;` / newlines) in one `run_command` — combined output overflows Antigravity's 10 KiB inline cap into `output.txt`. Issue independent `ctx` calls as parallel `run_command` tool calls instead (repeat this exact command once if strictly required)."
                                        .to_string(),
                                ),
                            ),
                        ]);
                    }
                }
                let is_worker = svc.store.is_worker_session(&sess_key);
                if let Some(broad_roots) = detect_broad_source_find(svc, cmd, cwd.as_deref()) {
                    let strike_key = format!(
                        "agy:{}:BroadFind:{:016x}",
                        conv_id,
                        fast_hash64(cmd.as_bytes())
                    );
                    if !svc.store.check_and_mark_dedup(&strike_key) {
                        let reason = if is_worker {
                            let cli_roots: Vec<&str> =
                                broad_roots.iter().take(6).map(String::as_str).collect();
                            let first_root = cli_roots.first().copied().unwrap_or(".");
                            format!(
                                "[RAM-Ctx] Broad `find` over >40 source files truncates output and wastes a turn. Query the in-RAM index directly via CLI `ctx inspect {}` or `ctx search -q \"{}:<pattern>\"`. (Repeat this exact `find` once if raw filesystem paths are strictly required.)",
                                cli_roots.join(" "),
                                first_root,
                            )
                        } else {
                            let paths_json: Vec<String> = broad_roots
                                .iter()
                                .take(6)
                                .map(|r| format!("\"{}\"", r))
                                .collect();
                            format!(
                                "[RAM-Ctx] Broad `find` over >40 source files truncates >10KB output into `output.txt` and wastes a turn. Query the in-RAM index directly in 1 step via `mcp_agent_ctx_ctx_inspect({{\"paths\": [{}], \"max_files\": 80}})` / `mcp_agent_ctx_ctx_search({{\"query\": \"...\", \"roots\": [{}]}})` (or `call_mcp_tool(ServerName=\"agent_ctx\", ToolName=\"ctx_inspect\", Arguments={{\"paths\": [{}], \"max_files\": 80}})`). (Repeat this exact `find` once if raw filesystem paths are strictly required.)",
                                paths_json.join(", "),
                                paths_json.join(", "),
                                paths_json.join(", ")
                            )
                        };
                        return Json::obj(vec![
                            ("decision", Json::Str("deny".to_string())),
                            ("reason", Json::Str(reason)),
                        ]);
                    }
                }
                if let Some(reason) =
                    workspace_grep_redirect_reason(svc, "agy", &sess_key, cmd, cwd.as_deref())
                {
                    return Json::obj(vec![
                        ("decision", Json::Str("deny".to_string())),
                        ("reason", Json::Str(reason)),
                    ]);
                }
                if let Some(hit) = detect_shell_file_slicing(svc, cmd, cwd.as_deref()) {
                    let outline = svc
                        .store
                        .get_outline_entry(&hit.target_path, Some(&hit.ws_root))
                        .map(|e| RamStore::format_outline_compact(&e, 10))
                        .unwrap_or_default();
                    let rel = display_workspace_path(&hit.target_path, Some(&hit.ws_root));
                    let reason = if is_worker {
                        format!(
                            "[RAM-Ctx] Avoid shell file-slicing (`cat`/`sed`/`head`/`nl`) on `{rel}`. Use CLI `ctx sym \"{rel}#<Symbol>\"`, `ctx read \"{rel}:<start>-<end>\"`, or `read_file`. Cached outline: {outline}"
                        )
                    } else {
                        format!(
                            "[RAM-Ctx] Avoid shell file-slicing (`cat`/`sed`/`head`/`nl`) on `{rel}`. Use `mcp_agent_ctx_ctx_symbols` (`{rel}#<Symbol>`) or `read_file` (with `StartLine`/`EndLine` for >=350L files). Cached outline: {outline}"
                        )
                    };
                    return Json::obj(vec![
                        ("decision", Json::Str("deny".to_string())),
                        ("reason", Json::Str(reason)),
                    ]);
                }
                if let Some(reason) =
                    workspace_git_redirect_reason(svc, "agy", &sess_key, cmd, cwd.as_deref())
                {
                    return Json::obj(vec![
                        ("decision", Json::Str("deny".to_string())),
                        ("reason", Json::Str(reason)),
                    ]);
                }

                // Safe CLI session injection strictly AFTER all deny guards (NEVER returns "allow").
                #[cfg(unix)]
                if is_valid_cli_conv_id(conv_id) && command_invokes_ctx(cmd) {
                    if let Some(context) = host_context("agy", payload, ws_root.as_deref()) {
                        if let Ok(tok) = svc
                            .broker
                            .capsules
                            .issue_cli_lease(sess_key.clone(), context.workspace)
                        {
                            let rt_export = std::env::var("AGENT_CTX_RUNTIME_DIR")
                                .ok()
                                .map(|s| s.trim().to_string())
                                .filter(|s| {
                                    !s.is_empty()
                                        && !s.contains("..")
                                        && s.bytes().all(|b| {
                                            b.is_ascii_alphanumeric()
                                                || matches!(b, b'/' | b'.' | b'_' | b'-' | b':')
                                        })
                                });
                            let updated_cmd = if let Some(rt_dir) = rt_export {
                                format!(
                                    "export AGENT_CTX_SESSION={} AGENT_CTX_CLI_TOKEN={} AGENT_CTX_RUNTIME_DIR={}; {}",
                                    sess_key, tok, rt_dir, cmd
                                )
                            } else {
                                format!(
                                    "export AGENT_CTX_SESSION={} AGENT_CTX_CLI_TOKEN={}; {}",
                                    sess_key, tok, cmd
                                )
                            };
                            let new_args =
                                replace_field(args, "CommandLine", Json::Str(updated_cmd));
                            return Json::obj(vec![
                                ("decision", Json::Str("ask".to_string())),
                                ("overwrite", new_args),
                            ]);
                        }
                    }
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
            let mut recorded_paths: Vec<PathBuf> = Vec::new();
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
                    if !is_internal_ide_path(&p) && !recorded_paths.contains(&p) {
                        recorded_paths.push(p.clone());
                        record_native_edit_change(
                            svc,
                            &p,
                            cwd.as_deref(),
                            ws_root.as_deref(),
                            &sess_key,
                        );
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::MemoFileLink;
    use crate::hooks::detect_workspace_readonly_git;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ctx-agy-{tag}-{}-{}",
            std::process::id(),
            now_ms_u64()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pre_tool_payload(conv_id: &str, cwd: &Path, call_id: &str, name: &str, args: Json) -> Json {
        Json::obj(vec![
            ("hookEventName", Json::Str("PreToolUse".into())),
            ("conversationId", Json::Str(conv_id.into())),
            ("cwd", Json::Str(cwd.to_string_lossy().into_owned())),
            (
                "toolCall",
                Json::obj(vec![
                    ("id", Json::Str(call_id.into())),
                    ("name", Json::Str(name.into())),
                    ("args", args),
                ]),
            ),
        ])
    }

    #[test]
    fn command_invokes_ctx_tokenizer_respects_quotes_and_run_command_injects_ask_overwrite() {
        assert!(command_invokes_ctx("ctx search -q 'Mod:foo'"));
        assert!(command_invokes_ctx("/home/u/.local/bin/ctx sym 'Mod#Sym'"));
        assert!(command_invokes_ctx("FOO=1 BAR=\"a b\" ctx status"));
        assert!(command_invokes_ctx("cd sub && ctx memo list"));
        assert!(command_invokes_ctx("echo ok; ctx git diff"));
        assert!(command_invokes_ctx("out=$(ctx status)"));
        assert!(!command_invokes_ctx("git commit -m \"a; ctx b\""));
        assert!(!command_invokes_ctx("echo 'foo && ctx bar'"));
        assert!(!command_invokes_ctx("python3 run.py ctx"));
        assert!(!command_invokes_ctx("export AGENT_CTX_SESSION=agy:1; ctx status"));

        #[cfg(unix)]
        {
            let dir = temp_dir("cli-inject");
            let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
            svc.allowlist.register_hint(&dir, true).unwrap();

            let req = pre_tool_payload(
                "worker-cli-1",
                &dir,
                "call-ctx-1",
                "run_command",
                Json::obj(vec![
                    ("CommandLine", Json::Str("ctx search -q 'Mod:foo'".into())),
                    ("WaitMsBeforeAsync", Json::Int(5000)),
                    ("toolSummary", Json::Str("Search module".into())),
                ]),
            );
            let reply = handle_agy(&svc, &req);
            assert_eq!(reply.get_str("decision"), Some("ask"));
            let ow = reply.get("overwrite").expect("must overwrite CommandLine");
            assert_eq!(ow.get_i64("WaitMsBeforeAsync"), Some(5000));
            assert_eq!(ow.get_str("toolSummary"), Some("Search module"));
            let new_cmd = ow.get_str("CommandLine").unwrap();
            assert!(
                new_cmd.starts_with("export AGENT_CTX_SESSION=agy:worker-cli-1 AGENT_CTX_CLI_TOKEN="),
                "{new_cmd}"
            );
            assert!(new_cmd.ends_with("; ctx search -q 'Mod:foo'"), "{new_cmd}");

            // Quoted commit message containing `; ctx ` MUST NOT be rewritten.
            let quoted = pre_tool_payload(
                "worker-cli-1",
                &dir,
                "call-git-commit",
                "run_command",
                Json::obj(vec![(
                    "CommandLine",
                    Json::Str("git commit -m \"a; ctx b\"".into()),
                )]),
            );
            let q_reply = handle_agy(&svc, &quoted);
            assert_eq!(q_reply.get_str("decision"), Some("allow"));
            assert!(q_reply.get("overwrite").is_none());

            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn large_read_gate_fires_once_with_untrusted_memo_and_skips_docs_and_few_symbols() {
        let dir = temp_dir("large-read");
        let code_file = dir.join("big_engine.rs");
        let mut src = String::new();
        for i in 0..6 {
            src.push_str(&format!("pub fn func_{i}(x: i32) -> i32 {{\n"));
            for j in 0..60 {
                src.push_str(&format!("    let v_{j} = x + {j};\n"));
            }
            src.push_str("    x\n}\n\n");
        }
        fs::write(&code_file, &src).unwrap();

        let doc_file = dir.join("big_doc.md");
        let md = (1..=400)
            .map(|i| format!("## Heading {i}\nParagraph line {i}\n"))
            .collect::<String>();
        fs::write(&doc_file, &md).unwrap();

        let few_sym_file = dir.join("few_syms.rs");
        let mut few = String::from("pub fn only_one() {\n");
        for i in 0..380 {
            few.push_str(&format!("    let _x_{i} = {i};\n"));
        }
        few.push_str("}\n");
        fs::write(&few_sym_file, &few).unwrap();

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        let root = svc.allowlist.register_hint(&dir, true).unwrap();
        let canon_code = fs::canonicalize(&code_file).unwrap();
        let hash = svc.store.current_file_hash64(&canon_code, Some(&root));
        let long_summary = format!("Important invariant: {}", "A".repeat(260));
        let shared_key = shared_repo_key(&root);
        svc.broker
            .put_memo(
                &shared_key,
                "engine-rule",
                &long_summary,
                Some("finding"),
                Some("scout"),
                vec![MemoFileLink {
                    abs_path: canon_code.clone(),
                    rel_path: "big_engine.rs".into(),
                    hash64_at_put: hash,
                }],
            )
            .unwrap();
        // Secret memos are refused and never surfaced.
        assert!(svc
            .broker
            .put_memo(
                &shared_key,
                "secret-leak",
                "token ghp_1234567890abcdefghij1234",
                Some("finding"),
                Some("scout"),
                vec![MemoFileLink {
                    abs_path: canon_code,
                    rel_path: "big_engine.rs".into(),
                    hash64_at_put: hash,
                }],
            )
            .is_err());

        // Strike 1 on >=350L code file with >=4 symbols -> deny with outline + clipped [untrusted memo]
        let req1 = pre_tool_payload(
            "coord-lr-1",
            &dir,
            "call-lr-1",
            "read_file",
            Json::obj(vec![(
                "Path",
                Json::Str(code_file.to_string_lossy().into_owned()),
            )]),
        );
        let r1 = handle_agy(&svc, &req1);
        assert_eq!(r1.get_str("decision"), Some("deny"), "{r1:?}");
        let reason = r1.get_str("reason").unwrap();
        assert!(reason.contains("mcp_agent_ctx_ctx_symbols"), "{reason}");
        assert!(reason.contains("func_0"), "{reason}");
        assert!(reason.contains("[untrusted memo] engine-rule:"), "{reason}");
        assert!(
            !reason.contains(&"A".repeat(220)),
            "memo summary must be clipped <= 200B: {reason}"
        );

        // Strike 2 with a NEW call_id passes cleanly (stored in SessionState, not 15s dedup ring)
        let req2 = pre_tool_payload(
            "coord-lr-1",
            &dir,
            "call-lr-2",
            "read_file",
            Json::obj(vec![(
                "Path",
                Json::Str(code_file.to_string_lossy().into_owned()),
            )]),
        );
        let r2 = handle_agy(&svc, &req2);
        assert_eq!(r2.get_str("decision"), Some("allow"), "{r2:?}");

        // Worker session receives CLI-first batched `ctx sym` without MCP noise
        svc.store.mark_worker_session("agy:worker-lr-1");
        let req_w = pre_tool_payload(
            "worker-lr-1",
            &dir,
            "call-lr-w1",
            "read_file",
            Json::obj(vec![(
                "Path",
                Json::Str(code_file.to_string_lossy().into_owned()),
            )]),
        );
        let rw = handle_agy(&svc, &req_w);
        assert_eq!(rw.get_str("decision"), Some("deny"));
        let w_reason = rw.get_str("reason").unwrap();
        assert!(
            w_reason.contains("ctx sym \"big_engine.rs#func_0\" \"big_engine.rs#func_1\"")
                && w_reason.contains("<350L"),
            "{w_reason}"
        );
        assert!(!w_reason.contains("mcp_agent_ctx_"), "{w_reason}");
        assert!(
            reason.contains("\"big_engine.rs#func_0\", \"big_engine.rs#func_1\"")
                && reason.contains("<350L"),
            "{reason}"
        );

        // Wide code slices (`requested_span >= 350`) trigger Strike 1 and pass on Strike 2.
        for (sess, start_opt, end_opt) in [
            ("wide-1", Some(1i64), Some(350i64)),
            ("wide-2", Some(1i64), Some(500i64)),
            ("wide-3", Some(10i64), None),
            ("wide-4", None, Some(355i64)),
        ] {
            let mut fields = vec![("Path", Json::Str(code_file.to_string_lossy().into_owned()))];
            if let Some(s) = start_opt {
                fields.push(("StartLine", Json::Int(s)));
            }
            if let Some(e) = end_opt {
                fields.push(("EndLine", Json::Int(e)));
            }
            let p1 = pre_tool_payload(sess, &dir, "call-w1", "read_file", Json::obj(fields.clone()));
            let d1 = handle_agy(&svc, &p1);
            assert_eq!(
                d1.get_str("decision"),
                Some("deny"),
                "wide slice ({start_opt:?}, {end_opt:?}) must trigger Strike 1: {d1:?}"
            );
            let p2 = pre_tool_payload(sess, &dir, "call-w2", "read_file", Json::obj(fields));
            let d2 = handle_agy(&svc, &p2);
            assert_eq!(
                d2.get_str("decision"),
                Some("allow"),
                "wide slice ({start_opt:?}, {end_opt:?}) must pass Strike 2: {d2:?}"
            );
        }

        // Targeted slices (`requested_span < 350`) remain 100% frictionless on Strike 1.
        for (sess, start_opt, end_opt) in [
            ("narrow-1", Some(1i64), Some(349i64)),
            ("narrow-2", Some(50i64), Some(250i64)),
            ("narrow-3", Some(100i64), None),
            ("narrow-4", None, Some(349i64)),
            ("narrow-5", Some(300i64), Some(999i64)),
        ] {
            let mut fields = vec![("Path", Json::Str(code_file.to_string_lossy().into_owned()))];
            if let Some(s) = start_opt {
                fields.push(("StartLine", Json::Int(s)));
            }
            if let Some(e) = end_opt {
                fields.push(("EndLine", Json::Int(e)));
            }
            let p = pre_tool_payload(sess, &dir, "call-n1", "read_file", Json::obj(fields));
            let d = handle_agy(&svc, &p);
            assert_eq!(
                d.get_str("decision"),
                Some("allow"),
                "targeted slice ({start_opt:?}, {end_opt:?}) must allow on Strike 1: {d:?}"
            );
        }

        // .md files and <4 symbol code files are NEVER blocked by Large-Read Gate
        for skip_path in [&doc_file, &few_sym_file] {
            let req_skip = pre_tool_payload(
                "coord-lr-skip",
                &dir,
                "call-skip",
                "read_file",
                Json::obj(vec![(
                    "Path",
                    Json::Str(skip_path.to_string_lossy().into_owned()),
                )]),
            );
            let rs = handle_agy(&svc, &req_skip);
            assert_eq!(
                rs.get_str("decision"),
                Some("allow"),
                "must skip {}: {rs:?}",
                skip_path.display()
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_git_redirect_is_one_strike_and_passes_complex_flags() {
        let dir = temp_dir("git-redirect");
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        svc.allowlist.register_hint(&dir, true).unwrap();

        // Passthrough commands outside strict allowlist
        for pass_cmd in [
            "git -C /other status",
            "git diff a..b",
            "git log --format=%H",
            "git status --porcelain",
            "git status -s",
            "git show HEAD:src/lib.rs",
            "git diff -U5",
            "git diff --name-only",
            "git rev-parse HEAD",
            "git branch",
            "git status | head -n 5",
        ] {
            assert!(
                detect_workspace_readonly_git(&svc, pass_cmd, Some(&dir)).is_none(),
                "must pass through `{pass_cmd}`"
            );
        }

        // Allowlisted commands redirect once, then allow on Strike 2
        for (idx, cmd) in ["git status", "git diff --stat"].iter().enumerate() {
            let p1 = pre_tool_payload(
                "coord-git-1",
                &dir,
                &format!("call-g1-{idx}"),
                "run_command",
                Json::obj(vec![("CommandLine", Json::Str((*cmd).into()))]),
            );
            let r1 = handle_agy(&svc, &p1);
            assert_eq!(r1.get_str("decision"), Some("deny"), "1st `{cmd}`: {r1:?}");
            assert!(r1.get_str("reason").unwrap().contains("ctx_git"));

            let p2 = pre_tool_payload(
                "coord-git-1",
                &dir,
                &format!("call-g2-{idx}"),
                "run_command",
                Json::obj(vec![("CommandLine", Json::Str((*cmd).into()))]),
            );
            let r2 = handle_agy(&svc, &p2);
            assert_eq!(r2.get_str("decision"), Some("allow"), "2nd `{cmd}`: {r2:?}");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_tool_use_records_change_feed_safely_and_skips_brain_and_secrets() {
        let dir = temp_dir("post-changes");
        let src = dir.join("module.rs");
        fs::write(&src, "pub fn alpha_fn() -> i32 { 1 }\n").unwrap();
        let env_file = dir.join(".env");
        fs::write(&env_file, "API_KEY=supersecret\n").unwrap();
        let brain_file = dir.join(".gemini/antigravity/brain/conv/note.md");
        fs::create_dir_all(brain_file.parent().unwrap()).unwrap();
        fs::write(&brain_file, "# scratch\n").unwrap();

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        let root = svc.allowlist.register_hint(&dir, true).unwrap();
        let shared_key = shared_repo_key(&root);

        let post = |call_id: &str, name: &str, args: Json| {
            let payload = Json::obj(vec![
                ("hookEventName", Json::Str("PostToolUse".into())),
                ("conversationId", Json::Str("worker-edit-1".into())),
                ("cwd", Json::Str(dir.to_string_lossy().into_owned())),
                (
                    "toolCall",
                    Json::obj(vec![
                        ("id", Json::Str(call_id.into())),
                        ("name", Json::Str(name.into())),
                        ("args", args),
                    ]),
                ),
            ]);
            handle_agy(&svc, &payload);
        };

        // Normal workspace file edit -> recorded with symbol
        post(
            "p1",
            "edit_file",
            Json::obj(vec![(
                "Path",
                Json::Str(src.to_string_lossy().into_owned()),
            )]),
        );
        // Secret file + brain artifact -> MUST NOT be recorded
        post(
            "p2",
            "write_file",
            Json::obj(vec![(
                "Path",
                Json::Str(env_file.to_string_lossy().into_owned()),
            )]),
        );
        post(
            "p3",
            "write_file",
            Json::obj(vec![(
                "Path",
                Json::Str(brain_file.to_string_lossy().into_owned()),
            )]),
        );
        // Deleted workspace file (no longer on disk) -> recorded safely with empty symbols
        let deleted = dir.join("removed.rs");
        post(
            "p4",
            "delete_file",
            Json::obj(vec![(
                "Path",
                Json::Str(deleted.to_string_lossy().into_owned()),
            )]),
        );
        // Deleted secret or traversal outside workspace -> MUST NOT be recorded
        post(
            "p5",
            "delete_file",
            Json::obj(vec![(
                "Path",
                Json::Str(dir.join(".env.local").to_string_lossy().into_owned()),
            )]),
        );
        post(
            "p6",
            "delete_file",
            Json::obj(vec![("Path", Json::Str("../../etc/passwd".into()))]),
        );

        let (_head, events) = svc.broker.changes.changes_since(&shared_key, 0, 16);
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0].rel_path, "module.rs");
        assert_eq!(events[0].actor, "agy:worker-edit-1");
        assert!(events[0].changed_symbols.contains(&"@alpha_fn".to_string()));
        assert_eq!(events[1].rel_path, "removed.rs");
        assert!(events[1].changed_symbols.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn forked_worker_transcript_skips_duplicate_startup_banner_and_marks_worker() {
        let dir = temp_dir("fork-kv");
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        svc.allowlist.register_hint(&dir, true).unwrap();

        // Case 1: transcript already contains `[RAM-Ctx Startup]`
        let t1 = dir.join("t1.jsonl");
        fs::write(
            &t1,
            concat!(
                "{\"type\":\"SYSTEM_MESSAGE\",\"source\":\"SYSTEM_SDK\",\"content\":\"[RAM-Ctx Startup] existing\"}\n",
                "{\"type\":\"SYSTEM_MESSAGE\",\"source\":\"SYSTEM\",\"content\":\"[Message] sender=coord content=[swarm] You have just started.\"}\n"
            ),
        )
        .unwrap();
        let ss1 = Json::obj(vec![
            ("hookEventName", Json::Str("SessionStart".into())),
            ("conversationId", Json::Str("forked-w1".into())),
            ("cwd", Json::Str(dir.to_string_lossy().into_owned())),
            ("transcriptPath", Json::Str(t1.to_string_lossy().into_owned())),
        ]);
        let r1 = handle_agy(&svc, &ss1);
        assert!(r1.get("injectSteps").is_none(), "must not re-inject: {r1:?}");
        assert!(svc.store.is_worker_session("agy:forked-w1"));
        assert!(svc.store.has_startup_settled("agy:forked-w1"));

        // Case 2: transcript already has `PLANNER_RESPONSE` from `review_seed`
        let t2 = dir.join("t2.jsonl");
        fs::write(
            &t2,
            concat!(
                "{\"type\":\"SYSTEM_MESSAGE\",\"source\":\"SYSTEM\",\"content\":\"[Message] sender=coord content=[swarm] You have just started.\"}\n",
                "{\"type\":\"PLANNER_RESPONSE\",\"content\":\"Loaded diff cleanly.\"}\n"
            ),
        )
        .unwrap();
        let ss2 = Json::obj(vec![
            ("hookEventName", Json::Str("PreInvocation".into())),
            ("conversationId", Json::Str("forked-w2".into())),
            ("cwd", Json::Str(dir.to_string_lossy().into_owned())),
            ("transcriptPath", Json::Str(t2.to_string_lossy().into_owned())),
        ]);
        let r2 = handle_agy(&svc, &ss2);
        assert!(r2.get("injectSteps").is_none(), "must not re-inject: {r2:?}");
        assert!(svc.store.is_worker_session("agy:forked-w2"));
        assert!(svc.store.has_startup_settled("agy:forked-w2"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_ctx_chain_gate_is_one_strike_runs_first_and_allows_lightweight_chains() {
        // Triggering chains: 2+ heavy ctx OR 1+ heavy ctx + 1+ separate raw inspect
        assert_eq!(detect_multi_ctx_chain("ctx inspect A && ctx inspect B"), Some((2, 0)));
        assert_eq!(
            detect_multi_ctx_chain("ctx sym 'a.rs#f'\nctx read b.rs:1-40"),
            Some((2, 0))
        );
        assert_eq!(
            detect_multi_ctx_chain("ctx search -q 'foo'; ctx outline src/a.rs"),
            Some((2, 0))
        );
        assert_eq!(
            detect_multi_ctx_chain("ctx inspect \\\n  src/a && ctx impact src/b.rs#fn_a"),
            Some((2, 0))
        );
        assert_eq!(
            detect_multi_ctx_chain("ctx memo changes\ngit diff a.rs"),
            Some((1, 1))
        );
        assert_eq!(
            detect_multi_ctx_chain("ctx memo && find src/ -type f"),
            Some((1, 1))
        );
        assert_eq!(
            detect_multi_ctx_chain("ctx memo pack-get p1 && rg foo src/"),
            Some((1, 1))
        );

        // Non-triggering commands (false-positive guards)
        for ok_cmd in [
            "ctx inspect src/",
            "ctx search -q 'foo' | grep bar",
            "ctx inspect src/ | head -n 40",
            "ctx shutdown && sleep 0.3",
            "ctx status && ctx doctor",
            "ctx memo put -t a -s b && ctx memo pack -t p src/",
            "ctx memo put -t a -s b && ctx inspect src/",
            "ctx memo --help && ctx inspect src/",
            "ctx edit --help && ctx diag -- cargo test",
            "cmake -B build && ninja -C build && ctest --test-dir build",
            "echo \"ctx inspect A && ctx inspect B\"",
            "git commit -m \"ctx inspect A; ctx search B\"",
            "echo '=== DIFF ==='\ngit diff src/a.rs",
        ] {
            assert!(
                detect_multi_ctx_chain(ok_cmd).is_none(),
                "must NOT trigger MultiCtxChainGate for `{ok_cmd}`"
            );
        }

        let dir = temp_dir("multi-ctx-chain");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/a.rs"), "pub fn a() {}\n").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        svc.allowlist.register_hint(&dir, true).unwrap();

        // Strike 1 denies `ctx inspect A && ctx inspect B`, Strike 2 passes cleanly.
        let chain_cmd = "ctx inspect src/a.rs && ctx read src/a.rs:1-5";
        let p1 = pre_tool_payload(
            "worker-chain-1",
            &dir,
            "call-c1",
            "run_command",
            Json::obj(vec![("CommandLine", Json::Str(chain_cmd.into()))]),
        );
        let r1 = handle_agy(&svc, &p1);
        assert_eq!(r1.get_str("decision"), Some("deny"), "{r1:?}");
        assert!(
            r1.get_str("reason")
                .unwrap()
                .contains("10 KiB inline cap"),
            "{r1:?}"
        );

        let p2 = pre_tool_payload(
            "worker-chain-1",
            &dir,
            "call-c2",
            "run_command",
            Json::obj(vec![("CommandLine", Json::Str(chain_cmd.into()))]),
        );
        let r2 = handle_agy(&svc, &p2);
        assert_ne!(r2.get_str("decision"), Some("deny"), "Strike 2 must not deny: {r2:?}");

        // Ordering check: `ctx memo changes\ngit diff src/a.rs` hits MultiCtxChainGate BEFORE git redirect / CLI token injection.
        let mixed_cmd = "ctx memo changes\ngit diff src/a.rs";
        let pm = pre_tool_payload(
            "worker-chain-2",
            &dir,
            "call-m1",
            "run_command",
            Json::obj(vec![("CommandLine", Json::Str(mixed_cmd.into()))]),
        );
        let rm = handle_agy(&svc, &pm);
        assert_eq!(rm.get_str("decision"), Some("deny"), "{rm:?}");
        let m_reason = rm.get_str("reason").unwrap();
        assert!(m_reason.contains("Avoid chaining multiple heavy `ctx` commands"), "{m_reason}");
        assert!(rm.get("overwrite").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn broad_source_find_handles_multiline_echo_and_xargs_wc_while_skipping_safe_variants() {
        let dir = temp_dir("broad-find");
        let src = dir.join("src");
        fs::create_dir_all(&src).unwrap();
        for i in 0..45 {
            fs::write(src.join(format!("mod_{i:02}.rs")), format!("pub fn f_{i}() {{}}\n"))
                .unwrap();
        }
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snap.bin"));
        svc.allowlist.register_hint(&dir, true).unwrap();

        // Multiline `echo ...\nfind src/ -type f` and `find ... | xargs -0 wc -l` trigger BroadFind.
        for broad_cmd in [
            "echo \"=== FILES ===\"\nfind src/ -type f",
            "echo \"=== COUNT ===\" && find src/ -type f -print0 | xargs -0 wc -l",
            "find src/ -type f | sort",
            "find src/ -type f | xargs -n 50 wc -l",
        ] {
            let roots = detect_broad_source_find(&svc, broad_cmd, Some(&dir));
            assert_eq!(
                roots.as_deref(),
                Some(&["src".to_string()][..]),
                "must detect broad find for `{broad_cmd}`"
            );
        }

        // Shallow, mutating, redirected, or non-wc xargs commands pass cleanly.
        for ok_cmd in [
            "find src/ -maxdepth 1 -type f",
            "find src/ -maxdepth 2 -type f",
            "find src/ -type f -delete",
            "find src/ -type f -exec wc -l {} +",
            "find src/ -type f | xargs rm -f",
            "find src/ -type f > list.txt",
            "find src/ -type f | head -n 10",
            "cd /tmp && find . -type f",
        ] {
            assert!(
                detect_broad_source_find(&svc, ok_cmd, Some(&dir)).is_none(),
                "must NOT flag `{ok_cmd}`"
            );
        }

        // End-to-end 1-Strike via handle_agy on multiline `echo ...\nfind`.
        let cmd = "echo \"=== FILES ===\"\nfind src/ -type f";
        let f1 = pre_tool_payload(
            "worker-find-1",
            &dir,
            "call-f1",
            "run_command",
            Json::obj(vec![("CommandLine", Json::Str(cmd.into()))]),
        );
        let rf1 = handle_agy(&svc, &f1);
        assert_eq!(rf1.get_str("decision"), Some("deny"), "{rf1:?}");
        assert!(rf1.get_str("reason").unwrap().contains("Broad `find`"));

        let f2 = pre_tool_payload(
            "worker-find-1",
            &dir,
            "call-f2",
            "run_command",
            Json::obj(vec![("CommandLine", Json::Str(cmd.into()))]),
        );
        let rf2 = handle_agy(&svc, &f2);
        assert_eq!(rf2.get_str("decision"), Some("allow"), "{rf2:?}");

        let _ = fs::remove_dir_all(&dir);
    }
}
