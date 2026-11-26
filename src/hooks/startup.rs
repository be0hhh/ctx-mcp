//! Startup classification, transcript/inbox inspection, and pre-warmed outline +
//! workspace memo capsule generation for subagent/worker launches.

use super::{
    is_internal_ide_path, AGY_LAZY_MCP_SIGNATURES, STARTUP_BUDGET_BYTES, SUBAGENT_STARTUP_DIGEST,
};
use crate::base::json::{self, Json};
use crate::base::security::is_sensitive_path;
use crate::broker::HostContext;
use crate::engine::walk_source_dir;
use crate::rpc::BrokerService;
use crate::store::{
    is_multimodal_or_binary_ext, norm_key_from_canon, resolve_input_path, MissingResolution,
    RamStore,
};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

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

pub(super) fn read_first_transcript_entries(path: &Path, max_lines: usize) -> Vec<Json> {
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

pub(super) enum AgyStartupKind {
    RootUser,
    IgnoreAux,
    Worker { brief: String },
    Undetermined,
}

pub(super) fn candidate_agy_messages_dirs(payload: &Json, conv_id: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut push_unique = |p: PathBuf| {
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    };
    if let Some(tp_str) = payload
        .get_str("transcriptPath")
        .filter(|s| !s.trim().is_empty())
    {
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

pub(super) fn bind_agy_inbound(svc: &BrokerService, payload: &Json, child: &HostContext) {
    for directory in candidate_agy_messages_dirs(payload, &child.session) {
        let Ok(files) = fs::read_dir(directory) else {
            continue;
        };
        let mut paths: Vec<_> = files
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .take(64)
            .collect();
        paths.sort();
        for path in paths {
            if !fs::metadata(&path).is_ok_and(|entry| entry.is_file() && entry.len() <= 96 * 1024) {
                continue;
            }
            let Some(message) = fs::read_to_string(path)
                .ok()
                .and_then(|raw| json::parse(&raw).ok())
            else {
                continue;
            };
            let (Some(sender), Some(brief)) =
                (message.get_str("sender"), message.get_str("content"))
            else {
                continue;
            };
            if message.get_str("recipient") != Some(&child.session)
                || sender == "system"
                || sender == child.session
            {
                continue;
            }
            if !brief.starts_with("[swarm] new board message") {
                svc.broker.capsules.bind_assignment(child, sender, brief);
                return;
            }
        }
    }
}

pub(super) fn bind_explicit_child_transcript(
    svc: &BrokerService,
    payload: &Json,
    child: &HostContext,
) {
    let Some(id) = child.agent.as_deref() else {
        return;
    };
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return;
    }
    let path = payload
        .get_str("agent_transcript_path")
        .map(PathBuf::from)
        .or_else(|| {
            let parent = Path::new(payload.get_str("transcript_path")?);
            Some(
                parent
                    .parent()?
                    .join(parent.file_stem()?)
                    .join("subagents")
                    .join(format!("agent-{id}.jsonl")),
            )
        });
    let Some(path) = path else {
        return;
    };
    if path.file_stem().and_then(|stem| stem.to_str()) != Some(&format!("agent-{id}")) {
        return;
    }
    let transcript = read_first_transcript_entries(&path, 16);
    if let Some(message) = transcript
        .iter()
        .find(|record| record.get_str("type") == Some("user"))
    {
        if let Some(content) = message.get("message").and_then(|value| value.get("content")) {
            let text = content.as_str().or_else(|| {
                let parts = content.as_arr()?;
                (parts.len() == 1)
                    .then(|| parts[0].get_str("text"))
                    .flatten()
            });
            if let Some(text) = text {
                svc.broker
                    .capsules
                    .bind_assignment(child, &child.session, text);
            }
        }
    }
}

pub(super) fn codex_launch_origin(payload: &Json, agent: &str) -> Option<(String, String)> {
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
    Some((
        spawn.get_str("parent_thread_id")?.into(),
        spawn.get_str("agent_path")?.into(),
    ))
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
            let low_hdr: String = content
                .chars()
                .take(500)
                .collect::<String>()
                .to_ascii_lowercase();
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

pub(super) fn classify_agy_startup(payload: &Json, conv_id: &str) -> AgyStartupKind {
    // 1. Check transcript entries if already flushed to disk
    if let Some(tp_str) = payload
        .get_str("transcriptPath")
        .filter(|s| !s.trim().is_empty())
    {
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

                    let low_hdr: String = combined
                        .chars()
                        .take(500)
                        .collect::<String>()
                        .to_ascii_lowercase();
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
        return AgyStartupKind::Worker {
            brief: last_input.to_string(),
        };
    }
    AgyStartupKind::Undetermined
}

fn has_known_source_ext(tok: &str) -> bool {
    let Some((_, ext)) = tok.rsplit_once('.') else {
        return false;
    };
    if ext.is_empty() || ext.len() > 10 || !ext.is_ascii() {
        return false;
    }
    let mut buf = [0u8; 10];
    for (i, b) in ext.bytes().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    let low = std::str::from_utf8(&buf[..ext.len()]).unwrap_or("");
    matches!(
        low,
        "h" | "hpp"
            | "ipp"
            | "hh"
            | "hxx"
            | "c"
            | "cc"
            | "cpp"
            | "cxx"
            | "inl"
            | "tpp"
            | "cu"
            | "cuh"
            | "ixx"
            | "cppm"
            | "rs"
            | "py"
            | "pyi"
            | "java"
            | "cs"
            | "go"
            | "ts"
            | "tsx"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "kt"
            | "kts"
            | "swift"
            | "zig"
            | "sh"
            | "bash"
            | "zsh"
            | "sql"
            | "proto"
            | "cmake"
            | "md"
            | "mdx"
            | "markdown"
            | "json"
            | "jsonc"
            | "toml"
            | "yml"
            | "yaml"
    )
}

pub(super) fn extract_candidate_paths_from_text(
    svc: &BrokerService,
    text: &str,
    cwd: Option<&Path>,
    ws_root: Option<&Path>,
) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for raw_tok in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '`' | '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';' | '{' | '}'
            )
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
        let looks_like_path =
            tok.contains('/') || tok.contains('\\') || has_known_source_ext(tok);
        if !looks_like_path
            || tok.starts_with("http://")
            || tok.starts_with("https://")
            || tok.starts_with("file://")
            || tok.starts_with("conversation://")
        {
            continue;
        }
        let p = resolve_input_path(tok, cwd);
        let target = if p.exists() {
            Some(p)
        } else if let Some(root) = ws_root {
            svc.store
                .find_workspace_dirs(tok, root, 1)
                .into_iter()
                .next()
                .or_else(|| match svc.store.resolve_missing_path(&p, root) {
                    MissingResolution::Unique(real) => Some(real),
                    _ => None,
                })
        } else {
            None
        };
        if let Some(real_p) = target {
            if !is_sensitive_path(&real_p)
                && !is_internal_ide_path(&real_p)
                && !found.contains(&real_p)
            {
                found.push(real_p);
                if found.len() >= 12 {
                    break;
                }
            }
        }
    }
    found
}

pub(super) fn prewarm_and_build_startup_capsule(
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
    msg.push_str(SUBAGENT_STARTUP_DIGEST);
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

pub(super) fn startup_reply(
    svc: &BrokerService,
    payload: &Json,
    cwd: Option<&Path>,
    root: Option<&Path>,
) -> Json {
    let brief = payload.get_str("prompt").unwrap_or_default();
    let context = prewarm_and_build_startup_capsule(svc, brief, cwd, root, false);
    Json::obj(vec![(
        "hookSpecificOutput",
        Json::obj(vec![
            ("hookEventName", Json::Str("SubagentStart".into())),
            ("additionalContext", Json::Str(context)),
        ]),
    )])
}
