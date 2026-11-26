//! Harness configuration planners & checkers for Antigravity, Codex, Claude Code,
//! and WSL->Windows Antigravity bridges (zero project-specific coupling).

pub(super) use super::toml_cfg::{
    check_codex_tool_config, plan_remove_codex_toml, upsert_codex_toml_mcp_and_hooks,
};

use super::plan::InstallPlan;
use crate::base::json::{self, Json, JsonKey};
use crate::mcp::expected_tool_names;
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};

const GLOBAL_BLOCK_BEGIN: &str = "<!-- BEGIN AGENT_CTX GLOBAL RULES -->";
const GLOBAL_BLOCK_END: &str = "<!-- END AGENT_CTX GLOBAL RULES -->";

const GLOBAL_RULES_SNIPPET: &str = "<!-- BEGIN AGENT_CTX GLOBAL RULES -->\n\
## In-RAM Context Broker (`ctx` / MCP `agent_ctx`)\n\
\n\
- In Antigravity, call eager `mcp_agent_ctx_*` tools directly (`ctx_search`, `ctx_inspect`, `ctx_read`, `ctx_symbols`); use `call_mcp_tool(ServerName=\"agent_ctx\", ...)` for lazy tools (`ctx_outline`, `ctx_impact`, `ctx_git`, `ctx_edit`, `ctx_memo`, `ctx_elf_audit`) without reading `mcp/agent_ctx/*.json` schema files:\n\
  - Parallel search (`1-6` queries in `q`, `8 KiB` cap; bare module stem matches all extensions; lowercase = smart-case; `a|b` alternation): `ctx_search` with `{\"q\": [\"ModOrDir:pattern\", ...]}` (CLI: `ctx search -q \"Mod:pat\"`).\n\
  - Directory/file triage (`<=80` files, exact line counts, `[>=600L]`/`[OVER 800L]`, `#include`, `[L_start-L_end]` symbols, `9 KB` inline default): `ctx_inspect` with `{\"paths\": [\"dir1\", \"dir2\"], \"max_files\": 80}` (CLI: `ctx inspect <paths...>`).\n\
  - Exact struct/function bodies: `ctx_symbols` with `{\"requests\": [\"ModOrPath#Symbol\"], \"compact\": true}` (CLI: `ctx sym \"Mod#Sym\" --compact`).\n\
  - Full files / slices: in Antigravity prefer parallel native `read_file` (`<=800L` / `46 KB` inline, zero MCP truncation) for full files, and `ctx_read` for `>800L` slices (`path:start-end`) or small batches (`<=9 KB`); in Codex/CLI batch full files in `ctx_read` / `ctx read` up to `1 MiB`.\n\
  - Impact & read-only Git: `ctx_impact` (`targets`) for callers/importers/tests; `ctx_git` (`diff` with optional `stat: true` | `status` with conflict-marker check | `log` | `show`) instead of chained `git diff | head` shell commands. When writing/creating scripts, use `ctx_edit` (`edits`/`renames`/`creates` + `verify_absent`).\n\
  - Shared context & findings board: `ctx_memo` (`list` | `put` | `get` | `changes` | Shared Context Packs `pack`/`pack_get`/`packs` for MD/JSON rules shared across subagents).\n\
  - Verbose CLI builds/tests/logs/JSON: wrap with `ctx diag -- <cmd>` to deduplicate compiler/test/syslog noise and compact large JSON.\n\
- Reuse `[RAM-Ctx Startup]` when provided. Finish directly from grouped search hits or compact symbols (`Mod#Sym`, `doc.md#Heading`, `cfg.json#a.b`) when sufficient; in Antigravity swarm workers without MCP use the `ctx` CLI directly. Never slice files in `100-400` line shell loops (`sed`/`head`/`nl`), run ad-hoc `python3 -c` file/conflict scans, or re-read unchanged files already in context.\n\
<!-- END AGENT_CTX GLOBAL RULES -->";

pub const AGY_CORE_EAGER_TOOLS: &[&str] = &[
    "ctx_search",
    "ctx_inspect",
    "ctx_read",
    "ctx_symbols",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EagerMode {
    Core,
    Search,
    All,
    None,
}

impl EagerMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "core" | "default" => Ok(Self::Core),
            "search" | "minimal" => Ok(Self::Search),
            "all" | "full" => Ok(Self::All),
            "none" | "lazy" | "off" => Ok(Self::None),
            other => Err(format!(
                "unknown --eager mode `{other}` (expected core, search, all, or none)"
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Search => "search",
            Self::All => "all",
            Self::None => "none",
        }
    }

    pub fn eager_tool_names(self) -> Vec<String> {
        match self {
            Self::Core => AGY_CORE_EAGER_TOOLS.iter().map(|&s| s.to_string()).collect(),
            Self::Search => vec!["ctx_search".to_string()],
            Self::All => expected_tool_names(),
            Self::None => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetSet {
    pub agy: bool,
    pub claude: bool,
    pub codex: bool,
}

impl TargetSet {
    pub const fn all() -> Self {
        Self { agy: true, claude: true, codex: true }
    }

    pub const fn agy_only() -> Self {
        Self { agy: true, claude: false, codex: false }
    }

    pub const fn is_all(self) -> bool {
        self.agy && self.claude && self.codex
    }

    pub const fn is_empty(self) -> bool {
        !self.agy && !self.claude && !self.codex
    }

    pub fn parse_csv(raw: &str) -> Result<Self, String> {
        let mut set = Self { agy: false, claude: false, codex: false };
        for part in raw.split(',') {
            match part.trim().to_ascii_lowercase().as_str() {
                "" => {}
                "all" => return Ok(Self::all()),
                "none" => return Ok(Self { agy: false, claude: false, codex: false }),
                "agy" | "antigravity" | "gemini" => set.agy = true,
                "claude" | "claude-code" | "claudecode" => set.claude = true,
                "codex" | "openai" => set.codex = true,
                other => {
                    return Err(format!(
                        "unknown target `{other}` (expected antigravity, claude, codex, or all)"
                    ));
                }
            }
        }
        Ok(set)
    }

    pub fn summary(self) -> String {
        let mut names = Vec::new();
        if self.agy { names.push("antigravity"); }
        if self.claude { names.push("claude"); }
        if self.codex { names.push("codex"); }
        if names.is_empty() { "none".to_string() } else { names.join(",") }
    }
}

fn upsert_marked_block(existing: &str, block: &str, begin: &str, end: &str) -> String {
    if let (Some(s), Some(e_pos)) = (existing.find(begin), existing.find(end)) {
        if e_pos >= s {
            let end_idx = e_pos + end.len();
            return format!("{}{}{}", &existing[..s], block, &existing[end_idx..]);
        }
    }
    let sep = if existing.is_empty() {
        ""
    } else if existing.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    format!("{}{}{}\n", existing, sep, block)
}

fn upsert_obj_field(fields: &mut Vec<(JsonKey, Json)>, key: impl Into<JsonKey>, val: Json) {
    let key = key.into();
    if let Some((_, v)) = fields.iter_mut().find(|(k, _)| k.as_ref() == key.as_ref()) {
        *v = val;
    } else {
        fields.push((key, val));
    }
}

fn remove_obj_field(fields: &mut Vec<(JsonKey, Json)>, key: &str) {
    fields.retain(|(k, _)| k.as_ref() != key);
}

fn build_agy_context_hook_cfg_cmd(cmd_str: String) -> Json {
    let hook_cmd = Json::obj(vec![
        ("type", Json::Str("command".to_string())),
        ("command", Json::Str(cmd_str)),
        ("timeout", Json::Int(5)),
    ]);
    Json::obj(vec![
        ("SessionStart", Json::Arr(vec![hook_cmd.clone()])),
        ("PreInvocation", Json::Arr(vec![hook_cmd.clone()])),
        (
            "PreToolUse",
            Json::Arr(vec![Json::obj(vec![
                (
                    "matcher",
                    Json::Str(
                        "^(read_file|view_file|run_command|call_mcp_tool|mcp_{1,2}agent_ctx_{1,2}ctx_(read|symbols|memo|capsule|impact|edit|git))$".to_string(),
                    ),
                ),
                ("hooks", Json::Arr(vec![hook_cmd.clone()])),
            ])]),
        ),
        (
            "PostToolUse",
            Json::Arr(vec![Json::obj(vec![
                (
                    "matcher",
                    Json::Str(
                        "^(read_file|view_file|edit_file|write_file|write_to_file|replace_file_content|multi_replace_file_content|create_file|delete_file|rename_file|run_command)$".to_string(),
                    ),
                ),
                ("hooks", Json::Arr(vec![hook_cmd])),
            ])]),
        ),
    ])
}

fn object_field(root: &Json, key: &str, path: &Path) -> Result<Vec<(JsonKey, Json)>, String> {
    match root.get(key) {
        Some(Json::Obj(fields)) => Ok(fields.clone()),
        None => Ok(vec![]),
        _ => Err(format!("{}: expected object in {}", path.display(), key)),
    }
}

pub(super) fn executable_name(command: &str) -> &str {
    command.trim_matches('"').rsplit(['/', '\\']).next().unwrap_or("")
}

fn is_owned_agent_ctx_mcp_entry(entry: &Json) -> bool {
    let exe = executable_name(entry.get_str("command").unwrap_or(""));
    let args = entry.get("args").and_then(Json::as_arr).unwrap_or(&[]);
    if matches!(exe, "ctx" | "ctx.exe") && args.first().and_then(Json::as_str) == Some("mcp") {
        return true;
    }
    if matches!(exe, "wsl" | "wsl.exe") {
        let len = args.len();
        if len >= 2 && args[len - 1].as_str() == Some("mcp") {
            let inner = executable_name(args[len - 2].as_str().unwrap_or(""));
            if matches!(inner, "ctx" | "ctx.exe") {
                return true;
            }
        }
    }
    false
}

fn apply_agy_eager_tools(
    entry: &mut Vec<(JsonKey, Json)>,
    mode: EagerMode,
    force_override: bool,
    path: &Path,
) -> Result<(), String> {
    let existing_tools = match entry
        .iter()
        .find(|(k, _)| k.as_ref() == "tools")
        .map(|(_, v)| v)
    {
        Some(Json::Obj(fields)) => fields.clone(),
        None => Vec::new(),
        _ => {
            return Err(format!(
                "{}: expected agent_ctx.tools to be an object",
                path.display()
            ));
        }
    };
    let desired_names = mode.eager_tool_names();
    if desired_names.is_empty() {
        if force_override {
            remove_obj_field(entry, "tools");
        }
        return Ok(());
    }
    let mut merged = if force_override {
        Vec::new()
    } else {
        existing_tools
    };
    if !force_override && mode == EagerMode::Core {
        merged.retain(|(k, v)| {
            !(k.as_ref() == "ctx_capsule"
                && v.as_obj().is_some_and(|o| {
                    o.len() == 1 && o[0].0.as_ref() == "eager" && o[0].1.as_bool() == Some(true)
                }))
        });
    }
    for tool_name in desired_names {
        if force_override || !merged.iter().any(|(k, _)| k.as_ref() == tool_name.as_str()) {
            upsert_obj_field(
                &mut merged,
                tool_name,
                Json::obj(vec![("eager", Json::Bool(true))]),
            );
        }
    }
    upsert_obj_field(entry, "tools", Json::Obj(merged));
    Ok(())
}

fn plan_mcp_custom(
    plan: &mut InstallPlan,
    path: &Path,
    command_str: String,
    args_vec: Vec<String>,
    claude: bool,
    agy_eager: Option<(EagerMode, bool)>,
) -> Result<(), String> {
    let old = plan.json(path)?;
    let mut root = old
        .as_obj()
        .ok_or_else(|| format!("{}: expected JSON object", path.display()))?
        .to_vec();
    let mut servers = object_field(&old, "mcpServers", path)?;
    if let Some((_, entry)) = servers.iter().find(|(k, _)| k.as_ref() == "agent_ctx") {
        if !is_owned_agent_ctx_mcp_entry(entry) {
            return Err(format!("{}: unmanaged MCP server agent_ctx", path.display()));
        }
    }
    let mut entry = servers
        .iter()
        .find(|(k, _)| k.as_ref() == "agent_ctx")
        .and_then(|(_, v)| v.as_obj())
        .unwrap_or(&[])
        .to_vec();
    remove_obj_field(&mut entry, "cwd");
    if claude {
        upsert_obj_field(&mut entry, "type", Json::Str("stdio".into()));
    }
    upsert_obj_field(&mut entry, "command", Json::Str(command_str));
    upsert_obj_field(
        &mut entry,
        "args",
        Json::Arr(args_vec.into_iter().map(Json::Str).collect()),
    );
    if let Some((mode, force)) = agy_eager {
        let mut env_fields = entry
            .iter()
            .find(|(k, _)| k.as_ref() == "env")
            .and_then(|(_, v)| v.as_obj())
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        upsert_obj_field(&mut env_fields, "AGENT_CTX_HOST", Json::Str("agy".into()));
        upsert_obj_field(&mut entry, "env", Json::Obj(env_fields));
        apply_agy_eager_tools(&mut entry, mode, force, path)?;
    }
    upsert_obj_field(&mut servers, "agent_ctx", Json::Obj(entry));
    upsert_obj_field(&mut root, "mcpServers", Json::Obj(servers));
    plan.set_json(path, &old, Json::Obj(root))
}

pub(super) fn plan_mcp(
    plan: &mut InstallPlan,
    path: &Path,
    bin: &Path,
    claude: bool,
    agy_eager: Option<(EagerMode, bool)>,
) -> Result<(), String> {
    plan_mcp_custom(
        plan,
        path,
        bin.to_string_lossy().into_owned(),
        vec!["mcp".into()],
        claude,
        agy_eager,
    )
}

pub(super) fn plan_rules(plan: &mut InstallPlan, path: &Path) -> Result<(), String> {
    let raw = plan.text(path)?.unwrap_or_default();
    let begin = raw.matches(GLOBAL_BLOCK_BEGIN).count();
    if begin != raw.matches(GLOBAL_BLOCK_END).count()
        || begin > 1
        || raw.find(GLOBAL_BLOCK_BEGIN) > raw.find(GLOBAL_BLOCK_END)
    {
        return Err(format!("{}: ambiguous instruction markers", path.display()));
    }
    let desired = upsert_marked_block(&raw, GLOBAL_RULES_SNIPPET, GLOBAL_BLOCK_BEGIN, GLOBAL_BLOCK_END);
    plan.set(path, desired.into_bytes(), None)
}

fn owned_handler(item: &Json, flavor: &str) -> bool {
    let Some(cmd) = item.get_str("command") else {
        return false;
    };
    let suffix = format!(" hook {} --global", flavor);
    if let Some(prefix) = cmd.strip_suffix(&suffix) {
        let single = if let Some(quoted) = prefix.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
        {
            !quoted.contains('"')
        } else {
            !prefix.chars().any(char::is_whitespace)
        };
        if single && matches!(executable_name(prefix), "ctx" | "ctx.exe") {
            return true;
        }
        let trimmed = prefix.trim();
        let first_tok = trimmed.split_whitespace().next().unwrap_or("");
        if matches!(executable_name(first_tok), "wsl" | "wsl.exe") {
            let last_tok = trimmed.split_whitespace().next_back().unwrap_or("");
            if matches!(executable_name(last_tok), "ctx" | "ctx.exe") {
                return true;
            }
        }
    }
    false
}

fn merge_hook_events(
    old: &Json,
    generated: &Json,
    flavor: &str,
    path: &Path,
) -> Result<Json, String> {
    let mut fields = old
        .as_obj()
        .ok_or_else(|| format!("{}: expected hooks object", path.display()))?
        .to_vec();
    let gen_obj = generated
        .as_obj()
        .ok_or_else(|| format!("{}: generated hooks must be an object", path.display()))?;
    for (event, desired) in gen_obj {
        let mut groups = vec![];
        if let Some(existing) = old.get(event.as_ref()) {
            let arr = existing
                .as_arr()
                .ok_or_else(|| format!("{}: expected array for {}", path.display(), event))?;
            for g in arr {
                if let Some(items) = g.get("hooks") {
                    let handlers = items
                        .as_arr()
                        .ok_or_else(|| format!("{}: malformed hook group", path.display()))?;
                    let kept: Vec<_> = handlers
                        .iter()
                        .filter(|h| !owned_handler(h, flavor))
                        .cloned()
                        .collect();
                    if !kept.is_empty() || handlers.is_empty() {
                        let mut g_fields = g
                            .as_obj()
                            .ok_or_else(|| format!("{}: malformed hook group object", path.display()))?
                            .to_vec();
                        upsert_obj_field(&mut g_fields, "hooks", Json::Arr(kept));
                        groups.push(Json::Obj(g_fields));
                    }
                } else if !owned_handler(g, flavor) {
                    groups.push(g.clone());
                }
            }
        }
        if let Some(desired_arr) = desired.as_arr() {
            groups.extend_from_slice(desired_arr);
        }
        upsert_obj_field(&mut fields, event.clone(), Json::Arr(groups));
    }
    Ok(Json::Obj(fields))
}

fn command_group(matcher: Option<&str>, cmd: &str) -> Json {
    let mut fields: Vec<(&'static str, Json)> = vec![];
    if let Some(m) = matcher {
        fields.push(("matcher", Json::Str(m.into())));
    }
    fields.push((
        "hooks",
        Json::Arr(vec![Json::obj(vec![
            ("type", Json::Str("command".into())),
            ("command", Json::Str(cmd.into())),
            ("timeout", Json::Int(5)),
        ])]),
    ));
    Json::obj(fields)
}

fn plan_hooks_with_cmd(
    plan: &mut InstallPlan,
    path: &Path,
    cmd_str: String,
    flavor: &str,
) -> Result<(), String> {
    let old = plan.json(path)?;
    let key: &'static str = if flavor == "agy" {
        "agent-context"
    } else {
        "hooks"
    };
    let current = Json::Obj(object_field(&old, key, path)?);
    let generated = if flavor == "agy" {
        build_agy_context_hook_cfg_cmd(cmd_str)
    } else {
        let events: &[(&'static str, Option<&str>)] = if flavor == "codex" {
            &[
                ("SessionStart", Some("^(compact|clear)$")),
                ("SubagentStart", None),
                (
                    "PreToolUse",
                    Some("^(exec|exec_command|Bash|shell|mcp__agent_ctx__ctx_(read|symbols|memo|capsule|impact|edit|git))$"),
                ),
                ("PostToolUse", Some("^(apply_patch|exec|exec_command|Bash|shell)$")),
            ]
        } else {
            &[
                ("SubagentStart", None),
                ("PreCompact", None),
                ("PreToolUse", Some("Agent|Task|Read|Bash|mcp__agent_ctx__ctx_.*")),
                ("PostToolUse", Some("Agent|Task|Read|Edit|MultiEdit|Write|Bash")),
            ]
        };
        let fields: Vec<(JsonKey, Json)> = events
            .iter()
            .map(|&(name, matcher)| {
                (
                    Cow::Borrowed(name),
                    Json::Arr(vec![command_group(matcher, &cmd_str)]),
                )
            })
            .collect();
        Json::Obj(fields)
    };
    let fields = merge_hook_events(&current, &generated, flavor, path)?;
    let mut root = old
        .as_obj()
        .ok_or_else(|| format!("{}: expected JSON object", path.display()))?
        .to_vec();
    upsert_obj_field(&mut root, key, fields);
    plan.set_json(path, &old, Json::Obj(root))
}

pub(super) fn plan_hooks(
    plan: &mut InstallPlan,
    path: &Path,
    bin: &Path,
    flavor: &str,
) -> Result<(), String> {
    let cmd = format!("\"{}\" hook {} --global", bin.display(), flavor);
    plan_hooks_with_cmd(plan, path, cmd, flavor)
}

pub(super) fn plan_remove_mcp(plan: &mut InstallPlan, path: &Path) -> Result<(), String> {
    if plan.target(path)?.content().is_none() {
        return Ok(());
    }
    let old = plan.json(path)?;
    let mut root = old
        .as_obj()
        .ok_or_else(|| format!("{}: expected JSON object", path.display()))?
        .to_vec();
    let mut servers = object_field(&old, "mcpServers", path)?;
    let before_len = servers.len();
    servers.retain(|(name, entry)| {
        if name.as_ref() != "agent_ctx" {
            return true;
        }
        !is_owned_agent_ctx_mcp_entry(entry)
    });
    if servers.len() != before_len {
        upsert_obj_field(&mut root, "mcpServers", Json::Obj(servers));
        plan.set_json(path, &old, Json::Obj(root))?;
    }
    Ok(())
}

pub(super) fn plan_remove_hooks(
    plan: &mut InstallPlan,
    path: &Path,
    flavor: &str,
) -> Result<(), String> {
    if plan.target(path)?.content().is_none() {
        return Ok(());
    }
    let old = plan.json(path)?;
    let mut root = old
        .as_obj()
        .ok_or_else(|| format!("{}: expected JSON object", path.display()))?
        .to_vec();
    if flavor == "agy" {
        let before_len = root.len();
        remove_obj_field(&mut root, "agent-context");
        if root.len() != before_len {
            plan.set_json(path, &old, Json::Obj(root))?;
        }
        return Ok(());
    }
    let Some(Json::Obj(events)) = old.get("hooks") else {
        return Ok(());
    };
    let mut new_events = Vec::new();
    for (ev_name, ev_val) in events {
        let Some(arr) = ev_val.as_arr() else {
            new_events.push((ev_name.clone(), ev_val.clone()));
            continue;
        };
        let mut kept_groups = Vec::new();
        for g in arr {
            if let Some(items) = g.get("hooks").and_then(Json::as_arr) {
                let kept: Vec<_> = items
                    .iter()
                    .filter(|h| !owned_handler(h, flavor))
                    .cloned()
                    .collect();
                if !kept.is_empty() {
                    if let Some(obj) = g.as_obj() {
                        let mut g_fields = obj.to_vec();
                        upsert_obj_field(&mut g_fields, "hooks", Json::Arr(kept));
                        kept_groups.push(Json::Obj(g_fields));
                    }
                }
            } else if !owned_handler(g, flavor) {
                kept_groups.push(g.clone());
            }
        }
        if !kept_groups.is_empty() {
            new_events.push((ev_name.clone(), Json::Arr(kept_groups)));
        }
    }
    upsert_obj_field(&mut root, "hooks", Json::Obj(new_events));
    plan.set_json(path, &old, Json::Obj(root))
}

pub(super) fn plan_remove_rules(plan: &mut InstallPlan, path: &Path) -> Result<(), String> {
    let Some(raw) = plan.text(path)? else {
        return Ok(());
    };
    if let (Some(s), Some(e_pos)) = (raw.find(GLOBAL_BLOCK_BEGIN), raw.find(GLOBAL_BLOCK_END)) {
        if e_pos >= s {
            let mut end_idx = e_pos + GLOBAL_BLOCK_END.len();
            if raw[end_idx..].starts_with("\r\n") {
                end_idx += 2;
            } else if raw[end_idx..].starts_with('\n') {
                end_idx += 1;
            }
            let prefix = raw[..s].trim_end_matches(['\r', '\n']);
            let suffix = &raw[end_idx..];
            let updated = if prefix.is_empty() {
                suffix.trim_start_matches(['\r', '\n']).to_string()
            } else if suffix.trim().is_empty() {
                format!("{prefix}\n")
            } else {
                format!("{prefix}\n\n{}", suffix.trim_start_matches(['\r', '\n']))
            };
            if updated != raw {
                plan.set(path, updated.into_bytes(), None)?;
            }
        }
    }
    Ok(())
}

pub(super) fn detect_wsl_windows_gemini_dirs(enable_bridge: bool) -> Option<(String, Vec<PathBuf>)> {
    if !enable_bridge {
        return None;
    }
    #[cfg(unix)]
    {
        let (distro, users_root) =
            if let Ok(test_users) = std::env::var("AGENT_CTX_WSL_WIN_USERS_DIR") {
                let d = std::env::var("AGENT_CTX_WSL_DISTRO")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "Ubuntu".to_string());
                if test_users.trim().is_empty() {
                    return None;
                }
                (d, PathBuf::from(test_users))
            } else {
                if std::env::var("AGENT_CTX_HOME").is_ok() {
                    return None;
                }
                let d = std::env::var("WSL_DISTRO_NAME").ok()?.trim().to_string();
                if d.is_empty() {
                    return None;
                }
                (d, PathBuf::from("/mnt/c/Users"))
            };
        let rd = fs::read_dir(&users_root).ok()?;
        let mut found = Vec::new();
        for entry in rd.flatten() {
            let user_dir = entry.path();
            let Some(name) = user_dir.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if matches!(name, "Public" | "Default" | "Default User" | "All Users")
                || name.starts_with('.')
            {
                continue;
            }
            if !user_dir.is_dir() {
                continue;
            }
            let gemini = user_dir.join(".gemini");
            let has_agy = gemini.join("antigravity").is_dir()
                || gemini.join("antigravity-ide").is_dir()
                || gemini.join("config").is_dir()
                || user_dir.join("AppData/Local/Programs/Antigravity").is_dir();
            if has_agy {
                found.push(gemini);
            }
        }
        found.sort();
        if found.is_empty() {
            None
        } else {
            Some((distro, found))
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

pub(super) fn plan_wsl_windows_bridge(
    plan: &mut InstallPlan,
    win_gemini: &Path,
    distro: &str,
    wsl_ctx_bin: &Path,
    eager: (EagerMode, bool),
) -> Result<(), String> {
    let cfg = win_gemini.join("config");
    let bin_str = wsl_ctx_bin.to_string_lossy().into_owned();
    plan_mcp_custom(
        plan,
        &cfg.join("mcp_config.json"),
        "wsl.exe".to_string(),
        vec![
            "-d".to_string(),
            distro.to_string(),
            "--".to_string(),
            bin_str.clone(),
            "mcp".to_string(),
        ],
        false,
        Some(eager),
    )?;
    let hook_bin = if bin_str.contains(' ') {
        format!("\"{}\"", bin_str)
    } else {
        bin_str
    };
    let hook_cmd = format!("wsl.exe -d {} -- {} hook agy --global", distro, hook_bin);
    plan_hooks_with_cmd(plan, &cfg.join("hooks.json"), hook_cmd, "agy")?;
    plan_rules(plan, &cfg.join("AGENTS.md"))
}

pub(super) fn plan_remove_wsl_windows_bridge(
    plan: &mut InstallPlan,
    win_gemini: &Path,
) -> Result<(), String> {
    let cfg = win_gemini.join("config");
    plan_remove_mcp(plan, &cfg.join("mcp_config.json"))?;
    plan_remove_hooks(plan, &cfg.join("hooks.json"), "agy")?;
    plan_remove_rules(plan, &cfg.join("AGENTS.md"))
}

pub(super) fn check_agy_config_dir(cfg_dir: &Path) -> (bool, String) {
    let mcp_path = cfg_dir.join("mcp_config.json");
    let hooks_path = cfg_dir.join("hooks.json");
    let Ok(mcp_raw) = fs::read_to_string(&mcp_path) else {
        return (false, format!("missing {}", mcp_path.display()));
    };
    let Ok(mcp_json) = json::parse_config(&mcp_raw) else {
        return (false, format!("invalid JSON in {}", mcp_path.display()));
    };
    let Some(entry) = mcp_json.get("mcpServers").and_then(|s| s.get("agent_ctx")) else {
        return (
            false,
            format!("missing mcpServers.agent_ctx in {}", mcp_path.display()),
        );
    };
    if !is_owned_agent_ctx_mcp_entry(entry) {
        return (
            false,
            format!("unrecognized agent_ctx command in {}", mcp_path.display()),
        );
    }
    let eager_count = entry
        .get("tools")
        .and_then(Json::as_obj)
        .map(|fields| {
            fields
                .iter()
                .filter(|(_, v)| v.get_bool("eager") == Some(true))
                .count()
        })
        .unwrap_or(0);
    let Ok(hooks_raw) = fs::read_to_string(&hooks_path) else {
        return (false, format!("missing {}", hooks_path.display()));
    };
    let Ok(hooks_json) = json::parse_config(&hooks_raw) else {
        return (false, format!("invalid JSON in {}", hooks_path.display()));
    };
    let Some(ac) = hooks_json.get("agent-context") else {
        return (
            false,
            format!("missing agent-context hook in {}", hooks_path.display()),
        );
    };
    for ev in ["SessionStart", "PreInvocation", "PreToolUse", "PostToolUse"] {
        let has_ev = ac
            .get(ev)
            .and_then(Json::as_arr)
            .is_some_and(|arr| !arr.is_empty());
        if !has_ev {
            return (
                false,
                format!("missing agent-context.{ev} in {}", hooks_path.display()),
            );
        }
    }
    (
        true,
        format!(
            "{}: agent_ctx ok ({} eager tools), hooks ok",
            cfg_dir.display(),
            eager_count
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_mcp_entry_recognizes_ctx_and_wsl_bridge_only() {
        let direct = Json::obj(vec![
            ("command", Json::Str("/home/u/.local/bin/ctx".into())),
            ("args", Json::Arr(vec![Json::Str("mcp".into())])),
        ]);
        assert!(is_owned_agent_ctx_mcp_entry(&direct));

        let bridge = Json::obj(vec![
            ("command", Json::Str("wsl.exe".into())),
            (
                "args",
                Json::Arr(vec![
                    Json::Str("-d".into()),
                    Json::Str("Ubuntu".into()),
                    Json::Str("--".into()),
                    Json::Str("/home/u/.local/bin/ctx".into()),
                    Json::Str("mcp".into()),
                ]),
            ),
        ]);
        assert!(is_owned_agent_ctx_mcp_entry(&bridge));

        let foreign = Json::obj(vec![
            ("command", Json::Str("python3".into())),
            ("args", Json::Arr(vec![Json::Str("custom_mcp.py".into())])),
        ]);
        assert!(!is_owned_agent_ctx_mcp_entry(&foreign));
    }
}
