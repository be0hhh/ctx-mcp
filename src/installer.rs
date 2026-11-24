//! Built-in cross-platform `ctx install` and `ctx doctor` commands:
//!   - `ctx install [--cxet] [--root <dir>] [--check]`:
//!       Atomically installs `~/.local/bin/ctx(.exe)` (shutting down any running daemon first
//!       to avoid `ETXTBSY` / Windows file locks), creates `.bak` backups before modifying
//!       existing configs, adds `%USERPROFILE%\.local\bin` to Windows User `PATH` when needed,
//!       and configures global MCP + `agent-context` hooks across Antigravity, Codex, and Claude.
//!       Default mode has zero project-specific model bans; `--cxet` additionally syncs CXET
//!       routing/guards from `<root>/agents/routing/`.
//!   - `ctx doctor [--json]`:
//!       Verifies binary installation, live daemon IPC, `0600` permissions on `daemon.json` and
//!       `snapshot.bin`, `ACTXSNP2` metadata-only snapshot integrity (zero raw source on disk),
//!       MCP tool inventory, per-agent session isolation, and client configs.

use crate::json::{self, Json};
use crate::mcp::{check_mcp_protocol, expected_tool_names};
use crate::protocol::{
    call_daemon_or_inproc, daemon_info_path, execute_request, read_daemon_info, stop_daemon_for_install, BrokerService,
};
use crate::security::find_superproject_root;
use crate::store::{default_snapshot_path, fnv1a_64, runtime_dir, verify_snapshot_metadata_only};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const GLOBAL_BLOCK_BEGIN: &str = "<!-- BEGIN AGENT_CTX GLOBAL RULES -->";
const GLOBAL_BLOCK_END: &str = "<!-- END AGENT_CTX GLOBAL RULES -->";

const GLOBAL_RULES_SNIPPET: &str = "<!-- BEGIN AGENT_CTX GLOBAL RULES -->\n\
## In-RAM Context Broker (`ctx` / MCP `agent_ctx`)\n\
\n\
- In Antigravity, call eager `mcp_agent_ctx_*` tools directly (`ctx_search`, `ctx_inspect`, `ctx_read`, `ctx_symbols`, `ctx_capsule`); use `call_mcp_tool(ServerName=\"agent_ctx\", ...)` for lazy tools (`ctx_outline`, `ctx_memo`, `ctx_elf_audit`) without reading `mcp/agent_ctx/*.json` schema files:\n\
  - Parallel search (`1-4` queries in `q`, `8 KiB` cap; bare module stem matches all extensions; lowercase = smart-case; `a|b` alternation): `ctx_search` with `{\"q\": [\"ModOrDir:pattern\", ...]}` (CLI: `ctx search -q \"Mod:pat\"`).\n\
  - Directory/file triage (`<=80` files, exact line counts, `[>=600L]`/`[OVER 800L]`, `#include`, `[L_start-L_end]` symbols): `ctx_inspect` with `{\"paths\": [\"dir1\", \"dir2\"], \"max_files\": 80}` (CLI: `ctx inspect <paths...>`).\n\
  - Exact struct/function bodies: `ctx_symbols` with `{\"requests\": [\"ModOrPath#Symbol\"], \"compact\": true}` (CLI: `ctx sym \"Mod#Sym\" --compact`).\n\
  - Full files or slices (`<=1 MiB`, no 800-line cap): `ctx_read` with `{\"paths\": [\"path\" | \"path:1-250\"]}` (CLI: `ctx read <paths...>`).\n\
  - Shared workspace findings board: `ctx_memo` with `{\"action\": \"list\" | \"put\", \"topic\": \"...\", \"summary\": \"...\", \"paths\": [...]}`.\n\
- Reuse `[RAM-Ctx Startup]` when provided. Batch known paths into a single `ctx_inspect`, `ctx_read`, or `ctx_symbols` call (`1 MiB` default budget per batch), finish directly from grouped search hits or compact symbols when sufficient, and never slice files in `100-400` line shell loops (`sed`/`head`/`nl`) or re-read unchanged files already in context.\n\
<!-- END AGENT_CTX GLOBAL RULES -->";

fn effective_home_dir() -> Result<PathBuf, String> {
    if let Ok(custom) = std::env::var("AGENT_CTX_HOME") {
        if !custom.trim().is_empty() {
            return Ok(PathBuf::from(custom));
        }
    }
    if let Ok(h) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        if !h.trim().is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    Err("cannot determine user home directory (HOME / USERPROFILE unset)".to_string())
}

fn effective_codex_home(home: &Path) -> PathBuf {
    if std::env::var("AGENT_CTX_HOME").is_err() {
        if let Ok(ch) = std::env::var("CODEX_HOME") {
            if !ch.trim().is_empty() {
                return PathBuf::from(ch);
            }
        }
    }
    home.join(".codex")
}

pub fn target_ctx_bin(home: &Path) -> PathBuf {
    let exe = if cfg!(windows) { "ctx.exe" } else { "ctx" };
    home.join(".local").join("bin").join(exe)
}

#[derive(PartialEq)]
struct Snapshot {
    data: Option<Vec<u8>>,
    mode: u32,
}

fn snapshot(path: &Path) -> Result<Snapshot, String> {
    for parent in path.ancestors().skip(1).filter(|p| !p.as_os_str().is_empty()) {
        match fs::symlink_metadata(parent) {
            Ok(m) if !m.is_dir() => return Err(format!("invalid destination parent {}", parent.display())),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
            _ => {}
        }
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => meta,
        Ok(_) => return Err(format!("refusing non-regular destination {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Snapshot { data: None, mode: 0o600 }),
        Err(e) => return Err(format!("{}: {}", path.display(), e)),
    };
    #[cfg(unix)]
    let mode = { use std::os::unix::fs::PermissionsExt; meta.permissions().mode() & 0o777 };
    #[cfg(not(unix))]
    let mode = { let _ = meta; 0o600 };
    Ok(Snapshot { data: Some(fs::read(path).map_err(|e| format!("{}: {}", path.display(), e))?), mode })
}

struct Target {
    path: PathBuf,
    before: Snapshot,
    after: Option<Vec<u8>>,
    mode: u32,
}

impl Target {
    fn content(&self) -> Option<&[u8]> {
        self.after.as_deref().or(self.before.data.as_deref())
    }

    fn changed(&self) -> bool {
        self.after.is_some() && (self.content() != self.before.data.as_deref()
            || (cfg!(unix) && self.mode != self.before.mode))
    }

    fn recheck(&self) -> Result<(), String> {
        if snapshot(&self.path)? != self.before {
            return Err(format!("{} changed since preview", self.path.display()));
        }
        Ok(())
    }
}

#[derive(Default)]
struct InstallPlan(Vec<Target>);

impl InstallPlan {
    fn target(&mut self, path: &Path) -> Result<&mut Target, String> {
        let index = match self.0.iter().position(|t| t.path == path) {
            Some(i) => i,
            None => {
                let before = snapshot(path)?;
                self.0.push(Target { path: path.to_owned(), mode: before.mode, before, after: None });
                self.0.len() - 1
            }
        };
        Ok(&mut self.0[index])
    }

    fn text(&mut self, path: &Path) -> Result<Option<String>, String> {
        self.target(path)?.content().map(|b| std::str::from_utf8(b).map(str::to_owned)
            .map_err(|_| format!("{}: invalid UTF-8", path.display()))).transpose()
    }

    fn set(&mut self, path: &Path, data: Vec<u8>, mode: Option<u32>) -> Result<(), String> {
        let target = self.target(path)?;
        target.after = Some(data);
        if let Some(m) = mode { target.mode = m; }
        Ok(())
    }

    fn json(&mut self, path: &Path) -> Result<Json, String> {
        let Some(raw) = self.text(path)? else { return Ok(Json::Obj(vec![])); };
        if raw.trim().is_empty() {
            return Ok(Json::Obj(vec![]));
        }
        let val = json::parse_config(&raw).map_err(|e| format!("{}: invalid JSON: {}", path.display(), e))?;
        if val.as_obj().is_none() { return Err(format!("{}: expected JSON object", path.display())); }
        Ok(val)
    }

    fn set_json(&mut self, path: &Path, old: &Json, new: Json) -> Result<(), String> {
        if &new != old {
            self.set(path, format!("{}\n", format_pretty_json(&new, 0)).into_bytes(), None)?;
        }
        Ok(())
    }

    fn apply(&self, binary: &Path) -> Result<(), String> {
        for file in &self.0 { file.recheck()?; }
        for file in self.0.iter().filter(|f| f.changed()) {
            file.recheck()?;
            let parent = file.path.parent().ok_or("missing destination directory")?;
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            if let Some(bytes) = &file.before.data {
                write_unique_sibling(&file.path, "bak", bytes, 0o600)?;
            }
            let staged = write_unique_sibling(&file.path, &format!("tmp.{}", std::process::id()),
                file.content().ok_or("missing replacement")?, file.mode)?;
            let replaced = (|| {
                file.recheck()?;
                if file.path == binary {
                    stop_daemon_for_install()?;
                }
                fs::rename(&staged, &file.path).map_err(|e| format!("replace {}: {}", file.path.display(), e))
            })();
            if replaced.is_err() { let _ = fs::remove_file(staged); }
            replaced?;
        }
        Ok(())
    }
}

fn write_unique_sibling(path: &Path, suffix: &str, bytes: &[u8], mode: u32) -> Result<PathBuf, String> {
    let name = path.file_name().ok_or("invalid filename")?;
    for i in 0u64.. {
        let mut filename = name.to_os_string();
        filename.push(format!(".{suffix}"));
        if i > 0 { filename.push(format!(".{i}")); }
        let sibling = path.with_file_name(filename);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut out = match options.open(&sibling) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {}", sibling.display(), e)),
        };
        let result = (|| -> std::io::Result<()> {
            out.write_all(bytes)?;
            #[cfg(unix)]
            { use std::os::unix::fs::PermissionsExt; out.set_permissions(fs::Permissions::from_mode(mode))?; }
            #[cfg(not(unix))]
            let _ = mode;
            out.sync_all()
        })();
        if let Err(e) = result {
            drop(out);
            let _ = fs::remove_file(&sibling);
            return Err(e.to_string());
        }
        return Ok(sibling);
    }
    Err("no free sibling filename".into())
}

fn plan_binary(plan: &mut InstallPlan, dest: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let source = fs::read(exe).map_err(|e| e.to_string())?;
    let stamp_path = dest.with_file_name(".ctx.sha256");
    let stamp = plan.text(&stamp_path)?;
    let old = plan.target(dest)?.content();
    let stamp_for = |bytes: &[u8]| format!("{:016x}\n", fnv1a_64(bytes));
    let new_stamp = stamp_for(&source);
    if let Some(old) = old {
        if stamp.as_deref() != Some(stamp_for(old).as_str()) && old != source {
            return Err(format!("unmanaged executable {}", dest.display()));
        }
    }
    if let Some(s) = &stamp {
        if Some(s.as_str()) != old.map(stamp_for).as_deref() && s != &new_stamp {
            return Err(format!("unmanaged stamp {}", stamp_path.display()));
        }
    }
    plan.set(dest, source, Some(0o755))?;
    plan.set(&stamp_path, new_stamp.into_bytes(), None)
}

#[cfg(windows)]
fn ensure_windows_user_path(bin_dir: &Path) {
    let dir_str = bin_dir.to_string_lossy();
    let cur_path = std::env::var("PATH").unwrap_or_default();
    if cur_path
        .split(';')
        .any(|p| p.trim().eq_ignore_ascii_case(&dir_str))
    {
        return;
    }
    let ps_script = format!(
        "$d = '{}'; $u = [Environment]::GetEnvironmentVariable('Path', 'User'); \
         if (-not $u) {{ [Environment]::SetEnvironmentVariable('Path', $d, 'User') }} \
         elseif (($u -split ';') -notcontains $d) {{ [Environment]::SetEnvironmentVariable('Path', \"$u;$d\", 'User') }}",
        dir_str.replace('\'', "''")
    );
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output();
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

fn upsert_obj_field(fields: &mut Vec<(String, Json)>, key: &str, val: Json) {
    if let Some((_, v)) = fields.iter_mut().find(|(k, _)| k == key) {
        *v = val;
    } else {
        fields.push((key.to_string(), val));
    }
}

fn remove_obj_field(fields: &mut Vec<(String, Json)>, key: &str) {
    fields.retain(|(k, _)| k != key);
}

fn format_pretty_json(val: &Json, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    let inner_pad = "  ".repeat(indent + 1);
    match val {
        Json::Obj(items) if items.is_empty() => "{}".to_string(),
        Json::Obj(items) => {
            let mut out = String::from("{\n");
            for (i, (k, v)) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&inner_pad);
                crate::json::escape_str(k, &mut out);
                out.push_str(": ");
                out.push_str(&format_pretty_json(v, indent + 1));
            }
            out.push('\n');
            out.push_str(&pad);
            out.push('}');
            out
        }
        Json::Arr(items) if items.is_empty() => "[]".to_string(),
        Json::Arr(items) => {
            let mut out = String::from("[\n");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&inner_pad);
                out.push_str(&format_pretty_json(item, indent + 1));
            }
            out.push('\n');
            out.push_str(&pad);
            out.push(']');
            out
        }
        other => other.to_json_string(),
    }
}

pub const AGY_CORE_EAGER_TOOLS: &[&str] = &[
    "ctx_search",
    "ctx_inspect",
    "ctx_read",
    "ctx_symbols",
    "ctx_capsule",
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
                        "^(read_file|view_file|run_command|swarm|invoke_subagent|call_mcp_tool|mcp_{1,2}agent_ctx_{1,2}ctx_.*)$".to_string(),
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

fn object_field(root: &Json, key: &str, path: &Path) -> Result<Vec<(String, Json)>, String> {
    match root.get(key) {
        Some(Json::Obj(fields)) => Ok(fields.clone()),
        None => Ok(vec![]),
        _ => Err(format!("{}: expected object in {}", path.display(), key)),
    }
}

fn executable_name(command: &str) -> &str {
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
    matches!(exe, "python" | "python3" | "python.exe" | "python3.exe")
        && args
            .iter()
            .filter_map(Json::as_str)
            .any(|a| executable_name(a) == "run_ctx.py")
}

fn apply_agy_eager_tools(
    entry: &mut Vec<(String, Json)>,
    mode: EagerMode,
    force_override: bool,
    path: &Path,
) -> Result<(), String> {
    let existing_tools = match entry.iter().find(|(k, _)| k == "tools").map(|(_, v)| v) {
        Some(Json::Obj(fields)) => fields.clone(),
        None => Vec::new(),
        _ => return Err(format!("{}: expected agent_ctx.tools to be an object", path.display())),
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
    for tool_name in desired_names {
        if force_override || !merged.iter().any(|(k, _)| k == &tool_name) {
            upsert_obj_field(
                &mut merged,
                &tool_name,
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
    let mut root = old.as_obj().unwrap().to_vec();
    let mut servers = object_field(&old, "mcpServers", path)?;
    for (name, entry) in &servers {
        if name != "agent_ctx" && name != "cxet_local" { continue; }
        let exe = executable_name(entry.get_str("command").unwrap_or(""));
        let args = entry.get("args").and_then(Json::as_arr).unwrap_or(&[]);
        let owned = if name == "agent_ctx" {
            is_owned_agent_ctx_mcp_entry(entry)
        } else {
            matches!(exe, "python" | "python3" | "python.exe" | "python3.exe") &&
                args.iter().filter_map(Json::as_str).any(|a| a.replace('\\', "/").ends_with("tools/Codex/CxetMcpServer.py"))
        };
        if !owned { return Err(format!("{}: unmanaged MCP server {}", path.display(), name)); }
    }
    remove_obj_field(&mut servers, "cxet_local");
    let mut entry = servers.iter().find(|(k, _)| k == "agent_ctx")
        .and_then(|(_, v)| v.as_obj()).unwrap_or(&[]).to_vec();
    remove_obj_field(&mut entry, "cwd");
    if claude { upsert_obj_field(&mut entry, "type", Json::Str("stdio".into())); }
    upsert_obj_field(&mut entry, "command", Json::Str(command_str));
    upsert_obj_field(
        &mut entry,
        "args",
        Json::Arr(args_vec.into_iter().map(Json::Str).collect()),
    );
    if let Some((mode, force)) = agy_eager {
        apply_agy_eager_tools(&mut entry, mode, force, path)?;
    }
    upsert_obj_field(&mut servers, "agent_ctx", Json::Obj(entry));
    upsert_obj_field(&mut root, "mcpServers", Json::Obj(servers));
    plan.set_json(path, &old, Json::Obj(root))
}

fn plan_mcp(
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

fn plan_rules(plan: &mut InstallPlan, path: &Path, codex: bool) -> Result<(), String> {
    let raw = plan.text(path)?.unwrap_or_default();
    if codex && raw.contains("BEGIN CXET CODEX ROUTING") { return Ok(()); }
    let begin = raw.matches(GLOBAL_BLOCK_BEGIN).count();
    if begin != raw.matches(GLOBAL_BLOCK_END).count() || begin > 1 ||
        raw.find(GLOBAL_BLOCK_BEGIN) > raw.find(GLOBAL_BLOCK_END) {
        return Err(format!("{}: ambiguous instruction markers", path.display()));
    }
    let desired = upsert_marked_block(&raw, GLOBAL_RULES_SNIPPET, GLOBAL_BLOCK_BEGIN, GLOBAL_BLOCK_END);
    plan.set(path, desired.into_bytes(), None)
}

// Locate single-line assignments and tables without treating data inside
// multiline arrays or strings as a configuration header.
fn toml_records(text: &str) -> Result<Vec<&str>, String> {
    let mut records = vec![];
    let mut start = 0;
    let mut end = 0;
    let mut depth = 0usize;
    let mut quoted: Option<(u8, bool)> = None;
    for line in text.split_inclusive('\n') {
        end += line.len();
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if let Some((q, triple)) = quoted {
                if q == b'"' && b == b'\\' { i += 2; continue; }
                if triple && bytes.get(i..i + 3) == Some(&[q; 3]) {
                    quoted = None;
                    i += 3;
                    continue;
                }
                if !triple && b == q { quoted = None; }
                if !triple && b == b'\n' { return Err("unterminated TOML string".into()); }
            } else {
                match b {
                    b'#' => break,
                    b'\'' | b'"' => {
                        let triple = bytes.get(i..i + 3) == Some(&[b; 3]);
                        quoted = Some((b, triple));
                        if triple { i += 2; }
                    }
                    b'[' | b'{' => depth += 1,
                    b']' | b'}' => depth = depth.checked_sub(1).ok_or("invalid TOML delimiter")?,
                    _ => {}
                }
            }
            i += 1;
        }
        if depth == 0 && quoted.is_none() {
            records.push(&text[start..end]);
            start = end;
        }
    }
    if start != text.len() { return Err("unterminated TOML value".into()); }
    Ok(records)
}

fn toml_value(text: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in text.char_indices() {
        if escaped { escaped = false; continue; }
        if let Some(q) = quote {
            if q == '"' && ch == '\\' { escaped = true; }
            if ch == q { quote = None; }
        } else if ch == '"' || ch == '\'' { quote = Some(ch); }
        else if ch == '#' { return text[..index].trim(); }
    }
    text.trim()
}

fn toml_table_name(header: &str) -> Result<String, String> {
    let table = header.strip_prefix('[').and_then(|t| t.strip_suffix(']')).ok_or("invalid TOML table")?;
    // Unquote simple segments without collapsing a quoted key containing literal dots.
    Ok(table.split('.').map(|key| {
        let k = key.trim();
        k.strip_prefix('"').and_then(|s| s.strip_suffix('"')).or_else(||
            k.strip_prefix('\'').and_then(|s| s.strip_suffix('\''))).unwrap_or(k)
    }).collect::<Vec<_>>().join("."))
}

fn toml_tool_names(raw: &str) -> Result<Vec<String>, String> {
    let value = raw.lines().map(toml_value).collect::<Vec<_>>().join(" ");
    let items = value.trim().strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        .ok_or("expected an array of tool names")?.trim();
    items.split_terminator(',').map(|item| {
        let item = item.trim();
        if let Some(literal) = item.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
            return Ok(literal.to_owned());
        }
        json::parse(item).ok().and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| "expected a quoted tool name".to_owned())
    }).collect()
}

fn codex_tool_config(raw: &str, expected: &[String]) -> Result<usize, String> {
    let mut in_server = false;
    let mut found_server = false;
    let mut enabled = None;
    let mut allow = None;
    let mut deny = None;
    for record in toml_records(raw)? {
        let line = record.trim();
        if line.starts_with('[') {
            in_server = toml_table_name(toml_value(line))? == "mcp_servers.agent_ctx";
            if in_server && std::mem::replace(&mut found_server, true) {
                return Err("duplicate mcp_servers.agent_ctx table".into());
            }
        } else if in_server && !line.is_empty() && !line.starts_with('#') {
            let (key, value) = line.split_once('=').ok_or("invalid TOML assignment")?;
            match key.trim().trim_matches(['"', '\'']) {
                "enabled" if enabled.is_none() => enabled = Some(match toml_value(value) {
                    "true" => true,
                    "false" => false,
                    _ => return Err("expected boolean in enabled".into()),
                }),
                "enabled_tools" if allow.is_none() => allow = Some(toml_tool_names(value)
                    .map_err(|error| format!("enabled_tools: {error}"))?),
                "disabled_tools" if deny.is_none() => deny = Some(toml_tool_names(value)
                    .map_err(|error| format!("disabled_tools: {error}"))?),
                key @ ("enabled" | "enabled_tools" | "disabled_tools") => {
                    return Err(format!("duplicate MCP setting {key}"));
                }
                _ => {}
            }
        }
    }
    if !found_server {
        return Err("mcp_servers.agent_ctx table is absent or uses an unsupported config form".into());
    }
    if enabled == Some(false) {
        return Err("agent_ctx is disabled (enabled = false)".into());
    }
    let excluded: Vec<_> = expected.iter().filter(|name| {
        allow.as_ref().is_some_and(|tools| !tools.contains(name))
            || deny.as_ref().is_some_and(|tools| tools.contains(name))
    }).map(String::as_str).collect();
    if !excluded.is_empty() {
        return Err(format!("enabled_tools/disabled_tools exclude: {}", excluded.join(", ")));
    }
    Ok(expected.len())
}

fn check_codex_tool_config(path: &Path, expected: &[String]) -> (bool, String) {
    let result = fs::read_to_string(path).map_err(|error| error.to_string())
        .and_then(|raw| codex_tool_config(&raw, expected));
    let (ok, detail) = match result {
        Ok(count) => (true, format!("config permits {count} catalog tools")),
        Err(error) => (false, error),
    };
    (ok, format!("{}: {detail}; host exposure unverified", path.display()))
}

fn upsert_codex_toml_mcp_and_hooks(raw: &str, bin: &Path) -> Result<String, String> {
    let nl = if raw.contains("\r\n") { "\r\n" } else { "\n" };
    let command = Json::Str(bin.to_string_lossy().into_owned()).to_json_string();
    let managed = [("command", command.as_str()), ("args", "[\"mcp\"]"),
        ("startup_timeout_sec", "10"), ("tool_timeout_sec", "30"), ("enabled", "true"),
        ("default_tools_approval_mode", "\"auto\"")];
    let sections = ["features", "mcp_servers.agent_ctx", "mcp_servers.cxet_local"];
    let records = toml_records(raw)?;
    let mut out = String::new();
    let mut found = [false; 3];
    let mut preamble = true;
    let mut i = 0;
    while i < records.len() {
        let header = toml_value(records[i]);
        if !header.starts_with('[') {
            if !header.is_empty() && !header.contains('=') { return Err("invalid TOML assignment".into()); }
            if let Some((key, _)) = header.split_once('=') {
                let key = key.trim().trim_matches(['"', '\'']);
                if preamble && (key == "mcp_servers" || key == "features" || key.starts_with("mcp_servers.")
                    || key.starts_with("features.")) {
                    return Err("ambiguous inline or dotted TOML configuration".into());
                }
            }
            out.push_str(records[i]);
            i += 1;
            continue;
        }
        let table = toml_table_name(header)?;
        preamble = false;
        let Some(idx) = sections.iter().position(|&s| s == table) else {
            if table.starts_with("mcp_servers.cxet_local.") {
                return Err("ambiguous retired MCP server subtable".into());
            }
            out.push_str(records[i]);
            i += 1;
            continue;
        };
        if found[idx] { return Err(format!("duplicate TOML table {table}")); }
        found[idx] = true;
        let mut end = i + 1;
        while end < records.len() && !toml_value(records[end]).starts_with('[') { end += 1; }
        let keys: &[(&str, &str)] = if idx == 0 { &[("hooks", "true")] } else { &managed };
        let mut present = vec![];
        let mut old_command = None;
        let mut old_args = None;
        let mut body = String::new();
        for line in &records[i+1..end] {
            let value = toml_value(line);
            if value.is_empty() { body.push_str(line); continue; }
            let (key, val) = value.split_once('=').ok_or("invalid TOML assignment")?;
            let key = key.trim().trim_matches(['"', '\'']);
            let val = val.trim();
            if key == "command" { old_command = Some(val); }
            if key == "args" { old_args = Some(val); }
            if idx != 0 && key == "cwd" { continue; }
            if let Some((key, desired)) = keys.iter().find(|(k, _)| *k == key) {
                if present.contains(key) { return Err(format!("duplicate TOML key {key}")); }
                present.push(*key);
                if val == *desired || (idx == 1 && !matches!(*key, "command" | "args")) { body.push_str(line); }
                else {
                    if line.trim_end().contains('\n') {
                        body.push_str(&format!("{key} = {desired}{nl}"));
                        continue;
                    }
                    let pos = line.find('=').unwrap() + 1;
                    let trailing = line[pos..].find(val).ok_or("ambiguous TOML value")? + pos + val.len();
                    body.push_str(&line[..pos]);
                    body.push(' ');
                    body.push_str(desired);
                    body.push_str(&line[trailing..]);
                }
            } else if idx == 2 {
                return Err(format!("unmanaged key in retired MCP server: {key}"));
            } else { body.push_str(line); }
        }
        if idx != 0 {
            let exe = old_command.and_then(|s| json::parse(s).ok())
                .and_then(|v| v.as_str().map(str::to_owned))
                .or_else(|| old_command.and_then(|s| s.strip_prefix('\'')?.strip_suffix('\'')).map(str::to_owned))
                .ok_or("MCP server has no recognized command")?;
            let exe = executable_name(&exe);
            let args = old_args.unwrap_or("");
            let owned = if idx == 2 {
                matches!(exe, "python" | "python3" | "python.exe" | "python3.exe") && args.contains("tools/Codex/CxetMcpServer.py")
            } else {
                matches!(exe, "ctx" | "ctx.exe") && (args.contains("\"mcp\"") || args.contains("'mcp'"))
                    || matches!(exe, "python" | "python3" | "python.exe" | "python3.exe") && args.contains("run_ctx.py")
            };
            if !owned { return Err(format!("unmanaged MCP server in {table}")); }
        }
        if idx != 2 {
            out.push_str(records[i]);
            if !out.ends_with('\n') { out.push_str(nl); }
            out.push_str(&body);
            for &(key, value) in keys {
                if !present.contains(&key) {
                    if !out.ends_with('\n') { out.push_str(nl); }
                    out.push_str(&format!("{key} = {value}{nl}"));
                }
            }
        }
        i = end;
    }
    for (idx, keys) in [(0usize, &[("hooks", "true")][..]), (1, &managed[..])] {
        if !found[idx] {
            if !out.is_empty() {
                if !out.ends_with('\n') { out.push_str(nl); }
                out.push_str(nl);
            }
            out.push_str(&format!("[{}]{nl}", sections[idx]));
            for &(key, val) in keys { out.push_str(&format!("{key} = {val}{nl}")); }
        }
    }
    Ok(out)
}

fn owned_handler(item: &Json, flavor: &str, guard: Option<&str>) -> bool {
    let Some(cmd) = item.get_str("command") else { return false; };
    let suffix = format!(" hook {} --global", flavor);
    if let Some(prefix) = cmd.strip_suffix(&suffix) {
        let single = if let Some(quoted) = prefix.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            !quoted.contains('"')
        } else { !prefix.chars().any(char::is_whitespace) };
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
    guard == Some(cmd)
}

fn merge_hook_events(old: &Json, generated: &Json, flavor: &str, guard: Option<&str>, path: &Path) -> Result<Json, String> {
    let mut fields = old.as_obj().ok_or_else(|| format!("{}: expected hooks object", path.display()))?.to_vec();
    for (event, desired) in generated.as_obj().unwrap() {
        let mut groups = vec![];
        if let Some(existing) = old.get(event) {
            let arr = existing.as_arr().ok_or_else(|| format!("{}: expected array for {}", path.display(), event))?;
            for g in arr {
                if let Some(items) = g.get("hooks") {
                    let handlers = items.as_arr().ok_or_else(|| format!("{}: malformed hook group", path.display()))?;
                    let kept: Vec<_> = handlers.iter().filter(|h| !owned_handler(h, flavor, guard)).cloned().collect();
                    if !kept.is_empty() || handlers.is_empty() {
                        let mut fields = g.as_obj().unwrap().to_vec();
                        upsert_obj_field(&mut fields, "hooks", Json::Arr(kept));
                        groups.push(Json::Obj(fields));
                    }
                } else if !owned_handler(g, flavor, guard) { groups.push(g.clone()); }
            }
        }
        groups.extend_from_slice(desired.as_arr().unwrap());
        upsert_obj_field(&mut fields, event, Json::Arr(groups));
    }
    Ok(Json::Obj(fields))
}

fn command_group(matcher: Option<&str>, cmd: &str) -> Json {
    let mut fields = vec![];
    if let Some(m) = matcher { fields.push(("matcher", Json::Str(m.into()))); }
    fields.push(("hooks", Json::Arr(vec![Json::obj(vec![
        ("type", Json::Str("command".into())), ("command", Json::Str(cmd.into())), ("timeout", Json::Int(5)),
    ])])));
    Json::obj(fields)
}

fn plan_hooks_with_cmd(
    plan: &mut InstallPlan,
    path: &Path,
    cmd_str: String,
    flavor: &str,
    guard: Option<&str>,
) -> Result<(), String> {
    let old = plan.json(path)?;
    let key = if flavor == "agy" { "agent-context" } else { "hooks" };
    let current = Json::Obj(object_field(&old, key, path)?);
    let generated = if flavor == "agy" {
        build_agy_context_hook_cfg_cmd(cmd_str)
    } else {
        let events: &[(&str, Option<&str>)] = if flavor == "codex" {
            &[("SessionStart", Some("^(compact|clear)$")), ("SubagentStart", None),
              ("PreToolUse", Some("^(spawn_agent|Agent|exec|exec_command|Bash|shell|mcp__agent_ctx__ctx_.*)$")),
              ("PostToolUse", Some("^(spawn_agent|Agent|apply_patch|exec|exec_command|Bash|shell)$"))]
        } else {
            &[("SubagentStart", None), ("PreCompact", None), ("PreToolUse", Some("Agent|Task|Read|Bash|mcp__agent_ctx__ctx_.*")),
              ("PostToolUse", Some("Agent|Task|Read|Edit|MultiEdit|Write|Bash"))]
        };
        let fields = events.iter().map(|&(name, matcher)| {
            let mut groups = vec![];
            if let Some(guard) = guard {
                match name {
                    "PreToolUse" => groups.push(command_group(Some("^(spawn_agent|Agent)$"), guard)),
                    "SubagentStart" => groups.push(command_group(None, guard)),
                    _ => {}
                }
            }
            groups.push(command_group(matcher, &cmd_str));
            (name.to_string(), Json::Arr(groups))
        }).collect();
        Json::Obj(fields)
    };
    let fields = merge_hook_events(&current, &generated, flavor, guard, path)?;
    let mut root = old.as_obj().unwrap().to_vec();
    upsert_obj_field(&mut root, key, fields);
    plan.set_json(path, &old, Json::Obj(root))
}

fn plan_hooks(plan: &mut InstallPlan, path: &Path, bin: &Path, flavor: &str, guard: Option<&str>) -> Result<(), String> {
    let cmd = format!("\"{}\" hook {} --global", bin.display(), flavor);
    plan_hooks_with_cmd(plan, path, cmd, flavor, guard)
}

fn plan_cxet_python(plan: &mut InstallPlan, repo: &Path, home: &Path, codex: &Path) -> Result<(), String> {
    let script = repo.join("agents/routing/SyncAgentAdapters.py");
    if !script.is_file() { return Err(format!("missing --cxet adapter {}", script.display())); }
    let cfg = home.join(".gemini/config");
    let mcp = cfg.join("mcp_config.json");
    let hooks = cfg.join("hooks.json");
    let guard = cfg.join("hooks/swarm_guard.py");
    let routing = guard.with_file_name("AgentRouting.py");
    let instructions = codex.join("AGENTS.md");
    let config = codex.join("config.toml");
    let destinations = [&mcp, &hooks, &guard, &routing, &instructions, &config];
    for path in destinations { plan.target(path)?; }
    let py = if cfg!(windows) { "python" } else { "python3" };
    let out = Command::new(py).arg("-B").arg(&script).arg("--root").arg(repo)
        .arg("--install-preview").arg("--global-path").arg(&mcp).arg("--hooks-path").arg(&hooks)
        .arg("--guard-script-path").arg(&guard).arg("--codex-home").arg(codex)
        .env("AGENT_CTX_HOME", home).output().map_err(|e| format!("{}: {}", py, e))?;
    if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).trim().to_string()); }
    let preview = json::parse_config(std::str::from_utf8(&out.stdout).map_err(|e| e.to_string())?)?;
    let mut seen = std::collections::HashSet::new();
    for item in preview.as_arr().ok_or("invalid install preview")? {
        let path = Path::new(item.get_str("path").ok_or("missing preview path")?);
        if !destinations.iter().any(|p| p.as_path() == path) || !seen.insert(path) {
            return Err(format!("unexpected or duplicate preview path {}", path.display()));
        }
        let prior = match item.get("before") {
            Some(Json::Null) => None,
            Some(Json::Str(s)) => Some(s.as_bytes()),
            _ => return Err("invalid preview baseline".into()),
        };
        if prior != plan.target(path)?.before.data.as_deref() { return Err(format!("{} changed since preview", path.display())); }
        let body = item.get_str("after").ok_or("missing preview content")?;
        let mode = item.get_i64("mode").filter(|n| (0..=0o7777).contains(n)).ok_or("invalid preview mode")?;
        plan.set(path, body.as_bytes().to_vec(), Some(mode as u32))?;
    }
    Ok(())
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
                "codex" | "openai" | "sol" => set.codex = true,
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

fn targets_stamp_path(bin: &Path) -> PathBuf {
    bin.with_file_name(".ctx.targets.json")
}

fn load_saved_targets(bin: &Path) -> Option<TargetSet> {
    let txt = fs::read_to_string(targets_stamp_path(bin)).ok()?;
    let parsed = json::parse_config(&txt).ok()?;
    let arr = parsed.get("targets")?.as_arr()?;
    let mut set = TargetSet { agy: false, claude: false, codex: false };
    for v in arr {
        match v.as_str().unwrap_or("") {
            "antigravity" | "agy" => set.agy = true,
            "claude" => set.claude = true,
            "codex" => set.codex = true,
            _ => {}
        }
    }
    Some(set)
}

fn load_saved_eager(bin: &Path) -> Option<EagerMode> {
    let txt = fs::read_to_string(targets_stamp_path(bin)).ok()?;
    let parsed = json::parse_config(&txt).ok()?;
    parsed.get_str("eager").and_then(|s| EagerMode::parse(s).ok())
}

fn write_targets_stamp(bin: &Path, targets: TargetSet, eager: EagerMode) {
    let t_stamp = targets_stamp_path(bin);
    let mut arr = Vec::new();
    if targets.agy { arr.push(Json::Str("antigravity".into())); }
    if targets.claude { arr.push(Json::Str("claude".into())); }
    if targets.codex { arr.push(Json::Str("codex".into())); }
    let body = format!(
        "{}\n",
        Json::obj(vec![
            ("targets", Json::Arr(arr)),
            ("eager", Json::Str(eager.as_str().into())),
        ])
        .to_json_string()
    );
    let _ = fs::write(&t_stamp, body);
}

fn which_in_path(exe_stem: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else { return false; };
    for dir in std::env::split_paths(&path_var) {
        if dir.join(exe_stem).is_file() {
            return true;
        }
        #[cfg(windows)]
        for ext in [".exe", ".cmd", ".bat"] {
            if dir.join(format!("{exe_stem}{ext}")).is_file() {
                return true;
            }
        }
    }
    false
}

fn detect_wsl_windows_gemini_dirs(enable_bridge: bool) -> Option<(String, Vec<PathBuf>)> {
    if !enable_bridge {
        return None;
    }
    #[cfg(unix)]
    {
        let (distro, users_root) = if let Ok(test_users) = std::env::var("AGENT_CTX_WSL_WIN_USERS_DIR") {
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
            let Some(name) = user_dir.file_name().and_then(|s| s.to_str()) else { continue; };
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

fn detect_antigravity_desktop_app(home: &Path) -> bool {
    if home.join(".gemini/antigravity").is_dir()
        || home.join(".gemini/antigravity-ide").is_dir()
        || Path::new("/Applications/Antigravity.app").exists()
        || home.join("Applications/Antigravity.app").exists()
        || which_in_path("antigravity")
    {
        return true;
    }
    #[cfg(windows)]
    {
        for var in ["LOCALAPPDATA", "ProgramFiles"] {
            if let Ok(base) = std::env::var(var) {
                if !base.trim().is_empty() {
                    let b = PathBuf::from(base);
                    if b.join("Programs").join("Antigravity").is_dir()
                        || b.join("Programs").join("Antigravity IDE").is_dir()
                        || b.join("Antigravity").is_dir()
                    {
                        return true;
                    }
                }
            }
        }
    }
    detect_wsl_windows_gemini_dirs(true).is_some()
}

fn scan_detected_harnesses(home: &Path, codex_home: &Path) -> (bool, bool, bool) {
    let agy = home.join(".gemini/config").is_dir()
        || home.join(".gemini/antigravity-cli").is_dir()
        || which_in_path("agy")
        || detect_antigravity_desktop_app(home);
    let claude = home.join(".claude").is_dir()
        || home.join(".claude.json").is_file()
        || which_in_path("claude");
    let codex = codex_home.is_dir() || which_in_path("codex");
    (agy, claude, codex)
}

fn recommended_default_targets(_home: &Path, _codex_home: &Path) -> TargetSet {
    // Antigravity (CLI + Desktop App 2.0 + IDE) is the primary validated default;
    // Claude Code and Codex CLI remain opt-in via interactive toggle or `--targets`.
    TargetSet::agy_only()
}

fn open_interactive_tty() -> Option<(Box<dyn BufRead>, Box<dyn Write>)> {
    #[cfg(unix)]
    {
        let reader = OpenOptions::new().read(true).open("/dev/tty").ok()?;
        let writer = OpenOptions::new().write(true).open("/dev/tty").ok()?;
        Some((Box::new(BufReader::new(reader)), Box::new(writer)))
    }
    #[cfg(windows)]
    {
        let reader = OpenOptions::new().read(true).open("CONIN$").ok()?;
        let writer = OpenOptions::new().write(true).open("CONOUT$").ok()?;
        Some((Box::new(BufReader::new(reader)), Box::new(writer)))
    }
}

fn prompt_targets_interactive(home: &Path, codex_home: &Path) -> Result<Option<TargetSet>, String> {
    let (agy_det, claude_det, codex_det) = scan_detected_harnesses(home, codex_home);
    let mut sel = recommended_default_targets(home, codex_home);
    let Some((mut reader, mut writer)) = open_interactive_tty() else {
        return Ok(Some(sel));
    };

    let tag = |det: bool| if det { "[detected] " } else { "[not found]" };
    let mark = |on: bool| if on { "x" } else { " " };
    let mut line = String::new();

    loop {
        let _ = writeln!(writer);
        let _ = writeln!(writer, "  ctx-mcp setup — select AI harnesses to configure:");
        let _ = writeln!(
            writer,
            "    [{}] 1. Antigravity (CLI, App 2.0 & IDE) {}  * Default (5 eager tools, -45% time, -38% new tokens)",
            mark(sel.agy),
            tag(agy_det)
        );
        let _ = writeln!(
            writer,
            "    [{}] 2. Claude Code                      {}  (optional)",
            mark(sel.claude),
            tag(claude_det)
        );
        let _ = writeln!(
            writer,
            "    [{}] 3. Codex CLI (GPT/Sol)              {}  (optional: deferred MCP token overhead)",
            mark(sel.codex),
            tag(codex_det)
        );
        let _ = writeln!(writer);
        let _ = write!(
            writer,
            "  Press Enter to confirm, type 1/2/3 to toggle (or 'all' / 'none' / 'q' to cancel): "
        );
        let _ = writer.flush();

        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            let _ = writeln!(writer);
            return Ok(Some(sel));
        }
        let trimmed = line.trim().to_ascii_lowercase();
        match trimmed.as_str() {
            "" | "y" | "yes" | "ok" => return Ok(Some(sel)),
            "q" | "quit" | "exit" => return Ok(None),
            "a" | "all" => {
                sel = TargetSet::all();
                continue;
            }
            "none" | "0" => {
                sel = TargetSet { agy: false, claude: false, codex: false };
                continue;
            }
            _ => {
                let mut toggled = false;
                for tok in trimmed.split(|c: char| c.is_whitespace() || c == ',') {
                    match tok {
                        "1" | "agy" | "antigravity" => { sel.agy = !sel.agy; toggled = true; }
                        "2" | "claude" => { sel.claude = !sel.claude; toggled = true; }
                        "3" | "codex" => { sel.codex = !sel.codex; toggled = true; }
                        "" => {}
                        _ => {
                            let _ = writeln!(writer, "  Unrecognized input `{tok}` — enter 1, 2, 3, all, q, or press Enter.");
                            toggled = true;
                        }
                    }
                }
                if !toggled {
                    return Ok(Some(sel));
                }
            }
        }
    }
}

fn plan_remove_mcp(plan: &mut InstallPlan, path: &Path) -> Result<(), String> {
    if plan.target(path)?.content().is_none() {
        return Ok(());
    }
    let old = plan.json(path)?;
    let mut root = old.as_obj().unwrap().to_vec();
    let mut servers = object_field(&old, "mcpServers", path)?;
    let before_len = servers.len();
    servers.retain(|(name, entry)| {
        if name != "agent_ctx" && name != "cxet_local" {
            return true;
        }
        let exe = executable_name(entry.get_str("command").unwrap_or(""));
        let args = entry.get("args").and_then(Json::as_arr).unwrap_or(&[]);
        let owned = if name == "agent_ctx" {
            is_owned_agent_ctx_mcp_entry(entry)
        } else {
            matches!(exe, "python" | "python3" | "python.exe" | "python3.exe")
                && args.iter().filter_map(Json::as_str).any(|a| a.replace('\\', "/").ends_with("tools/Codex/CxetMcpServer.py"))
        };
        !owned
    });
    if servers.len() != before_len {
        upsert_obj_field(&mut root, "mcpServers", Json::Obj(servers));
        plan.set_json(path, &old, Json::Obj(root))?;
    }
    Ok(())
}

fn plan_remove_hooks(plan: &mut InstallPlan, path: &Path, flavor: &str) -> Result<(), String> {
    if plan.target(path)?.content().is_none() {
        return Ok(());
    }
    let old = plan.json(path)?;
    let mut root = old.as_obj().unwrap().to_vec();
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
                let kept: Vec<_> = items.iter().filter(|h| !owned_handler(h, flavor, None)).cloned().collect();
                if !kept.is_empty() {
                    let mut g_fields = g.as_obj().unwrap().to_vec();
                    upsert_obj_field(&mut g_fields, "hooks", Json::Arr(kept));
                    kept_groups.push(Json::Obj(g_fields));
                }
            } else if !owned_handler(g, flavor, None) {
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

fn plan_remove_rules(plan: &mut InstallPlan, path: &Path) -> Result<(), String> {
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

fn plan_remove_codex_toml(plan: &mut InstallPlan, path: &Path) -> Result<(), String> {
    let Some(raw) = plan.text(path)? else {
        return Ok(());
    };
    let records = toml_records(&raw)?;
    let mut out = String::new();
    let mut changed = false;
    let mut i = 0;
    while i < records.len() {
        let header = toml_value(records[i]);
        if header.starts_with('[') {
            let table = toml_table_name(header)?;
            if table == "mcp_servers.agent_ctx" || table == "mcp_servers.cxet_local" {
                let mut end = i + 1;
                while end < records.len() && !toml_value(records[end]).starts_with('[') {
                    end += 1;
                }
                let mut owned = true;
                for rec in &records[i + 1..end] {
                    let line = toml_value(rec);
                    if let Some((k, v)) = line.split_once('=') {
                        if k.trim().trim_matches(['"', '\'']) == "command" {
                            let parsed = json::parse(v.trim()).ok();
                            let cmd = parsed.as_ref().and_then(Json::as_str).unwrap_or("");
                            let exe = executable_name(cmd);
                            owned = matches!(exe, "ctx" | "ctx.exe" | "python" | "python3" | "python.exe" | "python3.exe");
                        }
                    }
                }
                if owned {
                    changed = true;
                    i = end;
                    continue;
                }
            }
        }
        out.push_str(records[i]);
        i += 1;
    }
    if changed {
        plan.set(path, out.into_bytes(), None)?;
    }
    Ok(())
}

fn plan_wsl_windows_bridge(
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
    plan_hooks_with_cmd(plan, &cfg.join("hooks.json"), hook_cmd, "agy", None)?;
    plan_rules(plan, &cfg.join("AGENTS.md"), false)
}

fn plan_remove_wsl_windows_bridge(plan: &mut InstallPlan, win_gemini: &Path) -> Result<(), String> {
    let cfg = win_gemini.join("config");
    plan_remove_mcp(plan, &cfg.join("mcp_config.json"))?;
    plan_remove_hooks(plan, &cfg.join("hooks.json"), "agy")?;
    plan_remove_rules(plan, &cfg.join("AGENTS.md"))
}

fn check_agy_config_dir(cfg_dir: &Path) -> (bool, String) {
    let mcp_path = cfg_dir.join("mcp_config.json");
    let hooks_path = cfg_dir.join("hooks.json");
    let Ok(mcp_raw) = fs::read_to_string(&mcp_path) else {
        return (false, format!("missing {}", mcp_path.display()));
    };
    let Ok(mcp_json) = json::parse_config(&mcp_raw) else {
        return (false, format!("invalid JSON in {}", mcp_path.display()));
    };
    let Some(entry) = mcp_json.get("mcpServers").and_then(|s| s.get("agent_ctx")) else {
        return (false, format!("missing mcpServers.agent_ctx in {}", mcp_path.display()));
    };
    if !is_owned_agent_ctx_mcp_entry(entry) {
        return (false, format!("unrecognized agent_ctx command in {}", mcp_path.display()));
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
        return (false, format!("missing agent-context hook in {}", hooks_path.display()));
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

fn prepare_install(
    home: &Path,
    codex: &Path,
    bin: &Path,
    repo: Option<&Path>,
    targets: TargetSet,
    eager: (EagerMode, bool),
    wsl_bridge: bool,
) -> Result<InstallPlan, String> {
    let mut plan = InstallPlan::default();
    plan_binary(&mut plan, bin)?;
    let agy = home.join(".gemini/config");
    let mut guard_cmd = None;
    if let Some(repo) = repo {
        plan_cxet_python(&mut plan, repo, home, codex)?;
        let src = repo.join("agents/hooks/CodexSubagentGuardHook.py");
        let bytes = fs::read(&src).map_err(|e| format!("{}: {}", src.display(), e))?;
        let dest = codex.join("hooks/codex_subagent_guard.py");
        if let Some(old) = plan.target(&dest)?.content() {
            if old != bytes && !old.starts_with(b"#!/usr/bin/env python3\n\"\"\"Codex CLI subagent model/effort/capsule guard hook") {
                return Err(format!("unmanaged guard {}", dest.display()));
            }
        }
        plan.set(&dest, bytes, Some(0o755))?;
        let policy_src = repo.join("agents/routing/AgentRouting.json");
        let policy = fs::read(&policy_src).map_err(|e| format!("{}: {e}", policy_src.display()))?;
        plan.set(&dest.with_file_name("AgentRouting.json"), policy, Some(0o644))?;
        let py = if cfg!(windows) { "python" } else { "python3" };
        guard_cmd = Some(format!("{} -B \"{}\"", py, dest.display()));
    } else {
        if targets.agy {
            plan_mcp(&mut plan, &agy.join("mcp_config.json"), bin, false, Some(eager))?;
            plan_hooks(&mut plan, &agy.join("hooks.json"), bin, "agy", None)?;
            plan_rules(&mut plan, &agy.join("AGENTS.md"), false)?;
        } else {
            plan_remove_mcp(&mut plan, &agy.join("mcp_config.json"))?;
            plan_remove_hooks(&mut plan, &agy.join("hooks.json"), "agy")?;
            plan_remove_rules(&mut plan, &agy.join("AGENTS.md"))?;
        }
        if targets.codex {
            plan_rules(&mut plan, &codex.join("AGENTS.md"), true)?;
        } else {
            plan_remove_rules(&mut plan, &codex.join("AGENTS.md"))?;
        }
    }

    if repo.is_some() {
        plan_rules(&mut plan, &agy.join("AGENTS.md"), false)?;
    }

    if let Some((distro, win_dirs)) = detect_wsl_windows_gemini_dirs(wsl_bridge) {
        for win_gemini in win_dirs {
            if targets.agy || repo.is_some() {
                plan_wsl_windows_bridge(&mut plan, &win_gemini, &distro, bin, eager)?;
            } else {
                plan_remove_wsl_windows_bridge(&mut plan, &win_gemini)?;
            }
        }
    }

    if repo.is_some() || targets.codex {
        let cfg = codex.join("config.toml");
        let current = plan.text(&cfg)?.unwrap_or_default();
        let desired = upsert_codex_toml_mcp_and_hooks(&current, bin)?;
        plan.set(&cfg, desired.into_bytes(), None)?;
        plan_hooks(&mut plan, &codex.join("hooks.json"), bin, "codex", guard_cmd.as_deref())?;
    } else {
        plan_remove_codex_toml(&mut plan, &codex.join("config.toml"))?;
        plan_remove_hooks(&mut plan, &codex.join("hooks.json"), "codex")?;
    }

    if repo.is_some() || targets.claude {
        plan_hooks(&mut plan, &home.join(".claude/settings.json"), bin, "claude", None)?;
        plan_mcp(&mut plan, &home.join(".claude.json"), bin, true, None)?;
    } else {
        plan_remove_hooks(&mut plan, &home.join(".claude/settings.json"), "claude")?;
        plan_remove_mcp(&mut plan, &home.join(".claude.json"))?;
    }
    Ok(plan)
}

pub fn run_install_cli(args: &[String]) -> i32 {
    let mut cxet_mode = false;
    let mut check_only = false;
    let mut interactive = false;
    let mut wsl_bridge = true;
    let mut explicit_targets: Option<TargetSet> = None;
    let mut explicit_eager: Option<EagerMode> = None;
    let mut explicit_root: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cxet" => cxet_mode = true,
            "--check" => check_only = true,
            "--interactive" | "-i" => interactive = true,
            "--no-wsl-bridge" => wsl_bridge = false,
            "--all" => explicit_targets = Some(TargetSet::all()),
            "--targets" if i + 1 < args.len() => {
                i += 1;
                match TargetSet::parse_csv(&args[i]) {
                    Ok(t) => explicit_targets = Some(t),
                    Err(e) => { eprintln!("ctx install error: {e}"); return 1; }
                }
            }
            arg if arg.starts_with("--targets=") => {
                match TargetSet::parse_csv(&arg["--targets=".len()..]) {
                    Ok(t) => explicit_targets = Some(t),
                    Err(e) => { eprintln!("ctx install error: {e}"); return 1; }
                }
            }
            "--eager" if i + 1 < args.len() => {
                i += 1;
                match EagerMode::parse(&args[i]) {
                    Ok(m) => explicit_eager = Some(m),
                    Err(e) => { eprintln!("ctx install error: {e}"); return 1; }
                }
            }
            arg if arg.starts_with("--eager=") => {
                match EagerMode::parse(&arg["--eager=".len()..]) {
                    Ok(m) => explicit_eager = Some(m),
                    Err(e) => { eprintln!("ctx install error: {e}"); return 1; }
                }
            }
            "--root" if i + 1 < args.len() => {
                i += 1;
                explicit_root = Some(PathBuf::from(&args[i]));
            }
            arg => { eprintln!("ctx install: invalid argument {}", arg); return 1; }
        }
        i += 1;
    }

    let home = match effective_home_dir() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ctx install error: {}", e);
            return 1;
        }
    };
    let codex_home = effective_codex_home(&home);
    let ctx_bin = target_ctx_bin(&home);
    let saved_targets = load_saved_targets(&ctx_bin);
    let saved_eager = load_saved_eager(&ctx_bin);
    let eager_mode = explicit_eager.or(saved_eager).unwrap_or(EagerMode::Core);
    let eager_spec = (eager_mode, explicit_eager.is_some());

    let targets = if cxet_mode {
        TargetSet::all()
    } else if let Some(t) = explicit_targets {
        t
    } else if interactive && !check_only {
        match prompt_targets_interactive(&home, &codex_home) {
            Ok(Some(chosen)) => chosen,
            Ok(None) => {
                println!("ctx setup: cancelled (no changes written)");
                return 0;
            }
            Err(e) => {
                eprintln!("ctx setup error: {e}");
                return 1;
            }
        }
    } else {
        saved_targets.unwrap_or_else(TargetSet::agy_only)
    };

    if targets.is_empty() && !check_only {
        println!("ctx setup: no harnesses selected (run `ctx uninstall` to remove existing installation)");
        return 0;
    }

    let repo = if cxet_mode {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Some(explicit_root.or_else(|| find_superproject_root(&cwd)).unwrap_or(cwd))
    } else { None };
    let plan = match prepare_install(
        &home,
        &codex_home,
        &ctx_bin,
        repo.as_deref(),
        targets,
        eager_spec,
        wsl_bridge,
    ) {
        Ok(p) => p,
        Err(e) => { eprintln!("ctx install error: {}", e); return 1; }
    };
    let stale: Vec<_> = plan.0.iter().filter(|t| t.changed()).map(|t| t.path.display()).collect();
    if check_only {
        if stale.is_empty() {
            println!("ctx install --check: OK (ctx={})", ctx_bin.display());
            return 0;
        }
        for item in &stale {
            eprintln!("ctx install --check: stale {}", item);
        }
        return 1;
    }

    if let Err(e) = plan.apply(&ctx_bin) { eprintln!("ctx install error: {}", e); return 1; }
    write_targets_stamp(&ctx_bin, targets, eager_mode);
    #[cfg(windows)]
    if std::env::var("AGENT_CTX_HOME").is_err() {
        if let Some(dir) = ctx_bin.parent() { ensure_windows_user_path(dir); }
    }
    println!(
        "ctx install{}: OK (binary={}, targets={}, eager={}, updated {} file(s))",
        if cxet_mode { " --cxet" } else { "" },
        ctx_bin.display(),
        targets.summary(),
        eager_mode.as_str(),
        stale.len()
    );
    0
}

pub fn run_uninstall_cli(args: &[String]) -> i32 {
    let mut explicit_targets: Option<TargetSet> = None;
    let mut keep_binary = false;
    let mut wsl_bridge = true;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--all" => explicit_targets = Some(TargetSet::all()),
            "--keep-binary" => keep_binary = true,
            "--no-wsl-bridge" => wsl_bridge = false,
            "--targets" if i + 1 < args.len() => {
                i += 1;
                match TargetSet::parse_csv(&args[i]) {
                    Ok(t) => explicit_targets = Some(t),
                    Err(e) => { eprintln!("ctx uninstall error: {e}"); return 1; }
                }
            }
            arg if arg.starts_with("--targets=") => {
                match TargetSet::parse_csv(&arg["--targets=".len()..]) {
                    Ok(t) => explicit_targets = Some(t),
                    Err(e) => { eprintln!("ctx uninstall error: {e}"); return 1; }
                }
            }
            arg => { eprintln!("ctx uninstall: invalid argument {arg}"); return 1; }
        }
        i += 1;
    }

    let home = match effective_home_dir() {
        Ok(h) => h,
        Err(e) => { eprintln!("ctx uninstall error: {e}"); return 1; }
    };
    let codex_home = effective_codex_home(&home);
    let ctx_bin = target_ctx_bin(&home);
    let remove_set = explicit_targets.unwrap_or_else(TargetSet::all);
    let partial = explicit_targets.is_some() && !remove_set.is_all();

    let mut plan = InstallPlan::default();
    let agy = home.join(".gemini/config");
    let res = (|| -> Result<(), String> {
        if remove_set.agy {
            plan_remove_mcp(&mut plan, &agy.join("mcp_config.json"))?;
            plan_remove_hooks(&mut plan, &agy.join("hooks.json"), "agy")?;
            plan_remove_rules(&mut plan, &agy.join("AGENTS.md"))?;
            if let Some((_distro, win_dirs)) = detect_wsl_windows_gemini_dirs(wsl_bridge) {
                for win_gemini in win_dirs {
                    plan_remove_wsl_windows_bridge(&mut plan, &win_gemini)?;
                }
            }
        }
        if remove_set.codex {
            plan_remove_codex_toml(&mut plan, &codex_home.join("config.toml"))?;
            plan_remove_hooks(&mut plan, &codex_home.join("hooks.json"), "codex")?;
            plan_remove_rules(&mut plan, &codex_home.join("AGENTS.md"))?;
        }
        if remove_set.claude {
            plan_remove_hooks(&mut plan, &home.join(".claude/settings.json"), "claude")?;
            plan_remove_mcp(&mut plan, &home.join(".claude.json"))?;
        }
        plan.apply(&ctx_bin)
    })();
    if let Err(e) = res {
        eprintln!("ctx uninstall error: {e}");
        return 1;
    }

    let t_stamp = targets_stamp_path(&ctx_bin);
    if partial || keep_binary {
        let prev = load_saved_targets(&ctx_bin).unwrap_or_else(TargetSet::agy_only);
        let eager = load_saved_eager(&ctx_bin).unwrap_or(EagerMode::Core);
        let remaining = TargetSet {
            agy: prev.agy && !remove_set.agy,
            claude: prev.claude && !remove_set.claude,
            codex: prev.codex && !remove_set.codex,
        };
        write_targets_stamp(&ctx_bin, remaining, eager);
        println!("ctx uninstall: detached from {} (binary retained at {})", remove_set.summary(), ctx_bin.display());
    } else {
        let _ = stop_daemon_for_install();
        let _ = fs::remove_file(&ctx_bin);
        let _ = fs::remove_file(ctx_bin.with_file_name(".ctx.sha256"));
        let _ = fs::remove_file(&t_stamp);
        if let Some(cache_dir) = default_snapshot_path().parent() {
            let _ = fs::remove_dir_all(cache_dir);
        }
        let _ = fs::remove_dir_all(runtime_dir());
        println!("ctx uninstall: OK (removed binary, daemon state, and global configs for {})", remove_set.summary());
    }
    0
}

pub fn run_doctor_cli(args: &[String]) -> i32 {
    let as_json = args.iter().any(|a| a == "--json");
    let mut checks: Vec<Json> = Vec::new();
    let mut all_ok = true;

    let mut record = |name: &str, ok: bool, detail: String| {
        if !ok {
            all_ok = false;
        }
        checks.push(Json::obj(vec![
            ("check", Json::Str(name.to_string())),
            ("ok", Json::Bool(ok)),
            ("detail", Json::Str(detail)),
        ]));
    };

    // 1. Binary check
    if let Ok(home) = effective_home_dir() {
        let bin = target_ctx_bin(&home);
        if bin.is_file() {
            record("binary", true, format!("installed at {}", bin.display()));
        } else if let Ok(cur) = std::env::current_exe() {
            record(
                "binary",
                true,
                format!("running from {} (run `ctx install` to place in ~/.local/bin)", cur.display()),
            );
        } else {
            record("binary", false, "ctx binary not found".to_string());
        }
    }

    // 2. Daemon IPC + `0600` `daemon.json`
    let status_reply = call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("status".to_string()))]));
    let d_path = daemon_info_path();
    let inproc_forced = std::env::var("AGENT_CTX_INPROC").as_deref() == Ok("1");
    if status_reply.get_bool("ok") == Some(true) {
        if d_path.is_file() {
            let mut perm_ok = true;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(m) = fs::metadata(&d_path) {
                    perm_ok = (m.permissions().mode() & 0o077) == 0;
                }
            }
            let pid_info = read_daemon_info()
                .map(|i| format!("pid={}, port={}", i.pid, i.port))
                .unwrap_or_else(|| "active".to_string());
            record(
                "daemon_ipc",
                perm_ok,
                format!(
                    "daemon reachable ({}, {}, 0600={})",
                    pid_info,
                    d_path.display(),
                    perm_ok
                ),
            );
        } else {
            record(
                "daemon_ipc",
                inproc_forced,
                "responded via stateless inproc fallback".to_string(),
            );
        }
    } else {
        record("daemon_ipc", false, "status RPC failed".to_string());
    }

    // 3. Metadata-only `ACTXSNP2` `0600` `snapshot.bin`
    let _ = call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("save_snapshot".to_string()))]));
    let snap_path = default_snapshot_path();
    if snap_path.is_file() {
        match verify_snapshot_metadata_only(&snap_path) {
            Ok((cnt, bytes)) => record(
                "snapshot_security",
                true,
                format!(
                    "ACTXSNP2 metadata-only verified ({} entries, {} bytes, 0600, 0 raw source)",
                    cnt, bytes
                ),
            ),
            Err(e) => record("snapshot_security", false, e),
        }
    } else {
        record(
            "snapshot_security",
            false,
            format!("snapshot file missing at {}", snap_path.display()),
        );
    }

    // 4. The running binary's MCP protocol and exact tool inventory.
    match check_mcp_protocol(None) {
        Ok(count) => record("mcp_protocol", true, format!("tools/list matches catalog ({count} tools)")),
        Err(error) => record("mcp_protocol", false, error),
    }

    // 5. Per-agent isolation self-test (`codex:s1:agentA` vs `codex:s1:agentB`)
    {
        let tmp_dir = std::env::temp_dir().join(format!("ctx-doc-iso-{}", std::process::id()));
        let _ = fs::create_dir_all(tmp_dir.join(".git"));
        let sample = tmp_dir.join("IsoCheck.hpp");
        let _ = fs::write(&sample, "struct IsoCheck { int x = 1; };\n");
        let svc = BrokerService::new(tmp_dir.join("snap.bin"));

        let post_a = Json::obj(vec![
            ("op", Json::Str("hook".to_string())),
            ("flavor", Json::Str("claude".to_string())),
            (
                "payload",
                Json::Str(
                    Json::obj(vec![
                        ("hook_event_name", Json::Str("PostToolUse".to_string())),
                        ("session_id", Json::Str("shared-sess".to_string())),
                        ("agent_id", Json::Str("agent-A".to_string())),
                        ("cwd", Json::Str(tmp_dir.to_string_lossy().into_owned())),
                        ("tool_name", Json::Str("Read".to_string())),
                        (
                            "tool_input",
                            Json::obj(vec![(
                                "file_path",
                                Json::Str(sample.to_string_lossy().into_owned()),
                            )]),
                        ),
                    ])
                    .to_json_string(),
                ),
            ),
        ]);
        let _ = execute_request(&svc, &post_a);

        let pre_b = Json::obj(vec![
            ("op", Json::Str("hook".to_string())),
            ("flavor", Json::Str("claude".to_string())),
            (
                "payload",
                Json::Str(
                    Json::obj(vec![
                        ("hook_event_name", Json::Str("PreToolUse".to_string())),
                        ("session_id", Json::Str("shared-sess".to_string())),
                        ("agent_id", Json::Str("agent-B".to_string())),
                        ("cwd", Json::Str(tmp_dir.to_string_lossy().into_owned())),
                        ("tool_name", Json::Str("Read".to_string())),
                        (
                            "tool_input",
                            Json::obj(vec![(
                                "file_path",
                                Json::Str(sample.to_string_lossy().into_owned()),
                            )]),
                        ),
                    ])
                    .to_json_string(),
                ),
            ),
        ]);
        let rep_b = execute_request(&svc, &pre_b);
        let hr_b = rep_b.get("hook_reply").cloned().unwrap_or(Json::Null);
        let iso_ok = hr_b == Json::Obj(Vec::new());
        let _ = fs::remove_dir_all(&tmp_dir);
        record(
            "agent_isolation",
            iso_ok,
            "sibling subagents sharing session_id have isolated read histories".to_string(),
        );
    }

    // 6. Global configs check (respects selective harness installation in `.ctx.targets.json`)
    if let Ok(home) = effective_home_dir() {
        let selected = load_saved_targets(&target_ctx_bin(&home)).unwrap_or_else(TargetSet::agy_only);
        let agy_cfg_dir = home.join(".gemini").join("config");
        let (agy_ok, agy_detail) = check_agy_config_dir(&agy_cfg_dir);
        let codex_home = effective_codex_home(&home);
        let cx_ok = codex_home.join("config.toml").is_file()
            && codex_home.join("hooks.json").is_file();
        let cl_ok = home.join(".claude").join("settings.json").is_file()
            && home.join(".claude.json").is_file();
        let fmt_slot = |enabled: bool, present: bool| {
            if !enabled {
                "skipped"
            } else if present {
                "true"
            } else {
                "false"
            }
        };
        let required_ok = (!selected.agy || agy_ok)
            && (!selected.codex || cx_ok)
            && (!selected.claude || cl_ok);
        record(
            "global_configs",
            required_ok,
            format!(
                "antigravity={}, codex={}, claude={}",
                fmt_slot(selected.agy, agy_ok),
                fmt_slot(selected.codex, cx_ok),
                fmt_slot(selected.claude, cl_ok)
            ),
        );
        if selected.agy {
            record("antigravity_mcp", agy_ok, agy_detail);
            if let Some((_distro, win_dirs)) = detect_wsl_windows_gemini_dirs(true) {
                for win_gemini in win_dirs {
                    let (w_ok, w_detail) = check_agy_config_dir(&win_gemini.join("config"));
                    record("wsl_windows_bridge", w_ok, w_detail);
                }
            }
        }

        // Codex layers are checked when Codex is selected (or when `[mcp_servers.agent_ctx]` is present).
        let expected = expected_tool_names();
        let global_codex_toml = codex_home.join("config.toml");
        let global_has_table = fs::read_to_string(&global_codex_toml)
            .is_ok_and(|s| s.contains("mcp_servers.agent_ctx"));
        if selected.codex || global_has_table {
            let (ok, detail) = check_codex_tool_config(&global_codex_toml, &expected);
            record("codex_global_mcp_tools", ok, detail);
        }
        if let Some(path) = std::env::current_dir()
            .ok()
            .and_then(|cwd| find_superproject_root(&cwd))
            .map(|root| root.join(".codex/config.toml"))
            .filter(|path| path.exists())
        {
            let proj_has_table = fs::read_to_string(&path)
                .is_ok_and(|s| s.contains("mcp_servers.agent_ctx"));
            if selected.codex || proj_has_table {
                let (ok, detail) = check_codex_tool_config(&path, &expected);
                record("codex_project_mcp_tools", ok, detail);
            }
        }
    }

    if as_json {
        let report = Json::obj(vec![
            ("ok", Json::Bool(all_ok)),
            ("checks", Json::Arr(checks)),
        ]);
        println!("{}", report.to_json_string());
    } else {
        println!("ctx doctor: {}", if all_ok { "OK" } else { "ISSUES DETECTED" });
        for c in &checks {
            let mark = if c.get_bool("ok") == Some(true) {
                "[OK]  "
            } else {
                "[FAIL]"
            };
            println!(
                "  {} {:<18} {}",
                mark,
                c.get_str("check").unwrap_or(""),
                c.get_str("detail").unwrap_or("")
            );
        }
    }
    if all_ok {
        0
    } else {
        1
    }
}
