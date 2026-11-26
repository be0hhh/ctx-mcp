//! Safe Codex `config.toml` parser, MCP server upsert/removal, and tool-filter checker.

use super::configs::executable_name;
use super::plan::InstallPlan;
use crate::base::json::{self, Json};
use std::fs;
use std::path::Path;

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
                if q == b'"' && b == b'\\' {
                    i += 2;
                    continue;
                }
                if triple && bytes.get(i..i + 3) == Some(&[q; 3]) {
                    quoted = None;
                    i += 3;
                    continue;
                }
                if !triple && b == q {
                    quoted = None;
                }
                if !triple && b == b'\n' {
                    return Err("unterminated TOML string".into());
                }
            } else {
                match b {
                    b'#' => break,
                    b'\'' | b'"' => {
                        let triple = bytes.get(i..i + 3) == Some(&[b; 3]);
                        quoted = Some((b, triple));
                        if triple {
                            i += 2;
                        }
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
    if start != text.len() {
        return Err("unterminated TOML value".into());
    }
    Ok(records)
}

fn toml_value(text: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            if q == '"' && ch == '\\' {
                escaped = true;
            }
            if ch == q {
                quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch == '#' {
            return text[..index].trim();
        }
    }
    text.trim()
}

fn toml_table_name(header: &str) -> Result<String, String> {
    let table = header
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .ok_or("invalid TOML table")?;
    // Unquote simple segments without collapsing a quoted key containing literal dots.
    Ok(table
        .split('.')
        .map(|key| {
            let k = key.trim();
            k.strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| k.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(k)
        })
        .collect::<Vec<_>>()
        .join("."))
}

fn toml_tool_names(raw: &str) -> Result<Vec<String>, String> {
    let value = raw.lines().map(toml_value).collect::<Vec<_>>().join(" ");
    let items = value
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or("expected an array of tool names")?
        .trim();
    items
        .split_terminator(',')
        .map(|item| {
            let item = item.trim();
            if let Some(literal) = item.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
                return Ok(literal.to_owned());
            }
            json::parse(item)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| "expected a quoted tool name".to_owned())
        })
        .collect()
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
                "enabled" if enabled.is_none() => {
                    enabled = Some(match toml_value(value) {
                        "true" => true,
                        "false" => false,
                        _ => return Err("expected boolean in enabled".into()),
                    })
                }
                "enabled_tools" if allow.is_none() => {
                    allow = Some(
                        toml_tool_names(value)
                            .map_err(|error| format!("enabled_tools: {error}"))?,
                    )
                }
                "disabled_tools" if deny.is_none() => {
                    deny = Some(
                        toml_tool_names(value)
                            .map_err(|error| format!("disabled_tools: {error}"))?,
                    )
                }
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
    let excluded: Vec<_> = expected
        .iter()
        .filter(|name| {
            allow.as_ref().is_some_and(|tools| !tools.contains(name))
                || deny.as_ref().is_some_and(|tools| tools.contains(name))
        })
        .map(String::as_str)
        .collect();
    if !excluded.is_empty() {
        return Err(format!(
            "enabled_tools/disabled_tools exclude: {}",
            excluded.join(", ")
        ));
    }
    Ok(expected.len())
}

pub(super) fn check_codex_tool_config(path: &Path, expected: &[String]) -> (bool, String) {
    let result = fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|raw| codex_tool_config(&raw, expected));
    let (ok, detail) = match result {
        Ok(count) => (true, format!("config permits {count} catalog tools")),
        Err(error) => (false, error),
    };
    (ok, format!("{}: {detail}; host exposure unverified", path.display()))
}

pub(super) fn upsert_codex_toml_mcp_and_hooks(raw: &str, bin: &Path) -> Result<String, String> {
    let nl = if raw.contains("\r\n") { "\r\n" } else { "\n" };
    let command = Json::Str(bin.to_string_lossy().into_owned()).to_json_string();
    let managed = [
        ("command", command.as_str()),
        ("args", "[\"mcp\"]"),
        ("startup_timeout_sec", "10"),
        ("tool_timeout_sec", "30"),
        ("enabled", "true"),
        ("default_tools_approval_mode", "\"auto\""),
    ];
    let sections = ["features", "mcp_servers.agent_ctx"];
    let records = toml_records(raw)?;
    let mut out = String::new();
    let mut found = [false; 2];
    let mut preamble = true;
    let mut i = 0;
    while i < records.len() {
        let header = toml_value(records[i]);
        if !header.starts_with('[') {
            if !header.is_empty() && !header.contains('=') {
                return Err("invalid TOML assignment".into());
            }
            if let Some((key, _)) = header.split_once('=') {
                let key = key.trim().trim_matches(['"', '\'']);
                if preamble
                    && (key == "mcp_servers"
                        || key == "features"
                        || key.starts_with("mcp_servers.")
                        || key.starts_with("features."))
                {
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
            out.push_str(records[i]);
            i += 1;
            continue;
        };
        if found[idx] {
            return Err(format!("duplicate TOML table {table}"));
        }
        found[idx] = true;
        let mut end = i + 1;
        while end < records.len() && !toml_value(records[end]).starts_with('[') {
            end += 1;
        }
        let keys: &[(&str, &str)] = if idx == 0 {
            &[("hooks", "true")]
        } else {
            &managed
        };
        let mut present = vec![];
        let mut old_command = None;
        let mut old_args = None;
        let mut body = String::new();
        for line in &records[i + 1..end] {
            let value = toml_value(line);
            if value.is_empty() {
                body.push_str(line);
                continue;
            }
            let (key, val) = value.split_once('=').ok_or("invalid TOML assignment")?;
            let key = key.trim().trim_matches(['"', '\'']);
            let val = val.trim();
            if key == "command" {
                old_command = Some(val);
            }
            if key == "args" {
                old_args = Some(val);
            }
            if idx == 1 && key == "cwd" {
                continue;
            }
            if let Some((key, desired)) = keys.iter().find(|(k, _)| *k == key) {
                if present.contains(key) {
                    return Err(format!("duplicate TOML key {key}"));
                }
                present.push(*key);
                if val == *desired || (idx == 1 && !matches!(*key, "command" | "args")) {
                    body.push_str(line);
                } else {
                    if line.trim_end().contains('\n') {
                        body.push_str(&format!("{key} = {desired}{nl}"));
                        continue;
                    }
                    let pos = line.find('=').unwrap() + 1;
                    let trailing = line[pos..]
                        .find(val)
                        .ok_or("ambiguous TOML value")?
                        + pos
                        + val.len();
                    body.push_str(&line[..pos]);
                    body.push(' ');
                    body.push_str(desired);
                    body.push_str(&line[trailing..]);
                }
            } else {
                body.push_str(line);
            }
        }
        if idx == 1 {
            let exe = old_command
                .and_then(|s| json::parse(s).ok())
                .and_then(|v| v.as_str().map(str::to_owned))
                .or_else(|| {
                    old_command
                        .and_then(|s| s.strip_prefix('\'')?.strip_suffix('\''))
                        .map(str::to_owned)
                })
                .ok_or("MCP server has no recognized command")?;
            let exe = executable_name(&exe);
            let args = old_args.unwrap_or("");
            let owned = matches!(exe, "ctx" | "ctx.exe")
                && (args.contains("\"mcp\"") || args.contains("'mcp'"));
            if !owned {
                return Err(format!("unmanaged MCP server in {table}"));
            }
        }
        out.push_str(records[i]);
        if !out.ends_with('\n') {
            out.push_str(nl);
        }
        out.push_str(&body);
        for &(key, value) in keys {
            if !present.contains(&key) {
                if !out.ends_with('\n') {
                    out.push_str(nl);
                }
                out.push_str(&format!("{key} = {value}{nl}"));
            }
        }
        i = end;
    }
    for (idx, keys) in [(0usize, &[("hooks", "true")][..]), (1, &managed[..])] {
        if !found[idx] {
            if !out.is_empty() {
                if !out.ends_with('\n') {
                    out.push_str(nl);
                }
                out.push_str(nl);
            }
            out.push_str(&format!("[{}]{nl}", sections[idx]));
            for &(key, val) in keys {
                out.push_str(&format!("{key} = {val}{nl}"));
            }
        }
    }
    Ok(out)
}

pub(super) fn plan_remove_codex_toml(plan: &mut InstallPlan, path: &Path) -> Result<(), String> {
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
            if table == "mcp_servers.agent_ctx" {
                let mut end = i + 1;
                while end < records.len() && !toml_value(records[end]).starts_with('[') {
                    end += 1;
                }
                let mut owned = false;
                for rec in &records[i + 1..end] {
                    let line = toml_value(rec);
                    if let Some((k, v)) = line.split_once('=') {
                        if k.trim().trim_matches(['"', '\'']) == "command" {
                            let val = v.trim();
                            let cmd = json::parse(val)
                                .ok()
                                .and_then(|j| j.as_str().map(str::to_owned))
                                .or_else(|| {
                                    val.strip_prefix('\'')
                                        .and_then(|s| s.strip_suffix('\''))
                                        .map(str::to_owned)
                                });
                            if let Some(cmd) = cmd {
                                owned = matches!(executable_name(&cmd), "ctx" | "ctx.exe");
                            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_toml_upsert_preserves_custom_settings_and_rejects_foreign_agent_ctx() {
        let raw = "[mcp_servers.agent_ctx]\ncommand = \"ctx\"\nargs = [\"mcp\"]\ntool_timeout_sec = 77\n";
        let updated = upsert_codex_toml_mcp_and_hooks(raw, Path::new("/opt/bin/ctx"))
            .expect("upsert codex toml");
        assert!(updated.contains("command = \"/opt/bin/ctx\""));
        assert!(updated.contains("tool_timeout_sec = 77"));
        assert!(updated.contains("[features]\nhooks = true\n"));

        let foreign = "[mcp_servers.agent_ctx]\ncommand = \"python3\"\nargs = [\"other.py\"]\n";
        let err = upsert_codex_toml_mcp_and_hooks(foreign, Path::new("/opt/bin/ctx"))
            .expect_err("must reject unmanaged agent_ctx");
        assert!(err.contains("unmanaged MCP server"));
    }
}
