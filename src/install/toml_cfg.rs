//! Safe Codex `config.toml` parser, MCP server upsert/removal, and tool-filter checker.

use super::configs::executable_name;
use super::plan::InstallPlan;
use crate::base::json::{self, Json};
use std::fs;
use std::path::Path;

const WRITE_TOOL_NAMES: &[&str] = &["ctx_edit"];

fn is_write_tool(name: &str) -> bool {
    WRITE_TOOL_NAMES.contains(&name)
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

fn codex_tool_config_for_mode(
    raw: &str,
    expected: &[String],
    write_enabled: bool,
) -> Result<(usize, bool), String> {
    match codex_tool_config(raw, expected) {
        Ok(count) => Ok((count, false)),
        Err(full_err) if !write_enabled => {
            let ro_expected: Vec<String> = expected
                .iter()
                .filter(|name| !is_write_tool(name))
                .cloned()
                .collect();
            if ro_expected.len() == expected.len() {
                return Err(full_err);
            }
            codex_tool_config(raw, &ro_expected).map(|count| (count, true))
        }
        Err(err) => Err(err),
    }
}

pub(super) fn check_codex_tool_config(
    path: &Path,
    expected: &[String],
    write_enabled: bool,
) -> (bool, String) {
    let result = fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|raw| codex_tool_config_for_mode(&raw, expected, write_enabled));
    let (ok, detail) = match result {
        Ok((count, false)) => (true, format!("config permits {count} catalog tools")),
        Ok((count, true)) => (
            true,
            format!("config permits {count} read-only catalog tools (write disabled)"),
        ),
        Err(error) => (false, error),
    };
    (ok, format!("{}: {detail}; host exposure unverified", path.display()))
}

fn table_end(records: &[&str], start: usize) -> usize {
    let mut end = start + 1;
    while end < records.len() && !toml_value(records[end]).starts_with('[') {
        end += 1;
    }
    end
}

fn parse_toml_string(val: &str) -> Option<String> {
    json::parse(val)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .or_else(|| val.strip_prefix('\'')?.strip_suffix('\'').map(str::to_owned))
}

fn push_section_sep(out: &mut String, nl: &str) {
    if !out.is_empty() {
        if !out.ends_with('\n') {
            out.push_str(nl);
        }
        out.push_str(nl);
    }
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
        let end = table_end(&records, i);
        let keys: &[(&str, &str)] = if idx == 0 { &[("hooks", "true")] } else { &managed };
        let (mut present, mut old_command, mut old_args, mut body) = (vec![], None, None, String::new());
        for line in &records[i + 1..end] {
            let value = toml_value(line);
            if value.is_empty() {
                body.push_str(line);
                continue;
            }
            let (key, val) = value.split_once('=').ok_or("invalid TOML assignment")?;
            let (key, val) = (key.trim().trim_matches(['"', '\'']), val.trim());
            if key == "command" { old_command = Some(val); }
            if key == "args" { old_args = Some(val); }
            if idx == 1 && key == "cwd" { continue; }
            if let Some((key, desired)) = keys.iter().find(|(k, _)| *k == key) {
                if present.contains(key) {
                    return Err(format!("duplicate TOML key {key}"));
                }
                present.push(*key);
                if val == *desired || (idx == 1 && !matches!(*key, "command" | "args")) {
                    body.push_str(line);
                } else if line.trim_end().contains('\n') {
                    body.push_str(&format!("{key} = {desired}{nl}"));
                } else {
                    let pos = line.find('=').ok_or("malformed TOML assignment")? + 1;
                    let trailing = line[pos..].find(val).ok_or("ambiguous TOML value")? + pos + val.len();
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
            let exe = old_command.and_then(parse_toml_string).ok_or("MCP server has no recognized command")?;
            let args = old_args.unwrap_or("");
            if !(matches!(executable_name(&exe), "ctx" | "ctx.exe") && (args.contains("\"mcp\"") || args.contains("'mcp'"))) {
                return Err(format!("unmanaged MCP server in {table}"));
            }
        }
        out.push_str(records[i]);
        if !out.ends_with('\n') { out.push_str(nl); }
        out.push_str(&body);
        for &(key, value) in keys {
            if !present.contains(&key) {
                if !out.ends_with('\n') { out.push_str(nl); }
                out.push_str(&format!("{key} = {value}{nl}"));
            }
        }
        i = end;
    }
    for (idx, keys) in [(0usize, &[("hooks", "true")][..]), (1, &managed[..])] {
        if !found[idx] {
            push_section_sep(&mut out, nl);
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
    let mut owned = false;
    for (idx, rec) in records.iter().enumerate() {
        let header = toml_value(rec);
        if header.starts_with('[') && toml_table_name(header)? == "mcp_servers.agent_ctx" {
            for line in &records[idx + 1..table_end(&records, idx)] {
                if let Some((k, v)) = toml_value(line).split_once('=') {
                    if k.trim().trim_matches(['"', '\'']) == "command" {
                        owned = parse_toml_string(v.trim()).is_some_and(|c| matches!(executable_name(&c), "ctx" | "ctx.exe"));
                    }
                }
            }
            break;
        }
    }
    if !owned {
        return Ok(());
    }
    let (mut out, mut changed, mut i) = (String::new(), false, 0);
    while i < records.len() {
        let header = toml_value(records[i]);
        if header.starts_with('[') {
            let table = toml_table_name(header)?;
            if table == "mcp_servers.agent_ctx" || table.starts_with("mcp_servers.agent_ctx.") {
                changed = true;
                i = table_end(&records, i);
                continue;
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

    #[test]
    fn codex_toml_auto_approval_preserves_manual_tool_tables_and_mode_check() {
        let initial = upsert_codex_toml_mcp_and_hooks("", Path::new("/opt/bin/ctx"))
            .expect("fresh upsert");
        assert!(initial.contains("default_tools_approval_mode = \"auto\""));
        assert!(!initial.contains("approval_mode = \"approve\""));
        assert!(!initial.contains("[mcp_servers.agent_ctx.tools."));

        // Idempotent second upsert produces byte-identical output.
        let second = upsert_codex_toml_mcp_and_hooks(&initial, Path::new("/opt/bin/ctx"))
            .expect("idempotent upsert");
        assert_eq!(initial, second);

        // Manual `[mcp_servers.agent_ctx.tools.ctx_edit]` overrides are preserved verbatim.
        for mode in ["prompt", "approve"] {
            let manual_block = format!(
                "\n[mcp_servers.agent_ctx.tools.ctx_edit]\napproval_mode = \"{mode}\"\n"
            );
            let custom = format!("{initial}{manual_block}");
            let kept = upsert_codex_toml_mcp_and_hooks(&custom, Path::new("/opt/bin/ctx"))
                .expect("preserve manual tool table");
            assert_eq!(kept, custom);
        }

        // Mode-aware check accepts full catalog in both modes, and read-only subset when write=false.
        let full = vec!["ctx_search".to_string(), "ctx_read".to_string(), "ctx_edit".to_string()];
        assert_eq!(codex_tool_config_for_mode(&initial, &full, true), Ok((3, false)));
        assert_eq!(codex_tool_config_for_mode(&initial, &full, false), Ok((3, false)));

        let ro_only = "[mcp_servers.agent_ctx]\ncommand = \"ctx\"\nargs = [\"mcp\"]\ndisabled_tools = [\"ctx_edit\"]\n";
        assert!(codex_tool_config_for_mode(ro_only, &full, true).is_err());
        assert_eq!(codex_tool_config_for_mode(ro_only, &full, false), Ok((2, true)));

        let missing_ro = "[mcp_servers.agent_ctx]\ncommand = \"ctx\"\nargs = [\"mcp\"]\ndisabled_tools = [\"ctx_read\"]\n";
        assert!(codex_tool_config_for_mode(missing_ro, &full, false).is_err());
    }
}
