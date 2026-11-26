//! `ctx doctor [--json]` — verifies binary placement, live daemon IPC, `0600` runtime
//! and snapshot permissions, `ACTXSNP2` metadata-only integrity, MCP tool catalog,
//! per-agent isolation, and configured harness files.

use super::configs::{
    check_agy_config_dir, check_codex_tool_config, detect_wsl_windows_gemini_dirs, TargetSet,
};
use super::update;
use super::{effective_codex_home, effective_home_dir, load_saved_targets, target_ctx_bin};
use crate::base::ext;
use crate::base::json::Json;
use crate::base::mode;
use crate::base::security::find_superproject_root;
use crate::mcp::{check_mcp_protocol, expected_tool_names};
use crate::rpc::{
    call_daemon_or_inproc, daemon_info_path, execute_request, read_daemon_info, BrokerService,
};
use crate::store::{default_snapshot_path, verify_snapshot_metadata_only};
use std::fs;

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

    let flavor = ext::policy().build_flavor();
    let write_mode = mode::current_write_mode(None);
    let update_status = update::update_status_json();

    // 1. Binary, build flavor, write mode, and cached update status
    if let Ok(home) = effective_home_dir() {
        let bin = target_ctx_bin(&home);
        if bin.is_file() {
            record("binary", true, format!("installed at {}", bin.display()));
        } else if let Ok(cur) = std::env::current_exe() {
            record(
                "binary",
                true,
                format!(
                    "running from {} (run `ctx install` to place in ~/.local/bin)",
                    cur.display()
                ),
            );
        } else {
            record("binary", false, "ctx binary not found".to_string());
        }
    }
    record(
        "build_flavor",
        true,
        format!("{} (v{})", flavor, update::CURRENT_VERSION),
    );
    record(
        "write_mode",
        true,
        format!(
            "{} (source={})",
            if write_mode.enabled { "write" } else { "read-only" },
            write_mode.source.as_str()
        ),
    );
    let update_detail = if update_status.get_bool("update_available") == Some(true) {
        let latest = update_status.get_str("latest").unwrap_or("unknown");
        let url = update_status.get_str("url").unwrap_or("");
        if flavor == "upstream" {
            format!(
                "update available: v{} -> {} ({}) — run `ctx update`",
                update::CURRENT_VERSION,
                latest,
                url
            )
        } else {
            let hint = ext::policy().update_hint().unwrap_or("local rebuild");
            format!(
                "upstream {} released ({}); local {} build active — {}",
                latest, url, flavor, hint
            )
        }
    } else if let Some(latest) = update_status.get_str("latest").filter(|s| !s.is_empty()) {
        format!(
            "up to date (current=v{}, latest={})",
            update::CURRENT_VERSION,
            latest
        )
    } else {
        format!(
            "no cached release check (current=v{}, run `ctx update --check`)",
            update::CURRENT_VERSION
        )
    };
    record("update_check", true, update_detail);

    // 2. Daemon IPC + `0600` `daemon.json`
    let status_reply =
        call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("status".to_string()))]));
    let d_path = daemon_info_path();
    let inproc_forced = std::env::var("AGENT_CTX_INPROC").as_deref() == Ok("1");
    if status_reply.get_bool("ok") == Some(true) {
        if d_path.is_file() {
            #[cfg(unix)]
            let perm_ok = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(&d_path)
                    .map(|m| (m.permissions().mode() & 0o077) == 0)
                    .unwrap_or(true)
            };
            #[cfg(not(unix))]
            let perm_ok = true;
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
    let _ = call_daemon_or_inproc(Json::obj(vec![(
        "op",
        Json::Str("save_snapshot".to_string()),
    )]));
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

    // 4. Running binary's MCP protocol and exact tool inventory.
    match check_mcp_protocol(None) {
        Ok(count) => record(
            "mcp_protocol",
            true,
            format!("tools/list matches catalog ({count} tools)"),
        ),
        Err(error) => record("mcp_protocol", false, error),
    }

    // 5. Per-agent isolation self-test (`shared-sess:agent-A` vs `shared-sess:agent-B`)
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
        let required_ok =
            (!selected.agy || agy_ok) && (!selected.codex || cx_ok) && (!selected.claude || cl_ok);
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
        let write_enabled = write_mode.enabled;
        let global_codex_toml = codex_home.join("config.toml");
        let global_has_table = fs::read_to_string(&global_codex_toml)
            .is_ok_and(|s| s.contains("mcp_servers.agent_ctx"));
        if selected.codex || global_has_table {
            let (ok, detail) =
                check_codex_tool_config(&global_codex_toml, &expected, write_enabled);
            record("codex_global_mcp_tools", ok, detail);
        }
        if let Some(path) = std::env::current_dir()
            .ok()
            .and_then(|cwd| find_superproject_root(&cwd))
            .map(|root| root.join(".codex/config.toml"))
            .filter(|path| path.exists())
        {
            let proj_has_table =
                fs::read_to_string(&path).is_ok_and(|s| s.contains("mcp_servers.agent_ctx"));
            if selected.codex || proj_has_table {
                let (ok, detail) = check_codex_tool_config(&path, &expected, write_enabled);
                record("codex_project_mcp_tools", ok, detail);
            }
        }
    }

    if as_json {
        let report = Json::obj(vec![
            ("ok", Json::Bool(all_ok)),
            ("build_flavor", Json::Str(flavor.to_string())),
            (
                "write_mode",
                Json::obj(vec![
                    ("enabled", Json::Bool(write_mode.enabled)),
                    (
                        "source",
                        Json::Str(write_mode.source.as_str().to_string()),
                    ),
                ]),
            ),
            ("update_check", update_status),
            ("checks", Json::Arr(checks)),
        ]);
        println!("{}", report.to_json_string());
    } else {
        println!(
            "ctx doctor: {}",
            if all_ok { "OK" } else { "ISSUES DETECTED" }
        );
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
    if all_ok { 0 } else { 1 }
}
