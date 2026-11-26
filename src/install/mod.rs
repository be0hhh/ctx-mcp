//! Built-in cross-platform `ctx install`, `ctx uninstall`, and `ctx doctor` commands:
//!   - `ctx install [--targets agy,claude,codex] [--all] [--eager core|search|all|none]
//!                  [--interactive|-i] [--no-wsl-bridge] [--no-codex-rules] [--check]`:
//!       Atomically installs `~/.local/bin/ctx(.exe)` (shutting down any running daemon first
//!       to avoid `ETXTBSY` / Windows file locks), creates `.bak` backups before modifying
//!       existing configs, adds `%USERPROFILE%\.local\bin` to Windows User `PATH` when needed,
//!       and configures global MCP + `agent-context` hooks across Antigravity, Codex, and Claude.
//!   - `ctx uninstall [--targets agy,claude,codex] [--all] [--keep-binary] [--no-wsl-bridge]`
//!   - `ctx doctor [--json]`

mod configs;
mod doctor;
mod plan;
mod toml_cfg;

pub use configs::{EagerMode, TargetSet};
pub use doctor::run_doctor_cli;

use configs::{
    detect_wsl_windows_gemini_dirs, plan_hooks, plan_mcp, plan_remove_codex_toml,
    plan_remove_hooks, plan_remove_mcp, plan_remove_rules, plan_remove_wsl_windows_bridge,
    plan_rules, plan_wsl_windows_bridge, upsert_codex_toml_mcp_and_hooks,
};
use plan::{plan_binary, InstallPlan};

use crate::base::json::{self, Json};
use crate::rpc::stop_daemon_for_install;
use crate::store::{default_snapshot_path, runtime_dir};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub(super) fn effective_home_dir() -> Result<PathBuf, String> {
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

pub(super) fn effective_codex_home(home: &Path) -> PathBuf {
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
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output();
}

fn targets_stamp_path(bin: &Path) -> PathBuf {
    bin.with_file_name(".ctx.targets.json")
}

pub(super) fn load_saved_targets(bin: &Path) -> Option<TargetSet> {
    let txt = fs::read_to_string(targets_stamp_path(bin)).ok()?;
    let parsed = json::parse_config(&txt).ok()?;
    let arr = parsed.get("targets")?.as_arr()?;
    let mut set = TargetSet {
        agy: false,
        claude: false,
        codex: false,
    };
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
    if targets.agy {
        arr.push(Json::Str("antigravity".into()));
    }
    if targets.claude {
        arr.push(Json::Str("claude".into()));
    }
    if targets.codex {
        arr.push(Json::Str("codex".into()));
    }
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
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
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

fn prompt_targets_interactive(
    home: &Path,
    codex_home: &Path,
) -> Result<Option<TargetSet>, String> {
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
            "    [{}] 1. Antigravity (CLI, App 2.0 & IDE) {}  * Default (4 eager tools, -45% time, -38% new tokens)",
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
            "    [{}] 3. Codex CLI                        {}  (optional: deferred MCP token overhead)",
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
                sel = TargetSet {
                    agy: false,
                    claude: false,
                    codex: false,
                };
                continue;
            }
            _ => {
                let mut toggled = false;
                for tok in trimmed.split(|c: char| c.is_whitespace() || c == ',') {
                    match tok {
                        "1" | "agy" | "antigravity" => {
                            sel.agy = !sel.agy;
                            toggled = true;
                        }
                        "2" | "claude" => {
                            sel.claude = !sel.claude;
                            toggled = true;
                        }
                        "3" | "codex" => {
                            sel.codex = !sel.codex;
                            toggled = true;
                        }
                        "" => {}
                        _ => {
                            let _ = writeln!(
                                writer,
                                "  Unrecognized input `{tok}` — enter 1, 2, 3, all, q, or press Enter."
                            );
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

fn prepare_install(
    home: &Path,
    codex: &Path,
    bin: &Path,
    targets: TargetSet,
    eager: (EagerMode, bool),
    wsl_bridge: bool,
    codex_rules: bool,
) -> Result<InstallPlan, String> {
    let mut plan = InstallPlan::default();
    plan_binary(&mut plan, bin)?;
    let agy = home.join(".gemini/config");

    if targets.agy {
        plan_mcp(&mut plan, &agy.join("mcp_config.json"), bin, false, Some(eager))?;
        plan_hooks(&mut plan, &agy.join("hooks.json"), bin, "agy")?;
        plan_rules(&mut plan, &agy.join("AGENTS.md"))?;
    } else {
        plan_remove_mcp(&mut plan, &agy.join("mcp_config.json"))?;
        plan_remove_hooks(&mut plan, &agy.join("hooks.json"), "agy")?;
        plan_remove_rules(&mut plan, &agy.join("AGENTS.md"))?;
    }

    if let Some((distro, win_dirs)) = detect_wsl_windows_gemini_dirs(wsl_bridge) {
        for win_gemini in win_dirs {
            if targets.agy {
                plan_wsl_windows_bridge(&mut plan, &win_gemini, &distro, bin, eager)?;
            } else {
                plan_remove_wsl_windows_bridge(&mut plan, &win_gemini)?;
            }
        }
    }

    if targets.codex {
        if codex_rules {
            plan_rules(&mut plan, &codex.join("AGENTS.md"))?;
        }
        let cfg = codex.join("config.toml");
        let current = plan.text(&cfg)?.unwrap_or_default();
        let desired = upsert_codex_toml_mcp_and_hooks(&current, bin)?;
        plan.set(&cfg, desired.into_bytes(), None)?;
        plan_hooks(&mut plan, &codex.join("hooks.json"), bin, "codex")?;
    } else {
        plan_remove_codex_toml(&mut plan, &codex.join("config.toml"))?;
        plan_remove_hooks(&mut plan, &codex.join("hooks.json"), "codex")?;
        if codex_rules {
            plan_remove_rules(&mut plan, &codex.join("AGENTS.md"))?;
        }
    }

    if targets.claude {
        plan_hooks(&mut plan, &home.join(".claude/settings.json"), bin, "claude")?;
        plan_mcp(&mut plan, &home.join(".claude.json"), bin, true, None)?;
    } else {
        plan_remove_hooks(&mut plan, &home.join(".claude/settings.json"), "claude")?;
        plan_remove_mcp(&mut plan, &home.join(".claude.json"))?;
    }
    Ok(plan)
}

pub fn run_install_cli(args: &[String]) -> i32 {
    let mut check_only = false;
    let mut interactive = false;
    let mut wsl_bridge = true;
    let mut codex_rules = true;
    let mut explicit_targets: Option<TargetSet> = None;
    let mut explicit_eager: Option<EagerMode> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => check_only = true,
            "--interactive" | "-i" => interactive = true,
            "--no-wsl-bridge" => wsl_bridge = false,
            "--no-codex-rules" => codex_rules = false,
            "--all" => explicit_targets = Some(TargetSet::all()),
            "--targets" if i + 1 < args.len() => {
                i += 1;
                match TargetSet::parse_csv(&args[i]) {
                    Ok(t) => explicit_targets = Some(t),
                    Err(e) => {
                        eprintln!("ctx install error: {e}");
                        return 1;
                    }
                }
            }
            arg if arg.starts_with("--targets=") => {
                match TargetSet::parse_csv(&arg["--targets=".len()..]) {
                    Ok(t) => explicit_targets = Some(t),
                    Err(e) => {
                        eprintln!("ctx install error: {e}");
                        return 1;
                    }
                }
            }
            "--eager" if i + 1 < args.len() => {
                i += 1;
                match EagerMode::parse(&args[i]) {
                    Ok(m) => explicit_eager = Some(m),
                    Err(e) => {
                        eprintln!("ctx install error: {e}");
                        return 1;
                    }
                }
            }
            arg if arg.starts_with("--eager=") => {
                match EagerMode::parse(&arg["--eager=".len()..]) {
                    Ok(m) => explicit_eager = Some(m),
                    Err(e) => {
                        eprintln!("ctx install error: {e}");
                        return 1;
                    }
                }
            }
            arg => {
                eprintln!("ctx install: invalid argument {}", arg);
                return 1;
            }
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

    let targets = if let Some(t) = explicit_targets {
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
        println!(
            "ctx setup: no harnesses selected (run `ctx uninstall` to remove existing installation)"
        );
        return 0;
    }

    let plan = match prepare_install(
        &home,
        &codex_home,
        &ctx_bin,
        targets,
        eager_spec,
        wsl_bridge,
        codex_rules,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ctx install error: {}", e);
            return 1;
        }
    };
    let stale: Vec<_> = plan
        .0
        .iter()
        .filter(|t| t.changed())
        .map(|t| t.path.display())
        .collect();
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

    if let Err(e) = plan.apply(&ctx_bin) {
        eprintln!("ctx install error: {}", e);
        return 1;
    }
    write_targets_stamp(&ctx_bin, targets, eager_mode);
    #[cfg(windows)]
    if std::env::var("AGENT_CTX_HOME").is_err() {
        if let Some(dir) = ctx_bin.parent() {
            ensure_windows_user_path(dir);
        }
    }
    println!(
        "ctx install: OK (binary={}, targets={}, eager={}, updated {} file(s))",
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
                    Err(e) => {
                        eprintln!("ctx uninstall error: {e}");
                        return 1;
                    }
                }
            }
            arg if arg.starts_with("--targets=") => {
                match TargetSet::parse_csv(&arg["--targets=".len()..]) {
                    Ok(t) => explicit_targets = Some(t),
                    Err(e) => {
                        eprintln!("ctx uninstall error: {e}");
                        return 1;
                    }
                }
            }
            arg => {
                eprintln!("ctx uninstall: invalid argument {arg}");
                return 1;
            }
        }
        i += 1;
    }

    let home = match effective_home_dir() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ctx uninstall error: {e}");
            return 1;
        }
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
        println!(
            "ctx uninstall: detached from {} (binary retained at {})",
            remove_set.summary(),
            ctx_bin.display()
        );
    } else {
        let _ = stop_daemon_for_install();
        let _ = fs::remove_file(&ctx_bin);
        let _ = fs::remove_file(ctx_bin.with_file_name(".ctx.sha256"));
        let _ = fs::remove_file(&t_stamp);
        if let Some(cache_dir) = default_snapshot_path().parent() {
            let _ = fs::remove_dir_all(cache_dir);
        }
        let _ = fs::remove_dir_all(runtime_dir());
        println!(
            "ctx uninstall: OK (removed binary, daemon state, and global configs for {})",
            remove_set.summary()
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn no_codex_rules_leaves_codex_agents_md_untouched() {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let home = std::env::temp_dir().join(format!(
            "ctx-install-no-rules-{}-{}",
            std::process::id(),
            id
        ));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).expect("create fake home dir");
        let home = fs::canonicalize(&home).unwrap_or(home);
        let codex = home.join(".codex");
        fs::create_dir_all(&codex).expect("create fake codex dir");
        let codex_agents = codex.join("AGENTS.md");
        fs::write(&codex_agents, "# Externally managed instructions\n").expect("seed AGENTS.md");
        let bin = target_ctx_bin(&home);

        let plan = prepare_install(
            &home,
            &codex,
            &bin,
            TargetSet::all(),
            (EagerMode::Core, false),
            false,
            false,
        )
        .expect("prepare_install with codex_rules=false");
        assert!(
            plan.0.iter().all(|t| t.path != codex_agents),
            "codex AGENTS.md must not be planned when codex_rules=false"
        );
        assert!(
            plan.0.iter().any(|t| t.path == codex.join("config.toml")),
            "codex config.toml must still be planned"
        );

        let plan_with_rules = prepare_install(
            &home,
            &codex,
            &bin,
            TargetSet::all(),
            (EagerMode::Core, false),
            false,
            true,
        )
        .expect("prepare_install with codex_rules=true");
        assert!(
            plan_with_rules
                .0
                .iter()
                .any(|t| t.path == codex_agents && t.changed()),
            "codex AGENTS.md must be planned when codex_rules=true"
        );

        let _ = fs::remove_dir_all(&home);
    }
}
