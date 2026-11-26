//! Non-blocking release update checker and verified `ctx update` command
//! (pure-Rust SHA-256, zero external crates, custom-flavor safe).

use super::{effective_home_dir, target_ctx_bin};
use crate::base::{ext, json::{self, Json}, mode::runtime_dir, security::write_private_0600, simd::fast_hash64};
use crate::rpc::stop_daemon_for_install;
use crate::store::now_ms;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{atomic::{AtomicBool, Ordering}, Mutex, OnceLock};

pub const CURRENT_VERSION: &str = "2.5.0";
const RELEASES_LATEST_URL: &str = "https://api.github.com/repos/be0hhh/ctx-mcp/releases/latest";
const DEFAULT_RELEASE_URL: &str = "https://github.com/be0hhh/ctx-mcp/releases/latest";
const DEFAULT_UPDATE_TTL_MS: u64 = 21_600_000;
const MAX_NOTIFIED_SESSIONS: usize = 512;
const MAX_SUMMARY_CHARS: usize = 180;

static BG_CHECK_STARTED: AtomicBool = AtomicBool::new(false);
static NOTIFIED_SESSIONS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct UpdateState { checked_at_ms: u64, latest_tag: String, release_name: String, summary: String, html_url: String }

const SHA256_H0: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 { let j = i << 2; w[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]); }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let t1 = hh.wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
            .wrapping_add((e & f) ^ ((!e) & g)).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
        let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)).wrapping_add((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d.wrapping_add(t1); d = c; c = b; b = a; a = t1.wrapping_add(t2);
    }
    for (slot, add) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) { *slot = slot.wrapping_add(add); }
}

/// Pure-Rust FIPS 180-4 SHA-256 returning lowercase 64-char hex (0 external deps, 0 div/idiv).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = SHA256_H0;
    let mut chunks = data.chunks_exact(64);
    for block in &mut chunks { sha256_compress(&mut h, block); }
    let (rem, mut tail, bit_len) = (chunks.remainder(), [0u8; 128], (data.len() as u64).wrapping_shl(3));
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    if rem.len() < 56 {
        tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(&mut h, &tail[..64]);
    } else {
        tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(&mut h, &tail[..64]);
        sha256_compress(&mut h, &tail[64..128]);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in h.into_iter().flat_map(u32::to_be_bytes) { out.push(HEX[(b >> 4) as usize] as char); out.push(HEX[(b & 0x0f) as usize] as char); }
    out
}

fn parse_semver(raw: &str) -> Option<(u64, u64, u64, Option<&str>)> {
    let s = raw.trim().trim_start_matches(['v', 'V']);
    let s = s.split_once('+').map_or(s, |(a, _)| a);
    let (core, pre) = s.split_once('-').map_or((s, None), |(a, b)| (a, Some(b)));
    let mut p = core.split('.');
    let (major, minor) = (p.next()?.parse::<u64>().ok()?, p.next()?.parse::<u64>().ok()?);
    let patch = p.next().map(|v| v.parse::<u64>().ok()).unwrap_or(Some(0))?;
    p.next().is_none().then_some((major, minor, patch, pre))
}

/// Returns `true` when `latest_tag` is strictly newer than `current` (`v2.6.0` vs `2.5.0`).
pub fn is_newer_version(latest_tag: &str, current: &str) -> bool {
    let (Some(l), Some(c)) = (parse_semver(latest_tag), parse_semver(current)) else { return false; };
    if (l.0, l.1, l.2) != (c.0, c.1, c.2) { return (l.0, l.1, l.2) > (c.0, c.1, c.2); }
    matches!((l.3, c.3), (None, Some(_))) || matches!((l.3, c.3), (Some(a), Some(b)) if a > b)
}

fn state_file_path() -> PathBuf { runtime_dir().join("update_state.json") }

fn update_ttl_ms() -> u64 {
    std::env::var("AGENT_CTX_UPDATE_TTL_SECS").ok().and_then(|s| s.trim().parse::<u64>().ok())
        .map_or(DEFAULT_UPDATE_TTL_MS, |secs| secs.saturating_mul(1_000))
}
fn update_check_disabled() -> bool {
    let truthy = |k: &str| std::env::var(k).ok().is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"));
    truthy("AGENT_CTX_NO_UPDATE_CHECK") || truthy("CI") || std::env::var("AGENT_CTX_INPROC").as_deref() == Ok("1")
}

fn read_state_from(path: &Path) -> Option<UpdateState> {
    let p = json::parse(&fs::read_to_string(path).ok()?).ok()?;
    Some(UpdateState {
        checked_at_ms: p.get_i64("checked_at_ms").filter(|&v| v >= 0).map_or(0, |v| v as u64),
        latest_tag: p.get_str("latest_tag").unwrap_or("").into(), release_name: p.get_str("release_name").unwrap_or("").into(),
        summary: p.get_str("summary").unwrap_or("").into(), html_url: p.get_str("html_url").unwrap_or("").into(),
    })
}

fn write_state_to(path: &Path, s: &UpdateState) -> Result<(), String> {
    let body = Json::obj(vec![
        ("checked_at_ms", Json::Int(s.checked_at_ms as i64)), ("latest_tag", Json::Str(s.latest_tag.clone())),
        ("release_name", Json::Str(s.release_name.clone())), ("summary", Json::Str(s.summary.clone())),
        ("html_url", Json::Str(s.html_url.clone())),
    ]).to_json_string();
    write_private_0600(path, body.as_bytes())
}

fn sanitize_release_summary(body: &str, fallback_name: &str) -> String {
    let mut parts = Vec::new();
    for raw_line in body.lines() {
        let (mut clean, mut prev_sp, mut chars) = (String::new(), false, raw_line.chars().peekable());
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                if chars.peek() == Some(&'[') { let _ = chars.next(); while chars.next().is_some_and(|c| !c.is_ascii_alphabetic()) {} }
                continue;
            }
            if ch.is_control() { continue; }
            if ch.is_whitespace() { if !prev_sp { clean.push(' '); prev_sp = true; } }
            else { clean.push(ch); prev_sp = false; }
        }
        let t = clean.trim().trim_start_matches(['#', '-', '*', '>', ' ']).trim();
        if t.is_empty() || t.chars().all(|c| matches!(c, '-' | '=' | '_' | '*'))
            || t.starts_with("Full Changelog:") || t.starts_with("SHA256SUMS") { continue; }
        parts.push(t.to_string());
        if parts.len() >= 2 { break; }
    }
    let joined = if parts.is_empty() { fallback_name.trim().to_string() } else { parts.join("; ") };
    if joined.chars().count() <= MAX_SUMMARY_CHARS { return joined; }
    let mut out: String = joined.chars().take(MAX_SUMMARY_CHARS - 3).collect();
    out.push_str("...");
    out
}

fn run_hidden_output(mut cmd: Command, discard_stdout: bool) -> Result<Vec<u8>, String> {
    cmd.stdin(Stdio::null())
        .stdout(if discard_stdout { Stdio::null() } else { Stdio::piped() })
        .stderr(Stdio::piped());
    #[cfg(windows)]
    { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() { return Ok(out.stdout); }
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    Err(if err.is_empty() { format!("exit status {}", out.status) } else { err })
}

fn http_fetch(url: &str, timeout_secs: &str, github_json: bool, out_file: Option<&Path>) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://") { return Err(format!("refusing non-HTTPS URL: {url}")); }
    let mut cmd = crate::base::platform::hidden_command(crate::base::platform::resolve_tool("curl"));
    cmd.args(["-fsSL", "--max-time", timeout_secs, "-H", "User-Agent: ctx-mcp"]);
    if github_json { cmd.args(["-H", "Accept: application/vnd.github+json"]); }
    if let Some(dest) = out_file { cmd.arg("-o").arg(dest); }
    cmd.args(["--", url]);
    let curl_res = run_hidden_output(cmd, out_file.is_some());
    if curl_res.is_ok() { return curl_res; }
    #[cfg(windows)]
    {
        let u = url.replace('\'', "''");
        let ps = if let Some(dest) = out_file {
            format!("Invoke-WebRequest -UseBasicParsing -Uri '{u}' -OutFile '{}' -TimeoutSec {timeout_secs} -Headers @{{'User-Agent'='ctx-mcp'}}", dest.to_string_lossy().replace('\'', "''"))
        } else if github_json {
            format!("(Invoke-RestMethod -Uri '{u}' -TimeoutSec {timeout_secs} -Headers @{{'Accept'='application/vnd.github+json';'User-Agent'='ctx-mcp'}}) | ConvertTo-Json -Depth 4 -Compress")
        } else {
            format!("(Invoke-WebRequest -UseBasicParsing -Uri '{u}' -TimeoutSec {timeout_secs} -Headers @{{'User-Agent'='ctx-mcp'}}).Content")
        };
        let mut pcmd = Command::new("powershell");
        pcmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps]);
        return run_hidden_output(pcmd, out_file.is_some()).map_err(|e| format!("powershell fetch failed: {e}"));
    }
    #[cfg(not(windows))]
    curl_res.map_err(|e| format!("curl fetch failed: {e}"))
}

fn fetch_latest_release(timeout_secs: &str) -> Result<(UpdateState, Vec<(String, String)>), String> {
    let raw = http_fetch(RELEASES_LATEST_URL, timeout_secs, true, None)?;
    let parsed = json::parse(std::str::from_utf8(&raw).map_err(|_| "release response is not UTF-8")?)
        .map_err(|e| format!("invalid release JSON: {e}"))?;
    let tag_name = parsed.get_str("tag_name").map(str::trim).filter(|s| !s.is_empty())
        .ok_or("release JSON missing tag_name")?.to_string();
    let release_name = parsed.get_str("name").unwrap_or(&tag_name).to_string();
    let html_url = parsed.get_str("html_url").filter(|s| !s.is_empty()).unwrap_or(DEFAULT_RELEASE_URL).to_string();
    let summary = sanitize_release_summary(parsed.get_str("body").unwrap_or(""), &release_name);
    let assets = parsed.get("assets").and_then(Json::as_arr).map(|arr| {
        arr.iter().filter_map(|i| Some((i.get_str("name")?.to_string(), i.get_str("browser_download_url")?.to_string()))).collect()
    }).unwrap_or_default();
    Ok((UpdateState { checked_at_ms: now_ms(), latest_tag: tag_name, release_name, summary, html_url }, assets))
}

/// Non-blocking, TTL-cached background release check (at most once per process, silent on error).
pub fn maybe_spawn_background_update_check() {
    if update_check_disabled() { return; }
    let path = state_file_path();
    if let Some(st) = read_state_from(&path) {
        if st.checked_at_ms > 0 && now_ms().saturating_sub(st.checked_at_ms) < update_ttl_ms() { return; }
    }
    if BG_CHECK_STARTED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_err() { return; }
    let _ = std::thread::Builder::new().name("ctx-update-chk".into()).spawn(move || {
        if let Ok((state, _)) = fetch_latest_release("3") { let _ = write_state_to(&path, &state); }
    });
}

fn format_update_notice(st: &UpdateState, current: &str, flavor: &str, hint: Option<&str>) -> Option<String> {
    if !is_newer_version(&st.latest_tag, current) { return None; }
    let url = if st.html_url.is_empty() { DEFAULT_RELEASE_URL } else { st.html_url.as_str() };
    let summary = if st.summary.is_empty() { "new release available" } else { st.summary.as_str() };
    Some(if flavor == "upstream" {
        format!("[ctx update] v{current} -> {} released ({url}): {summary}\nRun `ctx update` to hot-upgrade without restarting your agent.", st.latest_tag)
    } else {
        let h = hint.unwrap_or("your local rebuild script");
        format!("[ctx update] upstream {} released ({url}): {summary}\nLocal {flavor} build active — run {h} (or `ctx update --rebuild`).", st.latest_tag)
    })
}

fn pending_update_notice_from(state_path: &Path, session_key: &str, current: &str, flavor: &str, hint: Option<&str>) -> Option<String> {
    let notice = format_update_notice(&read_state_from(state_path)?, current, flavor, hint)?;
    let mut guard = NOTIFIED_SESSIONS.get_or_init(|| Mutex::new(HashSet::new())).lock().ok()?;
    if guard.contains(session_key) { return None; }
    if guard.len() >= MAX_NOTIFIED_SESSIONS { guard.clear(); }
    guard.insert(session_key.to_string());
    Some(notice)
}

/// Returns a 2-line update notice at most once per `session_key` (cache only, zero network).
pub fn pending_update_notice_once(session_key: &str) -> Option<String> {
    let pol = ext::policy();
    pending_update_notice_from(&state_file_path(), session_key, CURRENT_VERSION, pol.build_flavor(), pol.update_hint())
}

/// Cached update status for `ctx status`, `ctx doctor`, and `ctx://status` (zero network).
pub fn update_status_json() -> Json {
    let flavor = ext::policy().build_flavor();
    let (latest, avail, summary, url, checked) = match read_state_from(&state_file_path()) {
        Some(s) => {
            let avail = is_newer_version(&s.latest_tag, CURRENT_VERSION);
            let tag = if s.latest_tag.is_empty() { Json::Null } else { Json::Str(s.latest_tag) };
            (tag, avail, s.summary, s.html_url, s.checked_at_ms as i64)
        }
        None => (Json::Null, false, String::new(), String::new(), 0i64),
    };
    Json::obj(vec![
        ("current", Json::Str(CURRENT_VERSION.to_string())), ("flavor", Json::Str(flavor.to_string())),
        ("latest", latest), ("update_available", Json::Bool(avail)),
        ("summary", Json::Str(summary)), ("url", Json::Str(url)), ("checked_at_ms", Json::Int(checked)),
    ])
}

pub fn remove_update_state_file() { let _ = fs::remove_file(state_file_path()); }

fn platform_asset_name(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Some("ctx-linux-x86_64"), ("linux", "aarch64") => Some("ctx-linux-aarch64"),
        ("macos", "aarch64") => Some("ctx-macos-arm64"), ("macos", "x86_64") => Some("ctx-macos-x86_64"),
        ("windows", "x86_64") => Some("ctx-windows-x86_64.exe"), _ => None,
    }
}

fn find_sha256_entry(sums_text: &str, asset_name: &str) -> Option<String> {
    for line in sums_text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let mut it = line.splitn(2, char::is_whitespace);
        let (hash, file) = (it.next()?.trim(), it.next()?.trim().trim_start_matches('*').trim_start_matches("./"));
        if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) && file == asset_name {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
enum UpdatePlan { UpstreamBinary, CustomHint(&'static str), CustomRebuild(Option<(&'static str, &'static [&'static str])>) }

fn decide_update_plan(flavor: &'static str, hint: Option<&'static str>, rebuild_cmd: Option<(&'static str, &'static [&'static str])>, want_rebuild: bool) -> UpdatePlan {
    if flavor == "upstream" { UpdatePlan::UpstreamBinary }
    else if want_rebuild { UpdatePlan::CustomRebuild(rebuild_cmd) }
    else { UpdatePlan::CustomHint(hint.unwrap_or("your local rebuild script")) }
}

fn atomic_install_binary(dest: &Path, bin_bytes: &[u8]) -> Result<(), String> {
    let parent = dest.parent().ok_or("missing binary parent directory")?;
    fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    let staged = dest.with_file_name(format!(".ctx.update.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&staged);
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o755); }
        let mut f = opts.open(&staged).map_err(|e| format!("stage {}: {e}", staged.display()))?;
        let ok = f.write_all(bin_bytes).and_then(|_| f.sync_all());
        #[cfg(unix)] let ok = ok.and_then(|_| { use std::os::unix::fs::PermissionsExt; f.set_permissions(fs::Permissions::from_mode(0o755)) });
        if let Err(e) = ok { let _ = fs::remove_file(&staged); return Err(format!("stage binary: {e}")); }
    }
    stop_daemon_for_install()?;
    let bak = dest.with_file_name(format!("{}.bak", dest.file_name().and_then(|n| n.to_str()).unwrap_or("ctx")));
    let had_existing = dest.is_file();
    if had_existing {
        #[cfg(unix)] let _ = fs::copy(dest, &bak);
        #[cfg(windows)] {
            let _ = fs::remove_file(&bak);
            if let Err(e) = fs::rename(dest, &bak) { let _ = fs::remove_file(&staged); return Err(format!("backup binary: {e}")); }
        }
    }
    if let Err(e) = fs::rename(&staged, dest) {
        let _ = fs::remove_file(&staged);
        #[cfg(windows)] if had_existing { let _ = fs::rename(&bak, dest); }
        return Err(format!("replace {}: {e}", dest.display()));
    }
    let stamp = format!("{:016x}\n", fast_hash64(bin_bytes));
    let _ = write_private_0600(&dest.with_file_name(".ctx.sha256"), stamp.as_bytes());
    Ok(())
}

fn run_upstream_update(force: bool) -> Result<String, String> {
    let (state, assets) = fetch_latest_release("10")?;
    let _ = write_state_to(&state_file_path(), &state);
    if !force && !is_newer_version(&state.latest_tag, CURRENT_VERSION) {
        return Ok(format!("ctx update: already up to date (current=v{CURRENT_VERSION}, latest={})", state.latest_tag));
    }
    let asset = platform_asset_name(std::env::consts::OS, std::env::consts::ARCH)
        .ok_or_else(|| format!("unsupported platform {}/{}", std::env::consts::OS, std::env::consts::ARCH))?;
    let bin_url = assets.iter().find(|(n, _)| n == asset).map(|(_, u)| u.as_str()).ok_or_else(|| format!("release {} missing `{asset}`", state.latest_tag))?;
    let sums_url = assets.iter().find(|(n, _)| n == "SHA256SUMS").map(|(_, u)| u.as_str()).ok_or_else(|| format!("release {} missing SHA256SUMS", state.latest_tag))?;
    let dest = target_ctx_bin(&effective_home_dir()?);
    let tmp = std::env::temp_dir().join(format!("ctx-upd-{}-{}", std::process::id(), now_ms()));
    fs::create_dir_all(&tmp).map_err(|e| format!("create temp dir: {e}"))?;
    let res = (|| -> Result<(), String> {
        let sums_raw = http_fetch(sums_url, "15", false, None)?;
        let expected = find_sha256_entry(std::str::from_utf8(&sums_raw).map_err(|_| "SHA256SUMS not UTF-8")?, asset)
            .ok_or_else(|| format!("SHA256SUMS missing entry for {asset}"))?;
        let bin_tmp = tmp.join(asset);
        let _ = http_fetch(bin_url, "60", false, Some(&bin_tmp))?;
        let bytes = fs::read(&bin_tmp).map_err(|e| format!("read binary: {e}"))?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(&expected) { return Err(format!("SHA-256 mismatch for {asset}: expected {expected}, got {actual}")); }
        atomic_install_binary(&dest, &bytes)
    })();
    let _ = fs::remove_dir_all(&tmp);
    res?;
    Ok(format!("ctx update: upgraded v{CURRENT_VERSION} -> {} at {} (daemon hot-swap ready)", state.latest_tag, dest.display()))
}

fn run_update_check(flavor: &str, hint: Option<&str>, as_json: bool) -> i32 {
    match fetch_latest_release("5") {
        Ok((st, _)) => {
            let _ = write_state_to(&state_file_path(), &st);
            if as_json { println!("{}", update_status_json().to_json_string()); } else {
                println!("ctx update --check: current=v{CURRENT_VERSION} flavor={flavor} latest={} update_available={}", st.latest_tag, is_newer_version(&st.latest_tag, CURRENT_VERSION));
                if let Some(n) = format_update_notice(&st, CURRENT_VERSION, flavor, hint) { println!("{n}"); }
            }
            0
        }
        Err(e) => { eprintln!("ctx update --check error: {e}"); 1 }
    }
}

pub fn run_update_cli(args: &[String]) -> i32 {
    let (mut check_only, mut rebuild, mut force, mut as_json) = (false, false, false, false);
    for arg in args {
        match arg.as_str() {
            "--check" => check_only = true, "--rebuild" => rebuild = true,
            "--force" => force = true, "--json" => as_json = true,
            other => { eprintln!("ctx update: invalid argument `{other}`"); return 1; }
        }
    }
    let pol = ext::policy();
    let flavor = pol.build_flavor();
    if check_only { return run_update_check(flavor, pol.update_hint(), as_json); }
    match decide_update_plan(flavor, pol.update_hint(), pol.rebuild_command(), rebuild) {
        UpdatePlan::CustomHint(hint) => {
            if let Ok((st, _)) = fetch_latest_release("4") {
                let _ = write_state_to(&state_file_path(), &st);
                println!("ctx update: upstream {} ({}): {}", st.latest_tag, st.html_url, st.summary);
            }
            println!("Local {flavor} build active (v{CURRENT_VERSION}) — upstream binary will not overwrite it.\nRun {hint} (or `ctx update --rebuild`).");
            0
        }
        UpdatePlan::CustomRebuild(None) => { eprintln!("ctx update --rebuild: no rebuild command configured for `{flavor}`"); 1 }
        UpdatePlan::CustomRebuild(Some((prog, cmd_args))) => match Command::new(prog).args(cmd_args).status() {
            Ok(st) if st.success() => {
                if let Err(e) = stop_daemon_for_install() { eprintln!("ctx update --rebuild warning: daemon stop skipped ({e})"); }
                println!("ctx update --rebuild: OK (rebuilt {flavor}; daemon hot-swap ready)");
                0
            }
            Ok(st) => { eprintln!("ctx update --rebuild: `{prog}` exited with {st}"); st.code().unwrap_or(1) }
            Err(e) => { eprintln!("ctx update --rebuild: failed to run `{prog}`: {e}"); 1 }
        },
        UpdatePlan::UpstreamBinary => match run_upstream_update(force) {
            Ok(msg) => { println!("{msg}"); 0 }
            Err(e) => { eprintln!("ctx update error: {e}"); 1 }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_fips_180_4_vectors() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }
    #[test]
    fn semver_comparison_handles_tags_and_prereleases() {
        assert!(is_newer_version("v2.6.0", "2.5.0") && is_newer_version("2.5.1", "2.5.0") && is_newer_version("V3.0.0", "2.9.9") && is_newer_version("v2.5.0", "2.5.0-rc1"));
        assert!(!is_newer_version("v2.5.0", "2.5.0") && !is_newer_version("v2.4.9", "2.5.0") && !is_newer_version("v2.5.0-rc1", "2.5.0") && !is_newer_version("", "2.5.0") && !is_newer_version("invalid", "2.5.0"));
    }
    #[test]
    fn pending_notice_deduplicates_per_session_and_formats_flavors() {
        let dir = std::env::temp_dir().join(format!("ctx-upd-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let st_path = dir.join("update_state.json");
        let st = UpdateState { checked_at_ms: now_ms(), latest_tag: "v2.6.0".into(), release_name: "v2.6.0".into(), summary: "hashline edit + impact".into(), html_url: "https://github.com/be0hhh/ctx-mcp/releases/tag/v2.6.0".into() };
        write_state_to(&st_path, &st).expect("write state");
        let (s1, s2) = (format!("dedup-s1-{}", std::process::id()), format!("dedup-s2-{}", std::process::id()));
        let first = pending_update_notice_from(&st_path, &s1, "2.5.0", "upstream", None).expect("first");
        assert!(first.contains("v2.5.0 -> v2.6.0 released") && first.contains("Run `ctx update`"));
        assert!(pending_update_notice_from(&st_path, &s1, "2.5.0", "upstream", None).is_none());
        let custom = pending_update_notice_from(&st_path, &s2, "2.5.0", "ctx-custom", Some("python3 build.py")).expect("custom");
        assert!(custom.contains("Local ctx-custom build active") && custom.contains("python3 build.py") && custom.contains("--rebuild"));
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn custom_flavor_protection_and_sha256sums_matching() {
        assert_eq!(decide_update_plan("upstream", None, None, false), UpdatePlan::UpstreamBinary);
        assert_eq!(decide_update_plan("ctx-local", Some("make rebuild"), None, false), UpdatePlan::CustomHint("make rebuild"));
        static ARGS: &[&str] = &["bootstrap.py"];
        assert_eq!(decide_update_plan("ctx-local", Some("make rebuild"), Some(("python3", ARGS)), true), UpdatePlan::CustomRebuild(Some(("python3", ARGS))));
        let sums = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ctx-linux-x86_64\n";
        assert_eq!(find_sha256_entry(sums, "ctx-linux-x86_64").as_deref(), Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert!(find_sha256_entry(sums, "ctx-macos-arm64").is_none());
    }
}
