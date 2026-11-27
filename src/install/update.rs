//! Non-blocking ETag release checker, verified auto-patch daemon handoff, and `ctx update`
//! (pure-Rust FIPS 180-4 SHA-256, pre-swap `--protocol-check`, zero external crates, custom-flavor safe).

use super::{effective_home_dir, target_ctx_bin};
use crate::base::{
    ext,
    json::{self, Json},
    mode::runtime_dir,
    security::{ensure_private_dir, write_private_0600},
    simd::{fast_hash64, fnv1a_64},
};
use crate::rpc::stop_daemon_for_install;
use crate::store::now_ms;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, OnceLock,
};
use std::time::{Duration, Instant};

pub const CURRENT_VERSION: &str = "2.5.3";
const RELEASES_LATEST_URL: &str = "https://api.github.com/repos/be0hhh/ctx-mcp/releases/latest";
const DEFAULT_RELEASE_URL: &str = "https://github.com/be0hhh/ctx-mcp/releases/latest";
const DEFAULT_UPDATE_TTL_SECS: u64 = 1_800; // 30 min (conditional HTTP ETag 304 = 0 GitHub rate-limit cost)
const FAILED_TAG_BACKOFF_MS: u64 = 21_600_000; // 6 hours backoff after a failed auto-upgrade attempt
const UPDATE_LOCK_STALE_SECS: u64 = 120;
const MAX_NOTIFIED_SESSIONS: usize = 512;
const MAX_SUMMARY_CHARS: usize = 180;
const MAX_ETAG_CHARS: usize = 128;

static BG_CHECK_STARTED: AtomicBool = AtomicBool::new(false);
static NOTIFIED_SESSIONS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoUpdatePolicy {
    Off,
    Patch,
    All,
}

impl AutoUpdatePolicy {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" | "no" | "disable" | "disabled" | "none" | "notify" => Some(Self::Off),
            "patch" | "patches" | "1" | "true" | "on" | "yes" | "auto" | "default" => Some(Self::Patch),
            "all" | "full" | "stable" | "minor" | "major" => Some(Self::All),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Patch => "patch",
            Self::All => "all",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct UpdateState {
    checked_at_ms: u64,
    latest_tag: String,
    release_name: String,
    summary: String,
    html_url: String,
    etag: String,
    last_failed_tag: String,
    last_failed_at_ms: u64,
    auto_upgraded_from: String,
    auto_upgraded_to: String,
    auto_upgraded_at_ms: u64,
}

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

/// Returns `true` when `latest_tag` is a non-prerelease patch upgrade on the same `major.minor`.
pub fn is_patch_upgrade(latest_tag: &str, current: &str) -> bool {
    let (Some(l), Some(c)) = (parse_semver(latest_tag), parse_semver(current)) else { return false; };
    l.3.is_none() && l.0 == c.0 && l.1 == c.1 && (l.2 > c.2 || (l.2 == c.2 && c.3.is_some()))
}

/// Returns `true` when `latest_tag` is a non-prerelease upgrade (`patch`, `minor`, or `major`).
pub fn is_stable_upgrade(latest_tag: &str, current: &str) -> bool {
    let Some(l) = parse_semver(latest_tag) else { return false; };
    l.3.is_none() && is_newer_version(latest_tag, current)
}

fn state_file_path() -> PathBuf { runtime_dir().join("update_state.json") }
fn lock_file_path() -> PathBuf { runtime_dir().join("update.lock") }
fn policy_file_for_bin(bin: &Path) -> PathBuf { bin.with_file_name(".ctx.update.json") }
fn version_stamp_for_bin(bin: &Path) -> PathBuf { bin.with_file_name(".ctx.version") }

fn update_ttl_secs() -> u64 {
    std::env::var("AGENT_CTX_UPDATE_TTL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_UPDATE_TTL_SECS)
}

fn update_ttl_ms() -> u64 { update_ttl_secs().saturating_mul(1_000) }

fn update_check_disabled() -> bool {
    let truthy = |k: &str| std::env::var(k).ok().is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"));
    truthy("AGENT_CTX_NO_UPDATE_CHECK") || truthy("CI") || std::env::var("AGENT_CTX_INPROC").as_deref() == Ok("1")
}

fn read_persisted_auto_policy(path: &Path) -> Option<AutoUpdatePolicy> {
    let raw = fs::read_to_string(path).ok()?;
    let parsed = json::parse(&raw).ok()?;
    parsed.get_str("auto_update").and_then(AutoUpdatePolicy::parse)
}

fn write_persisted_auto_policy(path: &Path, policy: AutoUpdatePolicy) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let body = Json::obj(vec![("auto_update", Json::Str(policy.as_str().to_string()))]).to_json_string();
    write_private_0600(path, body.as_bytes())
}

fn resolve_auto_policy_from(
    flavor: &str,
    disabled_env: bool,
    env_override: Option<&str>,
    cfg_path: Option<&Path>,
) -> (AutoUpdatePolicy, &'static str) {
    if flavor != "upstream" {
        return (AutoUpdatePolicy::Off, "custom-flavor");
    }
    if disabled_env {
        return (AutoUpdatePolicy::Off, "env-disabled");
    }
    if let Some(p) = env_override.and_then(AutoUpdatePolicy::parse) {
        return (p, "env");
    }
    if let Some(p) = cfg_path.and_then(read_persisted_auto_policy) {
        return (p, "config");
    }
    (AutoUpdatePolicy::Patch, "default")
}

pub fn current_auto_update_policy() -> (AutoUpdatePolicy, &'static str) {
    let flavor = ext::policy().build_flavor();
    let env_val = std::env::var("AGENT_CTX_AUTO_UPDATE").ok();
    let cfg_path = effective_home_dir().ok().map(|h| policy_file_for_bin(&target_ctx_bin(&h)));
    resolve_auto_policy_from(flavor, update_check_disabled(), env_val.as_deref(), cfg_path.as_deref())
}

fn read_installed_version_from(stamp_path: &Path) -> Option<String> {
    let raw = fs::read_to_string(stamp_path).ok()?;
    let trimmed = raw.trim();
    parse_semver(trimmed).map(|_| trimmed.trim_start_matches(['v', 'V']).to_string())
}

fn effective_installed_version(current: &str, stamp_path: Option<&Path>) -> String {
    if let Some(disk_ver) = stamp_path.and_then(read_installed_version_from) {
        if is_newer_version(&disk_ver, current) {
            return disk_ver;
        }
    }
    current.to_string()
}

fn read_state_from(path: &Path) -> Option<UpdateState> {
    let p = json::parse(&fs::read_to_string(path).ok()?).ok()?;
    Some(UpdateState {
        checked_at_ms: p.get_i64("checked_at_ms").filter(|&v| v >= 0).map_or(0, |v| v as u64),
        latest_tag: p.get_str("latest_tag").unwrap_or("").into(),
        release_name: p.get_str("release_name").unwrap_or("").into(),
        summary: p.get_str("summary").unwrap_or("").into(),
        html_url: p.get_str("html_url").unwrap_or("").into(),
        etag: p.get_str("etag").unwrap_or("").into(),
        last_failed_tag: p.get_str("last_failed_tag").unwrap_or("").into(),
        last_failed_at_ms: p.get_i64("last_failed_at_ms").filter(|&v| v >= 0).map_or(0, |v| v as u64),
        auto_upgraded_from: p.get_str("auto_upgraded_from").unwrap_or("").into(),
        auto_upgraded_to: p.get_str("auto_upgraded_to").unwrap_or("").into(),
        auto_upgraded_at_ms: p.get_i64("auto_upgraded_at_ms").filter(|&v| v >= 0).map_or(0, |v| v as u64),
    })
}

fn write_state_to(path: &Path, s: &UpdateState) -> Result<(), String> {
    let body = Json::obj(vec![
        ("checked_at_ms", Json::Int(s.checked_at_ms as i64)),
        ("latest_tag", Json::Str(s.latest_tag.clone())),
        ("release_name", Json::Str(s.release_name.clone())),
        ("summary", Json::Str(s.summary.clone())),
        ("html_url", Json::Str(s.html_url.clone())),
        ("etag", Json::Str(s.etag.clone())),
        ("last_failed_tag", Json::Str(s.last_failed_tag.clone())),
        ("last_failed_at_ms", Json::Int(s.last_failed_at_ms as i64)),
        ("auto_upgraded_from", Json::Str(s.auto_upgraded_from.clone())),
        ("auto_upgraded_to", Json::Str(s.auto_upgraded_to.clone())),
        ("auto_upgraded_at_ms", Json::Int(s.auto_upgraded_at_ms as i64)),
    ]).to_json_string();
    write_private_0600(path, body.as_bytes())
}

fn sanitize_etag(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|&c| c.is_ascii() && (c as u8) >= 0x21 && (c as u8) <= 0x7e)
        .take(MAX_ETAG_CHARS)
        .collect()
}

fn parse_etag_from_headers(headers: &str) -> String {
    let mut found = String::new();
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("etag") {
                let clean = sanitize_etag(v);
                if !clean.is_empty() {
                    found = clean;
                }
            }
        }
    }
    found
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

struct ChildReaper(Child);
impl Drop for ChildReaper {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn run_command_with_timeout(mut cmd: Command, timeout: Duration) -> Result<Vec<u8>, String> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = ChildReaper(cmd.spawn().map_err(|e| e.to_string())?);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.0.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                    return Err("command timed out".to_string());
                };
                std::thread::sleep(rem.min(Duration::from_millis(5)));
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    let mut stdout_buf = Vec::new();
    if let Some(out) = child.0.stdout.take() {
        let _ = out.take(65_536).read_to_end(&mut stdout_buf);
    }
    if status.success() {
        return Ok(stdout_buf);
    }
    let mut stderr_buf = Vec::new();
    if let Some(err) = child.0.stderr.take() {
        let _ = err.take(4096).read_to_end(&mut stderr_buf);
    }
    let err_str = String::from_utf8_lossy(&stderr_buf).trim().to_string();
    Err(if err_str.is_empty() { format!("exit status {status}") } else { err_str })
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

enum ReleaseFetch {
    NotModified,
    RateLimited,
    Updated(UpdateState, Vec<(String, String)>),
}

fn parse_release_payload(raw: &[u8], etag: String, prev: Option<&UpdateState>) -> Result<(UpdateState, Vec<(String, String)>), String> {
    let parsed = json::parse(std::str::from_utf8(raw).map_err(|_| "release response is not UTF-8")?)
        .map_err(|e| format!("invalid release JSON: {e}"))?;
    let tag_name = parsed.get_str("tag_name").map(str::trim).filter(|s| !s.is_empty())
        .ok_or("release JSON missing tag_name")?.to_string();
    let release_name = parsed.get_str("name").unwrap_or(&tag_name).to_string();
    let html_url = parsed.get_str("html_url").filter(|s| !s.is_empty()).unwrap_or(DEFAULT_RELEASE_URL).to_string();
    let summary = sanitize_release_summary(parsed.get_str("body").unwrap_or(""), &release_name);
    let assets = parsed.get("assets").and_then(Json::as_arr).map(|arr| {
        arr.iter().filter_map(|i| Some((i.get_str("name")?.to_string(), i.get_str("browser_download_url")?.to_string()))).collect()
    }).unwrap_or_default();
    let mut state = prev.cloned().unwrap_or_default();
    state.checked_at_ms = now_ms();
    state.latest_tag = tag_name;
    state.release_name = release_name;
    state.summary = summary;
    state.html_url = html_url;
    if !etag.is_empty() { state.etag = etag; }
    Ok((state, assets))
}

fn fetch_latest_release_conditional(timeout_secs: &str, prev: Option<&UpdateState>) -> Result<ReleaseFetch, String> {
    let hdr_path = std::env::temp_dir().join(format!("ctx-upd-hdr-{}-{}.tmp", std::process::id(), now_ms()));
    let mut cmd = crate::base::platform::hidden_command(crate::base::platform::resolve_tool("curl"));
    cmd.args(["-sSL", "--max-time", timeout_secs, "-H", "User-Agent: ctx-mcp", "-H", "Accept: application/vnd.github+json"]);
    if let Some(etag) = prev.map(|s| s.etag.as_str()).filter(|e| !e.is_empty()) {
        cmd.args(["-H", &format!("If-None-Match: {etag}")]);
    }
    cmd.arg("-D").arg(&hdr_path).args(["-w", "\n%{http_code}", "--", RELEASES_LATEST_URL]);
    let res = run_hidden_output(cmd, false);
    let headers_str = fs::read_to_string(&hdr_path).unwrap_or_default();
    let _ = fs::remove_file(&hdr_path);

    let out = match res {
        Ok(bytes) => bytes,
        Err(_curl_err) => {
            #[cfg(windows)]
            {
                let raw = http_fetch(RELEASES_LATEST_URL, timeout_secs, true, None)?;
                let (st, assets) = parse_release_payload(&raw, String::new(), prev)?;
                return Ok(ReleaseFetch::Updated(st, assets));
            }
            #[cfg(not(windows))]
            return Err(format!("curl fetch failed: {_curl_err}"));
        }
    };
    let Some(split) = out.iter().rposition(|&b| b == b'\n') else {
        return Err("missing HTTP status line from curl".to_string());
    };
    let code_str = std::str::from_utf8(&out[split + 1..]).unwrap_or("").trim();
    let code = code_str.parse::<u16>().map_err(|_| format!("invalid HTTP status `{code_str}`"))?;
    match code {
        304 => Ok(ReleaseFetch::NotModified),
        403 | 429 => Ok(ReleaseFetch::RateLimited),
        200 => {
            let etag = parse_etag_from_headers(&headers_str);
            let (st, assets) = parse_release_payload(&out[..split], etag, prev)?;
            Ok(ReleaseFetch::Updated(st, assets))
        }
        other => Err(format!("GitHub releases API returned HTTP {other}")),
    }
}

fn fetch_latest_release_unconditional(timeout_secs: &str, prev: Option<&UpdateState>) -> Result<(UpdateState, Vec<(String, String)>), String> {
    let raw = http_fetch(RELEASES_LATEST_URL, timeout_secs, true, None)?;
    parse_release_payload(&raw, String::new(), prev)
}

struct UpdateLockGuard(PathBuf);
impl Drop for UpdateLockGuard {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

fn try_acquire_update_lock(lock_path: &Path) -> Option<UpdateLockGuard> {
    if let Some(parent) = lock_path.parent() {
        let _ = ensure_private_dir(parent);
    }
    if let Ok(meta) = fs::metadata(lock_path) {
        let fresh = meta.modified().ok().and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age < Duration::from_secs(UPDATE_LOCK_STALE_SECS));
        if fresh { return None; }
        let _ = fs::remove_file(lock_path);
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o600); }
    opts.open(lock_path).ok().map(|_| UpdateLockGuard(lock_path.to_path_buf()))
}

fn is_failed_tag_backed_off(st: &UpdateState, tag: &str, now: u64) -> bool {
    !tag.is_empty() && st.last_failed_tag == tag
        && st.last_failed_at_ms > 0
        && now.saturating_sub(st.last_failed_at_ms) < FAILED_TAG_BACKOFF_MS
}

fn is_managed_target_binary(dest: &Path) -> bool {
    if !dest.is_file() { return false; }
    if let (Ok(cur), Ok(target)) = (
        std::env::current_exe().and_then(fs::canonicalize),
        fs::canonicalize(dest),
    ) {
        if cur == target { return true; }
    }
    let stamp_path = dest.with_file_name(".ctx.sha256");
    let Ok(stamp) = fs::read_to_string(&stamp_path) else { return false; };
    let Ok(bytes) = fs::read(dest) else { return false; };
    let fast = format!("{:016x}\n", fast_hash64(&bytes));
    let legacy = format!("{:016x}\n", fnv1a_64(&bytes));
    stamp == fast || stamp == legacy
}

fn verify_staged_binary(bin_path: &Path, expected_tag: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(bin_path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod staged binary: {e}"))?;
    }
    let expected_ver = expected_tag.trim().trim_start_matches(['v', 'V']);
    let mut vcmd = crate::base::platform::hidden_command(bin_path);
    vcmd.arg("--version");
    let ver_out = run_command_with_timeout(vcmd, Duration::from_secs(3))
        .map_err(|e| format!("staged --version check failed: {e}"))?;
    let ver_str = String::from_utf8_lossy(&ver_out);
    if !expected_ver.is_empty() && !ver_str.contains(expected_ver) {
        return Err(format!("staged --version mismatch: expected `{expected_ver}`, got `{}`", ver_str.trim()));
    }
    let mut pcmd = crate::base::platform::hidden_command(bin_path);
    pcmd.args(["mcp", "--protocol-check"]);
    run_command_with_timeout(pcmd, Duration::from_secs(5))
        .map_err(|e| format!("staged mcp --protocol-check failed: {e}"))?;
    Ok(())
}

/// Non-blocking, ETag/TTL-cached background release check (at most once per CLI/MCP process).
pub fn maybe_spawn_background_update_check() {
    if update_check_disabled() { return; }
    let path = state_file_path();
    let prev = read_state_from(&path);
    if let Some(ref st) = prev {
        if st.checked_at_ms > 0 && now_ms().saturating_sub(st.checked_at_ms) < update_ttl_ms() { return; }
    }
    if BG_CHECK_STARTED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_err() { return; }
    let _ = std::thread::Builder::new().name("ctx-update-chk".into()).spawn(move || {
        match fetch_latest_release_conditional("3", prev.as_ref()) {
            Ok(ReleaseFetch::Updated(state, _)) => { let _ = write_state_to(&path, &state); }
            Ok(ReleaseFetch::NotModified | ReleaseFetch::RateLimited) => {
                if let Some(mut st) = prev {
                    st.checked_at_ms = now_ms();
                    let _ = write_state_to(&path, &st);
                }
            }
            Err(_) => {}
        }
    });
}

fn should_auto_apply(policy: AutoUpdatePolicy, latest_tag: &str, current: &str) -> bool {
    match policy {
        AutoUpdatePolicy::Off => false,
        AutoUpdatePolicy::Patch => is_patch_upgrade(latest_tag, current),
        AutoUpdatePolicy::All => is_stable_upgrade(latest_tag, current),
    }
}

/// Periodic housekeeping tick run by `ctx daemon`'s 30s background thread.
/// Returns `true` when `~/.local/bin/ctx` is now newer than `CURRENT_VERSION` and the
/// daemon should gracefully save its snapshot and exit so the next RPC spawns the new binary.
pub fn daemon_housekeeping_update_tick() -> bool {
    if update_check_disabled() { return false; }
    if let Ok(home) = effective_home_dir() {
        let stamp = version_stamp_for_bin(&target_ctx_bin(&home));
        if let Some(disk_ver) = read_installed_version_from(&stamp) {
            if is_newer_version(&disk_ver, CURRENT_VERSION) {
                return true;
            }
        }
    }
    let path = state_file_path();
    let prev = read_state_from(&path);
    let now = now_ms();
    if let Some(ref st) = prev {
        if st.checked_at_ms > 0 && now.saturating_sub(st.checked_at_ms) < update_ttl_ms() {
            return false;
        }
    }
    let Some(_lock) = try_acquire_update_lock(&lock_file_path()) else { return false; };
    let (mut state, assets) = match fetch_latest_release_conditional("4", prev.as_ref()) {
        Ok(ReleaseFetch::Updated(st, assets)) => (st, Some(assets)),
        Ok(ReleaseFetch::NotModified) => {
            if let Some(mut st) = prev {
                st.checked_at_ms = now_ms();
                let _ = write_state_to(&path, &st);
                (st, None)
            } else {
                return false;
            }
        }
        Ok(ReleaseFetch::RateLimited) => {
            if let Some(mut st) = prev {
                st.checked_at_ms = now_ms();
                let _ = write_state_to(&path, &st);
            }
            return false;
        }
        Err(_) => return false,
    };
    let _ = write_state_to(&path, &state);

    let (policy, _) = current_auto_update_policy();
    if !should_auto_apply(policy, &state.latest_tag, CURRENT_VERSION) {
        return false;
    }
    if is_failed_tag_backed_off(&state, &state.latest_tag, now_ms()) {
        return false;
    }
    let Ok(home) = effective_home_dir() else { return false; };
    let dest = target_ctx_bin(&home);
    if !is_managed_target_binary(&dest) {
        return false;
    }
    let asset_list = match assets {
        Some(a) if !a.is_empty() => a,
        _ => match fetch_latest_release_unconditional("8", Some(&state)) {
            Ok((fresh_st, a)) => { state = fresh_st; a }
            Err(_) => return false,
        },
    };
    match download_verify_and_install(&dest, &state.latest_tag, &asset_list, false) {
        Ok(()) => {
            state.auto_upgraded_from = CURRENT_VERSION.to_string();
            state.auto_upgraded_to = state.latest_tag.clone();
            state.auto_upgraded_at_ms = now_ms();
            state.last_failed_tag.clear();
            state.last_failed_at_ms = 0;
            let _ = write_state_to(&path, &state);
            true
        }
        Err(_) => {
            state.last_failed_tag = state.latest_tag.clone();
            state.last_failed_at_ms = now_ms();
            let _ = write_state_to(&path, &state);
            false
        }
    }
}

fn format_update_notice(
    st: &UpdateState,
    current: &str,
    installed: &str,
    flavor: &str,
    hint: Option<&str>,
) -> Option<String> {
    // If an auto-upgrade already replaced the installed binary beyond this process's version,
    // emit a single informational confirmation and never nag to run `ctx update`.
    if flavor == "upstream"
        && is_newer_version(installed, current)
        && !st.auto_upgraded_to.is_empty()
        && !is_newer_version(&st.latest_tag, installed)
    {
        let from = if st.auto_upgraded_from.is_empty() { current } else { st.auto_upgraded_from.as_str() };
        return Some(format!(
            "[ctx update] Auto-upgraded ctx v{from} -> {} (SHA-256 & protocol-check verified; daemon hot-swapped).\n\
             Opt out anytime: `ctx update --auto off` or AGENT_CTX_NO_UPDATE_CHECK=1.",
            st.auto_upgraded_to
        ));
    }
    if !is_newer_version(&st.latest_tag, installed) { return None; }
    let url = if st.html_url.is_empty() { DEFAULT_RELEASE_URL } else { st.html_url.as_str() };
    let summary = if st.summary.is_empty() { "new release available" } else { st.summary.as_str() };
    Some(if flavor == "upstream" {
        format!(
            "[ctx update] v{installed} -> {} available ({url}): {summary}\n\
             Notice for user only (agents: do not run without explicit user approval): upgrade manually via `ctx update`, or set AGENT_CTX_NO_UPDATE_CHECK=1 to disable.",
            st.latest_tag
        )
    } else {
        let h = hint.unwrap_or("your local rebuild script");
        format!(
            "[ctx update] upstream {} available ({url}): {summary}\n\
             Notice for user only (local {flavor} build; agents: do not run without explicit user approval): rebuild manually via {h} (or `ctx update --rebuild`).",
            st.latest_tag
        )
    })
}

fn pending_update_notice_from(
    state_path: &Path,
    version_stamp: Option<&Path>,
    session_key: &str,
    current: &str,
    flavor: &str,
    hint: Option<&str>,
) -> Option<String> {
    let installed = effective_installed_version(current, version_stamp);
    let notice = format_update_notice(&read_state_from(state_path)?, current, &installed, flavor, hint)?;
    let mut guard = NOTIFIED_SESSIONS.get_or_init(|| Mutex::new(HashSet::new())).lock().ok()?;
    if guard.contains(session_key) { return None; }
    if guard.len() >= MAX_NOTIFIED_SESSIONS { guard.clear(); }
    guard.insert(session_key.to_string());
    Some(notice)
}

/// Returns a 2-line user-only update notice at most once per `session_key` (cache only, zero network).
pub fn pending_update_notice_once(session_key: &str) -> Option<String> {
    if update_check_disabled() { return None; }
    let pol = ext::policy();
    let stamp = effective_home_dir().ok().map(|h| version_stamp_for_bin(&target_ctx_bin(&h)));
    pending_update_notice_from(&state_file_path(), stamp.as_deref(), session_key, CURRENT_VERSION, pol.build_flavor(), pol.update_hint())
}

/// Cached update status for `ctx status`, `ctx doctor`, and `ctx://status` (zero network).
pub fn update_status_json() -> Json {
    let flavor = ext::policy().build_flavor();
    let (auto_pol, auto_src) = current_auto_update_policy();
    let stamp = effective_home_dir().ok().map(|h| version_stamp_for_bin(&target_ctx_bin(&h)));
    let installed = effective_installed_version(CURRENT_VERSION, stamp.as_deref());
    let (latest, avail, summary, url, checked, etag_present, upgraded_to) = match read_state_from(&state_file_path()) {
        Some(s) => {
            let avail = is_newer_version(&s.latest_tag, &installed);
            let tag = if s.latest_tag.is_empty() { Json::Null } else { Json::Str(s.latest_tag) };
            let up = if s.auto_upgraded_to.is_empty() { Json::Null } else { Json::Str(s.auto_upgraded_to) };
            (tag, avail, s.summary, s.html_url, s.checked_at_ms as i64, !s.etag.is_empty(), up)
        }
        None => (Json::Null, false, String::new(), String::new(), 0i64, false, Json::Null),
    };
    Json::obj(vec![
        ("current", Json::Str(CURRENT_VERSION.to_string())),
        ("installed", Json::Str(installed)),
        ("flavor", Json::Str(flavor.to_string())),
        ("auto_update", Json::Str(auto_pol.as_str().to_string())),
        ("auto_update_source", Json::Str(auto_src.to_string())),
        ("ttl_secs", Json::Int(update_ttl_secs() as i64)),
        ("etag_cached", Json::Bool(etag_present)),
        ("latest", latest),
        ("update_available", Json::Bool(avail)),
        ("auto_upgraded_to", upgraded_to),
        ("summary", Json::Str(summary)),
        ("url", Json::Str(url)),
        ("checked_at_ms", Json::Int(checked)),
    ])
}

pub fn remove_update_state_file() {
    let _ = fs::remove_file(state_file_path());
    let _ = fs::remove_file(lock_file_path());
}

pub fn remove_update_config_files(bin: &Path) {
    let _ = fs::remove_file(policy_file_for_bin(bin));
    let _ = fs::remove_file(version_stamp_for_bin(bin));
}

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

fn atomic_install_binary(dest: &Path, bin_bytes: &[u8], stop_daemon: bool, installed_tag: &str) -> Result<(), String> {
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
    if stop_daemon {
        if let Err(e) = stop_daemon_for_install() {
            let _ = fs::remove_file(&staged);
            return Err(e);
        }
    }
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
    let ver_clean = installed_tag.trim().trim_start_matches(['v', 'V']);
    if !ver_clean.is_empty() {
        let _ = write_private_0600(&version_stamp_for_bin(dest), format!("{ver_clean}\n").as_bytes());
    }
    Ok(())
}

fn download_verify_and_install(
    dest: &Path,
    tag: &str,
    assets: &[(String, String)],
    stop_daemon: bool,
) -> Result<(), String> {
    let asset = platform_asset_name(std::env::consts::OS, std::env::consts::ARCH)
        .ok_or_else(|| format!("unsupported platform {}/{}", std::env::consts::OS, std::env::consts::ARCH))?;
    let bin_url = assets.iter().find(|(n, _)| n == asset).map(|(_, u)| u.as_str())
        .ok_or_else(|| format!("release {tag} missing `{asset}`"))?;
    let sums_url = assets.iter().find(|(n, _)| n == "SHA256SUMS").map(|(_, u)| u.as_str())
        .ok_or_else(|| format!("release {tag} missing SHA256SUMS"))?;
    let tmp = std::env::temp_dir().join(format!("ctx-upd-{}-{}", std::process::id(), now_ms()));
    ensure_private_dir(&tmp).map_err(|e| format!("create temp dir: {e}"))?;
    let res = (|| -> Result<(), String> {
        let sums_raw = http_fetch(sums_url, "15", false, None)?;
        let expected = find_sha256_entry(std::str::from_utf8(&sums_raw).map_err(|_| "SHA256SUMS not UTF-8")?, asset)
            .ok_or_else(|| format!("SHA256SUMS missing entry for {asset}"))?;
        let bin_tmp = tmp.join(asset);
        let _ = http_fetch(bin_url, "60", false, Some(&bin_tmp))?;
        let bytes = fs::read(&bin_tmp).map_err(|e| format!("read binary: {e}"))?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(&expected) {
            return Err(format!("SHA-256 mismatch for {asset}: expected {expected}, got {actual}"));
        }
        verify_staged_binary(&bin_tmp, tag)?;
        atomic_install_binary(dest, &bytes, stop_daemon, tag)
    })();
    let _ = fs::remove_dir_all(&tmp);
    res
}

fn run_upstream_update(force: bool) -> Result<String, String> {
    let _lock = try_acquire_update_lock(&lock_file_path())
        .ok_or_else(|| "another ctx update is already in progress".to_string())?;
    let path = state_file_path();
    let prev = read_state_from(&path);
    let (mut state, assets) = fetch_latest_release_unconditional("10", prev.as_ref())?;
    let dest = target_ctx_bin(&effective_home_dir()?);
    let installed = effective_installed_version(CURRENT_VERSION, Some(&version_stamp_for_bin(&dest)));
    let _ = write_state_to(&path, &state);
    if !force && !is_newer_version(&state.latest_tag, &installed) {
        return Ok(format!("ctx update: already up to date (current=v{installed}, latest={})", state.latest_tag));
    }
    download_verify_and_install(&dest, &state.latest_tag, &assets, true)?;
    state.last_failed_tag.clear();
    state.last_failed_at_ms = 0;
    let _ = write_state_to(&path, &state);
    Ok(format!("ctx update: upgraded v{installed} -> {} at {} (SHA-256 & protocol-check verified; daemon hot-swap ready)", state.latest_tag, dest.display()))
}

fn run_update_check(flavor: &str, hint: Option<&str>, as_json: bool) -> i32 {
    let path = state_file_path();
    let prev = read_state_from(&path);
    match fetch_latest_release_conditional("5", prev.as_ref()) {
        Ok(ReleaseFetch::Updated(st, _)) => {
            let _ = write_state_to(&path, &st);
            print_update_check_result(&st, flavor, hint, as_json);
            0
        }
        Ok(ReleaseFetch::NotModified) => {
            if let Some(mut st) = prev {
                st.checked_at_ms = now_ms();
                let _ = write_state_to(&path, &st);
                print_update_check_result(&st, flavor, hint, as_json);
                return 0;
            }
            match fetch_latest_release_unconditional("5", None) {
                Ok((st, _)) => {
                    let _ = write_state_to(&path, &st);
                    print_update_check_result(&st, flavor, hint, as_json);
                    0
                }
                Err(e) => { eprintln!("ctx update --check error: {e}"); 1 }
            }
        }
        Ok(ReleaseFetch::RateLimited) => {
            eprintln!("ctx update --check error: GitHub API rate-limited (retry later)");
            1
        }
        Err(e) => { eprintln!("ctx update --check error: {e}"); 1 }
    }
}

fn print_update_check_result(st: &UpdateState, flavor: &str, hint: Option<&str>, as_json: bool) {
    if as_json {
        println!("{}", update_status_json().to_json_string());
        return;
    }
    let stamp = effective_home_dir().ok().map(|h| version_stamp_for_bin(&target_ctx_bin(&h)));
    let installed = effective_installed_version(CURRENT_VERSION, stamp.as_deref());
    let (auto_pol, auto_src) = current_auto_update_policy();
    println!(
        "ctx update --check: current=v{installed} flavor={flavor} auto={} ({auto_src}) latest={} update_available={}",
        auto_pol.as_str(),
        st.latest_tag,
        is_newer_version(&st.latest_tag, &installed),
    );
    if let Some(n) = format_update_notice(st, CURRENT_VERSION, &installed, flavor, hint) {
        println!("{n}");
    }
}

pub fn run_update_cli(args: &[String]) -> i32 {
    let (mut check_only, mut rebuild, mut force, mut as_json) = (false, false, false, false);
    let mut auto_flag = false;
    let mut auto_value: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => check_only = true,
            "--rebuild" => rebuild = true,
            "--force" => force = true,
            "--json" => as_json = true,
            "--auto" => {
                auto_flag = true;
                if let Some(next) = args.get(i + 1) {
                    if !next.starts_with('-') {
                        auto_value = Some(next.clone());
                        i += 1;
                    }
                }
            }
            arg if arg.starts_with("--auto=") => {
                auto_flag = true;
                auto_value = Some(arg["--auto=".len()..].to_string());
            }
            other => { eprintln!("ctx update: invalid argument `{other}`"); return 1; }
        }
        i += 1;
    }

    let pol = ext::policy();
    let flavor = pol.build_flavor();

    if auto_flag {
        if let Some(raw_val) = auto_value {
            let Some(chosen) = AutoUpdatePolicy::parse(&raw_val) else {
                eprintln!("ctx update --auto: invalid mode `{raw_val}` (expected off | patch | all)");
                return 1;
            };
            if flavor != "upstream" && chosen != AutoUpdatePolicy::Off {
                eprintln!("ctx update --auto: local `{flavor}` build cannot auto-install upstream binaries (keeping off; use `ctx update --rebuild` manually)");
                return 1;
            }
            let Ok(home) = effective_home_dir() else {
                eprintln!("ctx update --auto error: cannot resolve home directory");
                return 1;
            };
            let cfg = policy_file_for_bin(&target_ctx_bin(&home));
            if let Err(e) = write_persisted_auto_policy(&cfg, chosen) {
                eprintln!("ctx update --auto error: {e}");
                return 1;
            }
            println!("ctx update --auto: {} (saved at {})", chosen.as_str(), cfg.display());
            return 0;
        }
        let (cur_pol, src) = current_auto_update_policy();
        if as_json {
            println!("{}", update_status_json().to_json_string());
        } else {
            println!("auto_update: {} (source: {}, flavor: {}, ttl_secs: {})", cur_pol.as_str(), src, flavor, update_ttl_secs());
        }
        return 0;
    }

    if check_only { return run_update_check(flavor, pol.update_hint(), as_json); }
    match decide_update_plan(flavor, pol.update_hint(), pol.rebuild_command(), rebuild) {
        UpdatePlan::CustomHint(hint) => {
            let path = state_file_path();
            let prev = read_state_from(&path);
            if let Ok(ReleaseFetch::Updated(st, _)) = fetch_latest_release_conditional("4", prev.as_ref()) {
                let _ = write_state_to(&path, &st);
                println!("ctx update: upstream {} ({}): {}", st.latest_tag, st.html_url, st.summary);
            } else if let Some(st) = prev.filter(|s| !s.latest_tag.is_empty()) {
                println!("ctx update: upstream {} ({}): {}", st.latest_tag, st.html_url, st.summary);
            }
            println!("Local {flavor} build active (v{CURRENT_VERSION}) — upstream binary will not overwrite it.\nRebuild manually via {hint} (or `ctx update --rebuild`).");
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
    fn semver_patch_vs_minor_major_and_prerelease_gating() {
        assert!(is_newer_version("v2.6.0", "2.5.0") && is_newer_version("2.5.1", "2.5.0") && is_newer_version("V3.0.0", "2.9.9") && is_newer_version("v2.5.0", "2.5.0-rc1"));
        assert!(!is_newer_version("v2.5.0", "2.5.0") && !is_newer_version("v2.4.9", "2.5.0") && !is_newer_version("v2.5.0-rc1", "2.5.0") && !is_newer_version("", "2.5.0") && !is_newer_version("invalid", "2.5.0"));

        assert!(is_patch_upgrade("v2.5.1", "2.5.0") && is_patch_upgrade("2.5.12", "2.5.2") && is_patch_upgrade("v2.5.0", "2.5.0-rc1"));
        assert!(!is_patch_upgrade("v2.6.0", "2.5.0") && !is_patch_upgrade("v3.0.0", "2.5.0") && !is_patch_upgrade("v2.5.1-rc1", "2.5.0") && !is_patch_upgrade("v2.5.0", "2.5.0") && !is_patch_upgrade("v2.4.9", "2.5.0"));

        assert!(should_auto_apply(AutoUpdatePolicy::Patch, "v2.5.3", "2.5.2"));
        assert!(!should_auto_apply(AutoUpdatePolicy::Patch, "v2.6.0", "2.5.2"));
        assert!(should_auto_apply(AutoUpdatePolicy::All, "v2.6.0", "2.5.2"));
        assert!(!should_auto_apply(AutoUpdatePolicy::All, "v2.6.0-beta1", "2.5.2"));
        assert!(!should_auto_apply(AutoUpdatePolicy::Off, "v2.5.3", "2.5.2"));
    }

    #[test]
    fn auto_update_policy_precedence_and_custom_flavor_guard() {
        let dir = std::env::temp_dir().join(format!("ctx-upd-pol-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let cfg = dir.join(".ctx.update.json");

        assert_eq!(resolve_auto_policy_from("upstream", false, None, Some(&cfg)), (AutoUpdatePolicy::Patch, "default"));
        assert_eq!(resolve_auto_policy_from("ctx-cxet", false, Some("all"), Some(&cfg)), (AutoUpdatePolicy::Off, "custom-flavor"));
        assert_eq!(resolve_auto_policy_from("upstream", true, Some("all"), Some(&cfg)), (AutoUpdatePolicy::Off, "env-disabled"));

        write_persisted_auto_policy(&cfg, AutoUpdatePolicy::Off).expect("write policy");
        assert_eq!(resolve_auto_policy_from("upstream", false, None, Some(&cfg)), (AutoUpdatePolicy::Off, "config"));
        assert_eq!(resolve_auto_policy_from("upstream", false, Some("all"), Some(&cfg)), (AutoUpdatePolicy::All, "env"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn etag_parsing_failed_backoff_and_single_flight_lock() {
        let headers = "HTTP/2 200\r\ncontent-type: application/json\r\nETag: W/\"abc123\x07def\"\r\n";
        assert_eq!(parse_etag_from_headers(headers), "W/\"abc123def\"");
        let redirected = "HTTP/1.1 302\r\nETag: \"old\"\r\n\r\nHTTP/2 200\r\netag: \"fresh-tag\"\r\n";
        assert_eq!(parse_etag_from_headers(redirected), "\"fresh-tag\"");

        let now = now_ms();
        let st = UpdateState { last_failed_tag: "v2.5.3".into(), last_failed_at_ms: now.saturating_sub(1_000), ..Default::default() };
        assert!(is_failed_tag_backed_off(&st, "v2.5.3", now));
        assert!(!is_failed_tag_backed_off(&st, "v2.5.4", now));
        assert!(!is_failed_tag_backed_off(&st, "v2.5.3", now + FAILED_TAG_BACKOFF_MS + 1));

        let dir = std::env::temp_dir().join(format!("ctx-upd-lock-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let lock_p = dir.join("update.lock");
        let g1 = try_acquire_update_lock(&lock_p).expect("first lock");
        assert!(try_acquire_update_lock(&lock_p).is_none(), "concurrent lock must be rejected");
        drop(g1);
        assert!(!lock_p.exists());
        assert!(try_acquire_update_lock(&lock_p).is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_notice_is_user_only_dedups_and_respects_installed_version_stamp() {
        let dir = std::env::temp_dir().join(format!("ctx-upd-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let st_path = dir.join("update_state.json");
        let ver_stamp = dir.join(".ctx.version");
        let st = UpdateState {
            checked_at_ms: now_ms(),
            latest_tag: "v2.6.0".into(),
            release_name: "v2.6.0".into(),
            summary: "hashline edit + impact".into(),
            html_url: "https://github.com/be0hhh/ctx-mcp/releases/tag/v2.6.0".into(),
            etag: "\"e1\"".into(),
            ..Default::default()
        };
        write_state_to(&st_path, &st).expect("write state");
        let (s1, s2, s3) = (
            format!("dedup-s1-{}", std::process::id()),
            format!("dedup-s2-{}", std::process::id()),
            format!("dedup-s3-{}", std::process::id()),
        );
        let first = pending_update_notice_from(&st_path, Some(&ver_stamp), &s1, "2.5.0", "upstream", None).expect("first");
        assert!(first.contains("v2.5.0 -> v2.6.0 available") && first.contains("Notice for user only"));
        assert!(first.contains("do not run without explicit user approval") && first.contains("AGENT_CTX_NO_UPDATE_CHECK=1"));
        assert!(!first.contains("Run `ctx update`"));
        assert!(pending_update_notice_from(&st_path, Some(&ver_stamp), &s1, "2.5.0", "upstream", None).is_none());

        let custom = pending_update_notice_from(&st_path, Some(&ver_stamp), &s2, "2.5.0", "ctx-custom", Some("python3 build.py")).expect("custom");
        assert!(custom.contains("local ctx-custom build") && custom.contains("python3 build.py") && custom.contains("do not run without explicit user approval"));

        // Once installed binary stamp reaches v2.6.0, old `ctx mcp` stops nagging and shows auto-upgraded note if recorded
        fs::write(&ver_stamp, "2.6.0\n").expect("write version stamp");
        assert!(pending_update_notice_from(&st_path, Some(&ver_stamp), &s3, "2.5.0", "upstream", None).is_none());
        let upgraded = UpdateState { auto_upgraded_from: "2.5.0".into(), auto_upgraded_to: "v2.6.0".into(), auto_upgraded_at_ms: now_ms(), ..st };
        write_state_to(&st_path, &upgraded).expect("write upgraded state");
        let note = pending_update_notice_from(&st_path, Some(&ver_stamp), &s3, "2.5.0", "upstream", None).expect("upgraded note");
        assert!(note.contains("Auto-upgraded ctx v2.5.0 -> v2.6.0") && note.contains("ctx update --auto off"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_flavor_protection_sha256sums_and_verify_staged_gate() {
        assert_eq!(decide_update_plan("upstream", None, None, false), UpdatePlan::UpstreamBinary);
        assert_eq!(decide_update_plan("ctx-local", Some("make rebuild"), None, false), UpdatePlan::CustomHint("make rebuild"));
        static ARGS: &[&str] = &["bootstrap.py"];
        assert_eq!(decide_update_plan("ctx-local", Some("make rebuild"), Some(("python3", ARGS)), true), UpdatePlan::CustomRebuild(Some(("python3", ARGS))));
        let sums = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ctx-linux-x86_64\n";
        assert_eq!(find_sha256_entry(sums, "ctx-linux-x86_64").as_deref(), Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert!(find_sha256_entry(sums, "ctx-macos-arm64").is_none());

        #[cfg(unix)]
        {
            let dir = std::env::temp_dir().join(format!("ctx-upd-stage-{}", std::process::id()));
            let _ = fs::create_dir_all(&dir);
            let bad = dir.join("bad_ctx");
            fs::write(&bad, "#!/bin/sh\necho 'ctx 9.9.9'\nexit 1\n").unwrap();
            assert!(verify_staged_binary(&bad, "v2.5.3").is_err());

            let good = dir.join("good_ctx");
            fs::write(&good, "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ctx 2.5.3 (upstream)'; exit 0; fi\nif [ \"$1\" = \"mcp\" ] && [ \"$2\" = \"--protocol-check\" ]; then exit 0; fi\nexit 1\n").unwrap();
            assert!(verify_staged_binary(&good, "v2.5.3").is_ok());
            assert!(verify_staged_binary(&good, "v2.5.4").is_err());
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
