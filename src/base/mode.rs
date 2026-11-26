//! Canonical runtime directory and live `write` / `read-only` mode control (`ctx mode`).
//!
//! Resolution hierarchy (narrowing only from client to daemon):
//!   1. Process-local narrowing (`ctx mcp --read-only` or `AGENT_CTX_WRITE=0`) always blocks writes
//!      locally before RPC and hides write tools from `tools/list`.
//!   2. Daemon-side ceiling: `AGENT_CTX_WRITE` in daemon env if set, otherwise `runtime_dir()/mode.json`
//!      (re-read live on `mtime` change without restarting the daemon or IDE; default `write=on`).

use crate::base::json::{self, Json};
use crate::base::security::{ensure_private_dir, write_private_0600};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteModeSource {
    Default,
    Config,
    Env,
    Flag,
}

impl WriteModeSource {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Config => "config",
            Self::Env => "env",
            Self::Flag => "flag",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteModeStatus {
    pub enabled: bool,
    pub source: WriteModeSource,
}

#[derive(Default)]
struct ModeCache {
    path: PathBuf,
    mtime_ns: u64,
    size: u64,
    present: bool,
    enabled: bool,
}

static MODE_CACHE: Mutex<Option<ModeCache>> = Mutex::new(None);

pub fn runtime_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("AGENT_CTX_RUNTIME_DIR") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    #[cfg(unix)]
    {
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            if !xdg.trim().is_empty() && Path::new(&xdg).is_dir() {
                return PathBuf::from(xdg).join("agent-ctx");
            }
        }
        let uid = unix_uid_string();
        #[cfg(target_os = "linux")]
        if !uid.is_empty() && uid.bytes().all(|c| c.is_ascii_digit()) {
            let user_run = Path::new("/run/user").join(uid);
            if user_run.is_dir() {
                return user_run.join("agent-ctx");
            }
        }
        let shm = Path::new("/dev/shm");
        if shm.is_dir() {
            return shm.join(format!("agent-ctx-{}", uid));
        }
        std::env::temp_dir().join(format!("agent-ctx-{}", uid))
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.trim().is_empty() {
                return PathBuf::from(local).join("agent-ctx");
            }
        }
        std::env::temp_dir().join("agent-ctx")
    }
}

#[cfg(unix)]
fn unix_uid_string() -> &'static str {
    use std::sync::OnceLock;
    static UID: OnceLock<String> = OnceLock::new();
    UID.get_or_init(|| {
        if let Ok(meta) = fs::metadata("/proc/self") {
            use std::os::unix::fs::MetadataExt;
            return meta.uid().to_string();
        }
        std::env::var("USER").unwrap_or_else(|_| "user".to_string())
    })
    .as_str()
}

pub fn mode_file_path() -> PathBuf {
    runtime_dir().join("mode.json")
}

pub fn parse_write_env(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" | "rw" | "write" => Some(true),
        "0" | "false" | "off" | "no" | "ro" | "read-only" | "readonly" => Some(false),
        _ => None,
    }
}

pub fn env_write_override() -> Option<bool> {
    std::env::var("AGENT_CTX_WRITE")
        .ok()
        .and_then(|v| parse_write_env(&v))
}

fn read_mode_file_cached(path: &Path) -> Option<bool> {
    let meta = match fs::metadata(path) {
        Ok(m) if m.is_file() => m,
        _ => {
            if let Ok(mut guard) = MODE_CACHE.lock() {
                *guard = Some(ModeCache {
                    path: path.to_path_buf(),
                    mtime_ns: 0,
                    size: 0,
                    present: false,
                    enabled: true,
                });
            }
            return None;
        }
    };
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0);
    let size = meta.len();

    if let Ok(guard) = MODE_CACHE.lock() {
        if let Some(ref c) = *guard {
            if c.present && c.path == path && c.mtime_ns == mtime_ns && c.size == size {
                return Some(c.enabled);
            }
        }
    }

    let raw = fs::read_to_string(path).ok()?;
    let parsed = json::parse(&raw).ok()?;
    let enabled = parsed.get_bool("write_enabled")?;
    if let Ok(mut guard) = MODE_CACHE.lock() {
        *guard = Some(ModeCache {
            path: path.to_path_buf(),
            mtime_ns,
            size,
            present: true,
            enabled,
        });
    }
    Some(enabled)
}

/// Effective write mode for the current process/daemon.
pub fn current_write_mode(cli_flag: Option<bool>) -> WriteModeStatus {
    if let Some(flag) = cli_flag {
        return WriteModeStatus {
            enabled: flag,
            source: WriteModeSource::Flag,
        };
    }
    if let Some(env_val) = env_write_override() {
        return WriteModeStatus {
            enabled: env_val,
            source: WriteModeSource::Env,
        };
    }
    let path = mode_file_path();
    if let Some(cfg_val) = read_mode_file_cached(&path) {
        return WriteModeStatus {
            enabled: cfg_val,
            source: WriteModeSource::Config,
        };
    }
    WriteModeStatus {
        enabled: true,
        source: WriteModeSource::Default,
    }
}

/// Persists global write mode in `runtime_dir()/mode.json` (takes effect live on next call).
pub fn set_persisted_write_mode(enabled: bool) -> Result<PathBuf, String> {
    let dir = runtime_dir();
    ensure_private_dir(&dir)?;
    let path = dir.join("mode.json");
    let body = Json::obj(vec![("write_enabled", Json::Bool(enabled))]).to_json_string();
    write_private_0600(&path, body.as_bytes())?;
    if let Ok(mut guard) = MODE_CACHE.lock() {
        *guard = None;
    }
    Ok(path)
}

pub fn remove_persisted_mode_file() {
    let _ = fs::remove_file(mode_file_path());
    if let Ok(mut guard) = MODE_CACHE.lock() {
        *guard = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_write_env_variants() {
        assert_eq!(parse_write_env("1"), Some(true));
        assert_eq!(parse_write_env("write"), Some(true));
        assert_eq!(parse_write_env("0"), Some(false));
        assert_eq!(parse_write_env("read-only"), Some(false));
        assert_eq!(parse_write_env("ro"), Some(false));
        assert_eq!(parse_write_env("maybe"), None);
    }

    #[test]
    fn cli_flag_takes_precedence() {
        let ro = current_write_mode(Some(false));
        assert!(!ro.enabled);
        assert_eq!(ro.source, WriteModeSource::Flag);
        let rw = current_write_mode(Some(true));
        assert!(rw.enabled);
        assert_eq!(rw.source, WriteModeSource::Flag);
    }
}
