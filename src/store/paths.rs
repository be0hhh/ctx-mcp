//! Canonical workspace path normalization, directory skip list, runtime/snapshot paths,
//! and WSL/Windows path style translation.

pub use crate::base::mode::runtime_dir;
use crate::base::security::find_superproject_root;
use std::fs;
use std::path::{Path, PathBuf};

/// Single canonical directory exclusion filter shared across workspace indexing, inspection,
/// and search traversal.
pub fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "__pycache__"
            | ".venv"
            | "venv"
            | ".cache"
            | ".serena"
            | "dist"
            | ".next"
    ) || name.starts_with("build")
}

pub fn default_snapshot_path() -> PathBuf {
    if let Ok(custom) = std::env::var("AGENT_CTX_SNAPSHOT_PATH") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    #[cfg(unix)]
    {
        if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            if !xdg.trim().is_empty() {
                return PathBuf::from(xdg).join("agent-ctx").join("snapshot.bin");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.trim().is_empty() {
                return PathBuf::from(home)
                    .join(".cache")
                    .join("agent-ctx")
                    .join("snapshot.bin");
            }
        }
        std::env::temp_dir().join("agent-ctx-snapshot.bin")
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.trim().is_empty() {
                return PathBuf::from(local).join("agent-ctx").join("snapshot.bin");
            }
        }
        std::env::temp_dir().join("agent-ctx-snapshot.bin")
    }
}

pub fn norm_path(path: &Path) -> String {
    let resolved = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    norm_key_from_canon(&resolved)
}

pub fn norm_key_from_canon(canon: &Path) -> String {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut s = canon.to_string_lossy().into_owned();
    #[cfg(windows)]
    {
        if let Some(stripped) = s.strip_prefix("\\\\?\\") {
            s = stripped.to_string();
        }
        s = s.replace('\\', "/").to_ascii_lowercase();
    }
    s
}

/// Formats `path` as an exact forward-slash path relative to `ws_root` (or its detected
/// superproject `.git` root). Fast-paths already-canonical paths without redundant syscalls.
pub fn display_workspace_path(path: &Path, ws_root: Option<&Path>) -> String {
    if let Some(root) = ws_root {
        if let Ok(rel) = path.strip_prefix(root) {
            if !rel.as_os_str().is_empty() {
                let raw = rel.to_string_lossy();
                return if raw.contains('\\') {
                    raw.replace('\\', "/")
                } else {
                    raw.into_owned()
                };
            }
        }
    }

    let canon_p = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let root_opt = ws_root
        .map(|r| fs::canonicalize(r).unwrap_or_else(|_| r.to_path_buf()))
        .or_else(|| find_superproject_root(&canon_p));

    if let Some(root) = root_opt {
        if let Ok(rel) = canon_p.strip_prefix(&root) {
            let s = rel.to_string_lossy().replace('\\', "/");
            if !s.is_empty() {
                return s;
            }
        }
    }
    let s = canon_p.to_string_lossy().replace('\\', "/");
    #[cfg(windows)]
    if let Some(stripped) = s.strip_prefix("//?/") {
        return stripped.to_string();
    }
    s
}

/// Translates Windows UNC WSL paths (`\\wsl.localhost\<Distro>\...`, `\\wsl$\<Distro>\...`)
/// and mounted Windows drive paths (`C:\...` -> `/mnt/c/...`) into Unix paths when running
/// on Unix / WSL2 so Windows Desktop App MCP & hook payloads resolve natively in RAM.
pub fn translate_host_path_str(raw: &str) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        let trimmed = raw.trim().trim_matches('"').trim_matches('\'');
        let norm = trimmed.replace('\\', "/");
        for prefix in ["//wsl.localhost/", "//wsl$/"] {
            if norm.len() > prefix.len() && norm[..prefix.len()].eq_ignore_ascii_case(prefix) {
                let after = &norm[prefix.len()..];
                if let Some((_distro, rest)) = after.split_once('/') {
                    return Some(PathBuf::from(format!("/{}", rest.trim_start_matches('/'))));
                }
                return Some(PathBuf::from("/"));
            }
        }
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
        {
            let drive = (bytes[0] as char).to_ascii_lowercase();
            let mnt_drive = PathBuf::from(format!("/mnt/{}", drive));
            if mnt_drive.is_dir() {
                let tail = norm[3..].trim_start_matches('/');
                return Some(if tail.is_empty() {
                    mnt_drive
                } else {
                    mnt_drive.join(tail)
                });
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = raw;
    }
    None
}

/// Restores the caller's original Windows UNC or drive-letter path style when rewriting
/// a resolved Unix path back to a Windows Desktop App client over WSL2.
pub fn restore_caller_path_style(raw_original: &str, resolved: &Path) -> String {
    #[cfg(unix)]
    {
        let trimmed = raw_original.trim().trim_matches('"').trim_matches('\'');
        let use_backslash = trimmed.contains('\\');
        let norm = trimmed.replace('\\', "/");
        for prefix in ["//wsl.localhost/", "//wsl$/"] {
            if norm.len() > prefix.len() && norm[..prefix.len()].eq_ignore_ascii_case(prefix) {
                let raw_prefix = &trimmed[..prefix.len()];
                let after = &norm[prefix.len()..];
                let distro = after.split('/').next().unwrap_or("");
                if !distro.is_empty() {
                    let rel = resolved.to_string_lossy();
                    let sep = if use_backslash { '\\' } else { '/' };
                    let body = if use_backslash {
                        rel.trim_start_matches('/').replace('/', "\\")
                    } else {
                        rel.trim_start_matches('/').to_string()
                    };
                    let head = if use_backslash {
                        raw_prefix.replace('/', "\\")
                    } else {
                        raw_prefix.replace('\\', "/")
                    };
                    return if body.is_empty() {
                        format!("{}{}", head, distro)
                    } else {
                        format!("{}{}{}{}", head, distro, sep, body)
                    };
                }
            }
        }
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
        {
            let drive_char = bytes[0] as char;
            let mnt_prefix = format!("/mnt/{}", drive_char.to_ascii_lowercase());
            let res_str = resolved.to_string_lossy();
            if res_str == mnt_prefix || res_str.starts_with(&format!("{}/", mnt_prefix)) {
                let tail = res_str[mnt_prefix.len()..].trim_start_matches('/');
                let sep = if use_backslash { '\\' } else { '/' };
                let formatted_tail = if use_backslash {
                    tail.replace('/', "\\")
                } else {
                    tail.to_string()
                };
                return format!("{}:{}{}", drive_char, sep, formatted_tail);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = raw_original;
    }
    resolved.to_string_lossy().into_owned()
}

pub fn resolve_input_path(raw: &str, cwd: Option<&Path>) -> PathBuf {
    let trimmed = raw.trim().trim_matches('"').trim_matches('\'');
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    if let Some(translated) = translate_host_path_str(trimmed) {
        return translated;
    }
    let p = PathBuf::from(trimmed);
    if p.is_absolute() {
        p
    } else if let Some(base) = cwd {
        base.join(p)
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

pub fn is_multimodal_or_binary_ext(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    let mut buf = [0u8; 12];
    if ext.len() > buf.len() || !ext.is_ascii() {
        return false;
    }
    for (i, b) in ext.bytes().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    let low = std::str::from_utf8(&buf[..ext.len()]).unwrap_or("");
    matches!(
        low,
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "bmp"
            | "ico"
            | "pdf"
            | "mp3"
            | "wav"
            | "ogg"
            | "mp4"
            | "mov"
            | "webm"
            | "zip"
            | "tar"
            | "gz"
            | "xz"
            | "zst"
            | "7z"
            | "o"
            | "a"
            | "so"
            | "dll"
            | "exe"
            | "dylib"
            | "wasm"
            | "sqlite"
            | "db"
            | "pb"
    )
}
