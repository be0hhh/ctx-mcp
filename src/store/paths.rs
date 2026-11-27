//! Canonical workspace path normalization, directory skip list, runtime/snapshot paths,
//! and WSL/Windows path style translation.

pub use crate::base::mode::runtime_dir;
use crate::base::security::find_superproject_root;
use crate::base::simd::FastHashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

const SHARED_REPO_KEY_CACHE_MAX: usize = 256;
static SHARED_REPO_KEY_CACHE: OnceLock<RwLock<FastHashMap<PathBuf, String>>> = OnceLock::new();

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

pub(crate) fn git_admin_dir(root: &Path) -> Option<PathBuf> {
    let marker = root.join(".git");
    if marker.is_dir() {
        return fs::canonicalize(marker).ok();
    }
    if !marker.is_file() {
        return None;
    }
    let pointer = fs::read_to_string(&marker).ok()?;
    let target = pointer.trim().strip_prefix("gitdir: ")?.trim();
    if target.is_empty() {
        return None;
    }
    fs::canonicalize(root.join(target)).ok()
}

pub(crate) fn git_common_dir(admin: &Path) -> Option<PathBuf> {
    match fs::read_to_string(admin.join("commondir")) {
        Ok(pointer) => {
            let target = pointer.trim();
            if target.is_empty() {
                return None;
            }
            fs::canonicalize(admin.join(target)).ok()
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(admin.to_owned()),
        Err(_) => None,
    }
}

/// Verifies a linked git worktree via bidirectional backlink:
/// `admin_dir.parent() == common_dir/worktrees` AND `admin_dir/gitdir` canonicalizes to
/// `ws_root/.git` (or `ws_root`). Returns `Some(common_dir)` only when both checks pass.
pub(crate) fn verified_linked_worktree_common(canon_ws: &Path) -> Option<PathBuf> {
    let marker = canon_ws.join(".git");
    if !fs::symlink_metadata(&marker)
        .ok()
        .is_some_and(|meta| meta.file_type().is_file())
    {
        return None;
    }
    let admin = git_admin_dir(canon_ws)?;
    let common = git_common_dir(&admin)?;
    if !admin
        .parent()
        .is_some_and(|dir| dir == common.join("worktrees"))
    {
        return None;
    }
    let backlink = fs::read_to_string(admin.join("gitdir")).ok()?;
    let target = backlink.trim();
    if target.is_empty() {
        return None;
    }
    let actual = fs::canonicalize(admin.join(target)).ok()?;
    if actual == marker || actual == canon_ws {
        Some(common)
    } else {
        None
    }
}

pub(crate) fn is_linked_worktree(parent: &Path, child: &Path) -> bool {
    let Some(parent_common) = git_admin_dir(parent).and_then(|a| git_common_dir(&a)) else {
        return false;
    };
    let canon_child = fs::canonicalize(child).unwrap_or_else(|_| child.to_path_buf());
    verified_linked_worktree_common(&canon_child)
        .is_some_and(|child_common| child_common == parent_common)
}

fn resolve_shared_repo_key(ws_root: &Path) -> String {
    let canon_ws = fs::canonicalize(ws_root).unwrap_or_else(|_| ws_root.to_path_buf());
    let marker = canon_ws.join(".git");
    if marker.is_dir() {
        return norm_key_from_canon(&canon_ws);
    }
    if marker.is_file() {
        if let Some(common_dir) = verified_linked_worktree_common(&canon_ws) {
            if common_dir.file_name() == Some(OsStr::new(".git")) {
                if let Some(parent) = common_dir.parent() {
                    return norm_key_from_canon(parent);
                }
            }
            return norm_key_from_canon(&common_dir);
        }
    }
    norm_key_from_canon(&canon_ws)
}

/// Returns the canonical workspace key shared across a main git repository and its
/// bidirectional-backlink-verified linked worktrees. Falls back fail-closed to
/// `norm_key_from_canon(ws_root)` if `.git` is missing, malformed, or forged.
pub fn shared_repo_key(ws_root: &Path) -> String {
    let cache = SHARED_REPO_KEY_CACHE.get_or_init(|| RwLock::new(FastHashMap::default()));
    if let Ok(guard) = cache.read() {
        if let Some(hit) = guard.get(ws_root) {
            return hit.clone();
        }
    }
    let resolved = resolve_shared_repo_key(ws_root);
    if let Ok(mut guard) = cache.write() {
        if guard.len() >= SHARED_REPO_KEY_CACHE_MAX && !guard.contains_key(ws_root) {
            guard.clear();
        }
        guard.insert(ws_root.to_path_buf(), resolved.clone());
    }
    resolved
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::security::generate_csprng_token;

    #[test]
    fn shared_repo_key_unifies_verified_worktree_and_rejects_forged_git_file() {
        let root = std::env::temp_dir().join(format!(
            "ctx-shared-key-{}",
            generate_csprng_token().unwrap()
        ));
        let main_repo = root.join("repo");
        let linked = root.join("wt-valid");
        let forged = root.join("wt-forged");
        let plain = root.join("plain");
        let admin = main_repo.join(".git/worktrees/wt-valid");
        fs::create_dir_all(&admin).unwrap();
        fs::create_dir_all(&linked).unwrap();
        fs::create_dir_all(&forged).unwrap();
        fs::create_dir_all(&plain).unwrap();

        fs::write(linked.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
        fs::write(forged.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
        fs::write(admin.join("commondir"), "../..\n").unwrap();
        fs::write(
            admin.join("gitdir"),
            linked.join(".git").to_string_lossy().as_bytes(),
        )
        .unwrap();

        let canon_main = fs::canonicalize(&main_repo).unwrap();
        let canon_linked = fs::canonicalize(&linked).unwrap();
        let canon_forged = fs::canonicalize(&forged).unwrap();
        let canon_plain = fs::canonicalize(&plain).unwrap();

        let main_key = shared_repo_key(&canon_main);
        assert_eq!(main_key, norm_key_from_canon(&canon_main));
        assert_eq!(shared_repo_key(&canon_linked), main_key);
        assert_eq!(shared_repo_key(&canon_forged), norm_key_from_canon(&canon_forged));
        assert_ne!(shared_repo_key(&canon_forged), main_key);
        assert_eq!(shared_repo_key(&canon_plain), norm_key_from_canon(&canon_plain));

        assert!(is_linked_worktree(&canon_main, &canon_linked));
        assert!(!is_linked_worktree(&canon_main, &canon_forged));

        #[cfg(unix)]
        {
            let symlink_evil = root.join("wt-symlink-evil");
            fs::create_dir_all(&symlink_evil).unwrap();
            std::os::unix::fs::symlink(linked.join(".git"), symlink_evil.join(".git")).unwrap();
            let canon_evil = fs::canonicalize(&symlink_evil).unwrap();
            assert_eq!(shared_repo_key(&canon_evil), norm_key_from_canon(&canon_evil));
            assert_ne!(shared_repo_key(&canon_evil), main_key);
            assert!(!is_linked_worktree(&canon_main, &canon_evil));
        }

        fs::remove_dir_all(&root).unwrap();
    }
}
