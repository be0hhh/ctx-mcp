//! Security primitives for `ctx`:
//!   1. OS CSPRNG 256-bit daemon auth token (`/dev/urandom` on Unix, Win32 `SystemFunction036` on Windows).
//!   2. Race-free `0600` private atomic file writer (`write_private_0600`) and directory guard.
//!   3. Superproject-aware `WorkspaceAllowlist` with `fs::canonicalize` symlink-escape protection
//!      and a code-safe secret denylist.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn generate_csprng_token() -> Result<String, String> {
    let mut entropy = [0u8; 32];

    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = fs::File::open("/dev/urandom")
            .map_err(|e| format!("failed to open /dev/urandom: {}", e))?;
        f.read_exact(&mut entropy)
            .map_err(|e| format!("failed to read /dev/urandom: {}", e))?;
    }

    #[cfg(windows)]
    {
        #[link(name = "advapi32")]
        extern "system" {
            fn SystemFunction036(random_buffer: *mut u8, random_buffer_length: u32) -> u8;
        }
        let ok = unsafe { SystemFunction036(entropy.as_mut_ptr(), entropy.len() as u32) };
        if ok == 0 {
            return Err("Win32 SystemFunction036 (RtlGenRandom) failed".to_string());
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        return Err("unsupported OS for CSPRNG token generation".to_string());
    }

    let mut hex = String::with_capacity(64);
    for &b in &entropy {
        hex.push_str(&format!("{:02x}", b));
    }
    Ok(hex)
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("cannot create dir {}: {}", dir.display(), e))?;
    let sym_meta = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if sym_meta.file_type().is_symlink() {
        return Err(format!("refusing symlinked state dir {}", dir.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

pub fn write_private_0600(target: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_private_dir(parent)?;
        }
    }
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let file_name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("state.bin");
    let tmp_path = target.with_file_name(format!(".{}.tmp.{}.{}", file_name, pid, seq));

    let open_res = {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&tmp_path)
    };

    let mut f = open_res.map_err(|e| format!("create temp {}: {}", tmp_path.display(), e))?;
    if let Err(e) = f.write_all(data).and_then(|_| f.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("write temp {}: {}", tmp_path.display(), e));
    }
    drop(f);

    if let Err(e) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "atomic rename {} -> {} failed: {}",
            tmp_path.display(),
            target.display(),
            e
        ));
    }
    Ok(())
}

fn check_single_sensitive(p: &Path) -> bool {
    let full_low = p.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    if full_low == "/proc"
        || full_low == "/sys"
        || full_low == "/dev"
        || full_low.starts_with("/proc/")
        || full_low.starts_with("/sys/")
        || full_low.starts_with("/dev/")
    {
        return true;
    }
    if full_low.contains("/deploy/cfg/")
        || full_low.contains("/deploy/private/")
        || full_low.contains("/cfg/private/")
    {
        return true;
    }

    for comp in p.components() {
        let part = comp.as_os_str().to_string_lossy().to_ascii_lowercase();
        if matches!(
            part.as_str(),
            ".ssh"
                | ".aws"
                | ".gnupg"
                | ".secrets"
                | "auth.json"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
                | "known_hosts"
                | "private.ini"
                | "vstack.ini"
                | "servers.local.toml"
        ) {
            return true;
        }
        if part.starts_with("id_rsa") || part.starts_with("id_ed25519") || part.starts_with("id_ecdsa") {
            return true;
        }
        if part == ".env"
            || (part.starts_with(".env.")
                && !part.ends_with(".example")
                && !part.ends_with(".sample")
                && !part.ends_with(".template"))
        {
            return true;
        }
    }

    let file_low = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let ext_low = p
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if matches!(
        ext_low.as_str(),
        "pem" | "key" | "p12" | "pfx" | "ppk" | "kdbx" | "jks" | "keystore"
    ) {
        return true;
    }

    // Code and documentation extensions are never blocked by fuzzy substring heuristics
    let is_code_or_doc = matches!(
        ext_low.as_str(),
        "h" | "hpp"
            | "ipp"
            | "hh"
            | "hxx"
            | "inl"
            | "tpp"
            | "c"
            | "cc"
            | "cpp"
            | "cxx"
            | "rs"
            | "py"
            | "pyi"
            | "ts"
            | "tsx"
            | "js"
            | "mjs"
            | "go"
            | "java"
            | "cs"
            | "md"
            | "markdown"
            | "cmake"
            | "sh"
            | "bash"
            | "ps1"
            | "html"
            | "css"
    );

    if !is_code_or_doc && !full_low.contains("/docs/") {
        let safe_manifest = matches!(
            file_low.as_str(),
            "ruleindex.json"
                | "agentrouting.json"
                | "hooks.json"
                | "mcp_config.json"
                | ".mcp.json"
                | "settings.json"
                | "skills.json"
                | "workflow.json"
                | "package.json"
                | "tsconfig.json"
                | "cargo.toml"
                | "pyproject.toml"
        );
        if !safe_manifest
            && (file_low.contains("secret")
                || file_low.contains("credential")
                || file_low.contains("apikey")
                || file_low.contains("api_key")
                || file_low.contains("oauth"))
        {
            return true;
        }
    }

    false
}

pub fn is_sensitive_path(raw_path: &Path) -> bool {
    if check_single_sensitive(raw_path) {
        return true;
    }
    if let Ok(canon) = fs::canonicalize(raw_path) {
        if check_single_sensitive(&canon) {
            return true;
        }
    }
    false
}

fn canonical_file_path(raw_path: &Path) -> Result<PathBuf, String> {
    if is_sensitive_path(raw_path) {
        return Err("REFUSED: sensitive path".to_string());
    }
    let canon = fs::canonicalize(raw_path).map_err(|e| e.to_string())?;
    if is_sensitive_path(&canon) {
        return Err("REFUSED: sensitive target path".to_string());
    }
    Ok(canon)
}

pub(crate) fn admit_file_in_workspace(raw_path: &Path, ws_root: &Path) -> Result<PathBuf, String> {
    let canon = canonical_file_path(raw_path)?;
    require_file_in_workspace(&canon, ws_root)?;
    Ok(canon)
}

fn require_file_in_workspace(canon: &Path, ws_root: &Path) -> Result<(), String> {
    if !canon.starts_with(ws_root) {
        return Err("REFUSED: path escapes active request workspace".to_string());
    }
    Ok(())
}

/// Climb to the outermost ancestor containing `.git` (dir or submodule gitfile) so
/// git submodules (`apps/trading-core`, `apps/diagnostic`, `extra/*`) register the
/// enclosing superproject root.
pub fn find_superproject_root(start: &Path) -> Option<PathBuf> {
    let base = if start.is_file() {
        start.parent().unwrap_or(start)
    } else {
        start
    };
    let canon = fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
    let mut outermost: Option<PathBuf> = None;
    let mut cur: Option<&Path> = Some(canon.as_path());
    while let Some(dir) = cur {
        if dir.join(".git").exists() {
            outermost = Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    outermost
}

pub fn is_forbidden_broad_root(canon: &Path) -> bool {
    if canon.parent().is_none() {
        return true;
    }
    let norm = canon.to_string_lossy().replace('\\', "/");
    let trimmed = norm.trim_end_matches('/');
    let low = trimmed.to_ascii_lowercase();
    if matches!(
        low.as_str(),
        "" | "/" | "/etc" | "/proc" | "/sys" | "/dev" | "/var" | "/usr" | "/bin" | "/sbin" | "/tmp" | "/home" | "/users" | "c:" | "c:/windows" | "c:/users"
    ) {
        return true;
    }
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        if !home.trim().is_empty() {
            let hc = fs::canonicalize(&home).unwrap_or_else(|_| PathBuf::from(&home));
            if canon == hc {
                return true;
            }
        }
    }
    let tmp = std::env::temp_dir();
    let tc = fs::canonicalize(&tmp).unwrap_or(tmp);
    if canon == tc {
        return true;
    }
    false
}

pub struct WorkspaceAllowlist {
    roots: RwLock<HashSet<PathBuf>>,
}

impl Default for WorkspaceAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkspaceAllowlist {
    pub fn new() -> Self {
        Self {
            roots: RwLock::new(HashSet::new()),
        }
    }

    pub fn root_count(&self) -> usize {
        self.roots.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Register a workspace root derived from `hint` (`cwd`, `workspacePaths`, or `--repo-root`).
    /// Prefers the outermost `.git` superproject root; falls back to `hint` itself when it is a
    /// concrete project directory (never `/`, `$HOME`, or `$TMPDIR` root).
    pub fn register_hint(&self, hint: &Path, explicit_root: bool) -> Option<PathBuf> {
        let candidate = if let Some(git_root) = find_superproject_root(hint) {
            git_root
        } else {
            let dir = if hint.is_file() { hint.parent()? } else { hint };
            let canon = fs::canonicalize(dir).ok()?;
            if !canon.is_dir() {
                return None;
            }
            if !explicit_root && is_forbidden_broad_root(&canon) {
                return None;
            }
            canon
        };

        if is_forbidden_broad_root(&candidate) {
            return None;
        }
        if let Ok(guard) = self.roots.read() {
            if guard.contains(&candidate) {
                return Some(candidate);
            }
        }
        if let Ok(mut guard) = self.roots.write() {
            guard.insert(candidate.clone());
        }
        Some(candidate)
    }

    fn resolve_request_workspace(&self, cwd: &Path) -> Result<PathBuf, String> {
        if let Some(active_ws) = self.register_hint(cwd, false) {
            return Ok(active_ws);
        }
        let c_canon = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
        let guard = self
            .roots
            .read()
            .map_err(|_| "allowlist lock poisoned".to_string())?;
        if let Some(active_ws) = guard
            .iter()
            .filter(|root| c_canon.starts_with(root.as_path()))
            .max_by_key(|root| root.as_os_str().len())
        {
            return Ok(active_ws.clone());
        }
        Err("REFUSED: request cwd is not an admitted workspace".to_string())
    }

    /// Canonicalizes `raw_path`, enforces the secret denylist before and after symlink resolution,
    /// and verifies containment inside the request's own active workspace root (when `cwd` is supplied)
    /// or a registered `WorkspaceAllowlist` root.
    pub fn admit_file(&self, raw_path: &Path, cwd: Option<&Path>) -> Result<(PathBuf, PathBuf), String> {
        let canon = canonical_file_path(raw_path)?;
        if let Some(c) = cwd {
            let active_ws = self.resolve_request_workspace(c)?;
            require_file_in_workspace(&canon, &active_ws)?;
            return Ok((canon, active_ws));
        }
        let guard = self
            .roots
            .read()
            .map_err(|_| "allowlist lock poisoned".to_string())?;
        if let Some(ws_root) = guard
            .iter()
            .filter(|root| canon.starts_with(root.as_path()))
            .max_by_key(|root| root.as_os_str().len())
        {
            return Ok((canon, ws_root.clone()));
        }
        Err("REFUSED: path escapes workspace allowlist".to_string())
    }

    pub fn admit_dir(&self, raw_dir: &Path, cwd: Option<&Path>) -> Result<(PathBuf, PathBuf), String> {
        if is_sensitive_path(raw_dir) {
            return Err("REFUSED: sensitive directory".to_string());
        }
        let canon = fs::canonicalize(raw_dir).map_err(|e| format!("{}", e))?;
        if is_sensitive_path(&canon) {
            return Err("REFUSED: sensitive target directory".to_string());
        }
        if let Some(c) = cwd {
            let active_ws = self.resolve_request_workspace(c)?;
            if canon.starts_with(&active_ws) {
                return Ok((canon, active_ws));
            }
            return Err("REFUSED: directory escapes active request workspace".to_string());
        }
        let guard = self
            .roots
            .read()
            .map_err(|_| "allowlist lock poisoned".to_string())?;
        if let Some(ws_root) = guard
            .iter()
            .filter(|root| canon.starts_with(root.as_path()))
            .max_by_key(|root| root.as_os_str().len())
        {
            return Ok((canon, ws_root.clone()));
        }
        Err("REFUSED: directory escapes workspace allowlist".to_string())
    }
}
