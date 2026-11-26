//! Security primitives for `ctx`:
//!   1. OS CSPRNG 256-bit daemon auth token (`/dev/urandom` on Unix, Win32 `SystemFunction036` on Windows).
//!   2. Race-free `0600` private atomic file writer (`write_private_0600`) and directory guard.
//!   3. Superproject-aware `WorkspaceAllowlist` with single-canonicalize symlink-escape protection
//!      and a zero-allocation, code-safe generic secret denylist.

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

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(64);
    for &b in &entropy {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
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

#[inline]
fn starts_with_ascii_ci(hay: &[u8], prefix: &[u8]) -> bool {
    hay.len() >= prefix.len() && hay[..prefix.len()].eq_ignore_ascii_case(prefix)
}

#[inline]
fn ends_with_ascii_ci(hay: &[u8], suffix: &[u8]) -> bool {
    hay.len() >= suffix.len() && hay[hay.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

#[inline]
fn contains_ascii_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

#[inline(never)]
fn matches_any_ascii_ci(seg: &[u8], list: &[&[u8]]) -> bool {
    list.iter().any(|&item| seg.eq_ignore_ascii_case(item))
}

const fn pack_ext(s: &[u8]) -> u64 {
    let mut acc = 0u64;
    let mut i = 0usize;
    while i < s.len() {
        acc |= (s[i] as u64) << (i * 8);
        i += 1;
    }
    acc
}

#[inline]
fn pack_ascii_lower_u64(s: &[u8]) -> u64 {
    if s.is_empty() || s.len() > 8 {
        return 0;
    }
    let mut acc = 0u64;
    for (i, &b) in s.iter().enumerate() {
        if b == 0 {
            return 0;
        }
        acc |= (b.to_ascii_lowercase() as u64) << (i * 8);
    }
    acc
}

/// Zero-allocation lexical sensitivity check over `OsStr::as_encoded_bytes()`,
/// handling `/` and `\` uniformly across Unix and Windows.
pub fn is_sensitive_path_lexical(p: &Path) -> bool {
    const SENSITIVE_COMPONENTS: &[&[u8]] = &[
        b".ssh",
        b".aws",
        b".gnupg",
        b".secrets",
        b"auth.json",
        b".netrc",
        b".npmrc",
        b".pypirc",
        b"known_hosts",
        b"private.ini",
    ];
    const SAFE_MANIFESTS: &[&[u8]] = &[
        b"hooks.json",
        b"mcp_config.json",
        b".mcp.json",
        b"settings.json",
        b"skills.json",
        b"workflow.json",
        b"package.json",
        b"tsconfig.json",
        b"cargo.toml",
        b"pyproject.toml",
    ];

    // Block root virtual filesystems `/proc`, `/sys`, `/dev` (with `/` or `\` prefix).
    let raw = p.as_os_str().as_encoded_bytes();
    if matches!(raw.first(), Some(b'/' | b'\\')) {
        let mut idx = 0usize;
        while idx < raw.len() && matches!(raw[idx], b'/' | b'\\') {
            idx += 1;
        }
        let rest = &raw[idx..];
        let seg_end = rest
            .iter()
            .position(|&b| b == b'/' || b == b'\\')
            .unwrap_or(rest.len());
        let first_seg = &rest[..seg_end];
        if first_seg.eq_ignore_ascii_case(b"proc")
            || first_seg.eq_ignore_ascii_case(b"sys")
            || first_seg.eq_ignore_ascii_case(b"dev")
        {
            return true;
        }
    }

    let mut prev_was_cfg = false;
    let mut saw_docs = false;
    let mut in_docs = false;
    let mut last_seg: &[u8] = b"";

    for seg in raw.split(|&b| b == b'/' || b == b'\\') {
        if seg.is_empty() || seg == b"." {
            continue;
        }
        if seg == b".." || (seg.len() == 2 && seg[1] == b':' && seg[0].is_ascii_alphabetic()) {
            prev_was_cfg = false;
            continue;
        }
        if saw_docs {
            in_docs = true;
        }
        if prev_was_cfg && seg.eq_ignore_ascii_case(b"private") {
            return true;
        }
        if (4..=11).contains(&seg.len()) && matches_any_ascii_ci(seg, SENSITIVE_COMPONENTS) {
            return true;
        }
        if seg.len() >= 6
            && (seg[0] | 0x20) == b'i'
            && (starts_with_ascii_ci(seg, b"id_rsa")
                || starts_with_ascii_ci(seg, b"id_ed25519")
                || starts_with_ascii_ci(seg, b"id_ecdsa"))
        {
            return true;
        }
        if seg[0] == b'.'
            && (seg.eq_ignore_ascii_case(b".env")
                || (starts_with_ascii_ci(seg, b".env.")
                    && !ends_with_ascii_ci(seg, b".example")
                    && !ends_with_ascii_ci(seg, b".sample")
                    && !ends_with_ascii_ci(seg, b".template")))
        {
            return true;
        }
        prev_was_cfg = seg.len() == 3 && seg.eq_ignore_ascii_case(b"cfg");
        if seg.len() == 4 && seg.eq_ignore_ascii_case(b"docs") {
            saw_docs = true;
        }
        last_seg = seg;
    }

    let ext: &[u8] = match last_seg.iter().rposition(|&b| b == b'.') {
        Some(dot) if dot > 0 => &last_seg[dot + 1..],
        _ => b"",
    };

    let ext_key = pack_ascii_lower_u64(ext);
    const EXT_PEM: u64 = pack_ext(b"pem");
    const EXT_KEY: u64 = pack_ext(b"key");
    const EXT_P12: u64 = pack_ext(b"p12");
    const EXT_PFX: u64 = pack_ext(b"pfx");
    const EXT_PPK: u64 = pack_ext(b"ppk");
    const EXT_KDBX: u64 = pack_ext(b"kdbx");
    const EXT_JKS: u64 = pack_ext(b"jks");
    const EXT_KEYSTORE: u64 = pack_ext(b"keystore");
    if matches!(
        ext_key,
        EXT_PEM | EXT_KEY | EXT_P12 | EXT_PFX | EXT_PPK | EXT_KDBX | EXT_JKS | EXT_KEYSTORE
    ) {
        return true;
    }

    const EXT_H: u64 = pack_ext(b"h");
    const EXT_HPP: u64 = pack_ext(b"hpp");
    const EXT_IPP: u64 = pack_ext(b"ipp");
    const EXT_HH: u64 = pack_ext(b"hh");
    const EXT_HXX: u64 = pack_ext(b"hxx");
    const EXT_INL: u64 = pack_ext(b"inl");
    const EXT_TPP: u64 = pack_ext(b"tpp");
    const EXT_C: u64 = pack_ext(b"c");
    const EXT_CC: u64 = pack_ext(b"cc");
    const EXT_CPP: u64 = pack_ext(b"cpp");
    const EXT_CXX: u64 = pack_ext(b"cxx");
    const EXT_RS: u64 = pack_ext(b"rs");
    const EXT_PY: u64 = pack_ext(b"py");
    const EXT_PYI: u64 = pack_ext(b"pyi");
    const EXT_TS: u64 = pack_ext(b"ts");
    const EXT_TSX: u64 = pack_ext(b"tsx");
    const EXT_JS: u64 = pack_ext(b"js");
    const EXT_MJS: u64 = pack_ext(b"mjs");
    const EXT_GO: u64 = pack_ext(b"go");
    const EXT_JAVA: u64 = pack_ext(b"java");
    const EXT_CS: u64 = pack_ext(b"cs");
    const EXT_MD: u64 = pack_ext(b"md");
    const EXT_MARKDOWN: u64 = pack_ext(b"markdown");
    const EXT_CMAKE: u64 = pack_ext(b"cmake");
    const EXT_SH: u64 = pack_ext(b"sh");
    const EXT_BASH: u64 = pack_ext(b"bash");
    const EXT_PS1: u64 = pack_ext(b"ps1");
    const EXT_HTML: u64 = pack_ext(b"html");
    const EXT_CSS: u64 = pack_ext(b"css");
    let is_code_or_doc = matches!(
        ext_key,
        EXT_H
            | EXT_HPP
            | EXT_IPP
            | EXT_HH
            | EXT_HXX
            | EXT_INL
            | EXT_TPP
            | EXT_C
            | EXT_CC
            | EXT_CPP
            | EXT_CXX
            | EXT_RS
            | EXT_PY
            | EXT_PYI
            | EXT_TS
            | EXT_TSX
            | EXT_JS
            | EXT_MJS
            | EXT_GO
            | EXT_JAVA
            | EXT_CS
            | EXT_MD
            | EXT_MARKDOWN
            | EXT_CMAKE
            | EXT_SH
            | EXT_BASH
            | EXT_PS1
            | EXT_HTML
            | EXT_CSS
    );
    if !is_code_or_doc && !in_docs && !matches_any_ascii_ci(last_seg, SAFE_MANIFESTS) {
        if contains_ascii_ci(last_seg, b"secret")
            || contains_ascii_ci(last_seg, b"credential")
            || contains_ascii_ci(last_seg, b"apikey")
            || contains_ascii_ci(last_seg, b"api_key")
            || contains_ascii_ci(last_seg, b"oauth")
        {
            return true;
        }
    }

    false
}

pub fn is_sensitive_path(raw_path: &Path) -> bool {
    if is_sensitive_path_lexical(raw_path) {
        return true;
    }
    if let Ok(canon) = fs::canonicalize(raw_path) {
        if is_sensitive_path_lexical(&canon) {
            return true;
        }
    }
    false
}

fn canonical_file_path(raw_path: &Path) -> Result<PathBuf, String> {
    if is_sensitive_path_lexical(raw_path) {
        return Err("REFUSED: sensitive path".to_string());
    }
    let canon = fs::canonicalize(raw_path).map_err(|e| e.to_string())?;
    if is_sensitive_path_lexical(&canon) {
        return Err("REFUSED: sensitive target path".to_string());
    }
    Ok(canon)
}

pub fn admit_file_in_workspace(raw_path: &Path, ws_root: &Path) -> Result<PathBuf, String> {
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
/// git submodules register the enclosing superproject root.
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
        "" | "/"
            | "/etc"
            | "/proc"
            | "/sys"
            | "/dev"
            | "/var"
            | "/usr"
            | "/bin"
            | "/sbin"
            | "/tmp"
            | "/home"
            | "/users"
            | "c:"
            | "c:/windows"
            | "c:/users"
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
            if let Ok(guard) = self.roots.read() {
                if guard.contains(&canon) {
                    return Some(canon);
                }
            }
            if !explicit_root && is_forbidden_broad_root(&canon) {
                return None;
            }
            canon
        };

        // Fast path: already-admitted roots have already passed `is_forbidden_broad_root`.
        if let Ok(guard) = self.roots.read() {
            if guard.contains(&candidate) {
                return Some(candidate);
            }
        }
        if is_forbidden_broad_root(&candidate) {
            return None;
        }
        if let Ok(mut guard) = self.roots.write() {
            guard.insert(candidate.clone());
        }
        Some(candidate)
    }

    fn longest_matching_root(&self, canon: &Path) -> Result<Option<PathBuf>, String> {
        let guard = self
            .roots
            .read()
            .map_err(|_| "allowlist lock poisoned".to_string())?;
        Ok(guard
            .iter()
            .filter(|root| canon.starts_with(root.as_path()))
            .max_by_key(|root| root.as_os_str().len())
            .cloned())
    }

    fn resolve_request_workspace(&self, cwd: &Path) -> Result<PathBuf, String> {
        if let Some(active_ws) = self.register_hint(cwd, false) {
            return Ok(active_ws);
        }
        let c_canon = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
        if let Some(active_ws) = self.longest_matching_root(&c_canon)? {
            return Ok(active_ws);
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
        if let Some(ws_root) = self.longest_matching_root(&canon)? {
            return Ok((canon, ws_root));
        }
        Err("REFUSED: path escapes workspace allowlist".to_string())
    }

    pub fn admit_dir(&self, raw_dir: &Path, cwd: Option<&Path>) -> Result<(PathBuf, PathBuf), String> {
        if is_sensitive_path_lexical(raw_dir) {
            return Err("REFUSED: sensitive directory".to_string());
        }
        let canon = fs::canonicalize(raw_dir).map_err(|e| format!("{}", e))?;
        if is_sensitive_path_lexical(&canon) {
            return Err("REFUSED: sensitive target directory".to_string());
        }
        if let Some(c) = cwd {
            let active_ws = self.resolve_request_workspace(c)?;
            if canon.starts_with(&active_ws) {
                return Ok((canon, active_ws));
            }
            return Err("REFUSED: directory escapes active request workspace".to_string());
        }
        if let Some(ws_root) = self.longest_matching_root(&canon)? {
            return Ok((canon, ws_root));
        }
        Err("REFUSED: directory escapes workspace allowlist".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_path_lexical_generic_rules() {
        // Blocked roots and directories.
        assert!(is_sensitive_path_lexical(Path::new("/proc/self/environ")));
        assert!(is_sensitive_path_lexical(Path::new("/SYS/devices")));
        assert!(is_sensitive_path_lexical(Path::new("/dev")));
        assert!(is_sensitive_path_lexical(Path::new("/repo/cfg/private/keys.toml")));
        assert!(is_sensitive_path_lexical(Path::new("repo\\CFG\\Private\\keys.toml")));

        // Blocked components and extensions.
        assert!(is_sensitive_path_lexical(Path::new("/home/u/.ssh/config")));
        assert!(is_sensitive_path_lexical(Path::new("/repo/.env")));
        assert!(is_sensitive_path_lexical(Path::new("/repo/.env.production")));
        assert!(!is_sensitive_path_lexical(Path::new("/repo/.env.example")));
        assert!(!is_sensitive_path_lexical(Path::new("/repo/.env.sample")));
        assert!(!is_sensitive_path_lexical(Path::new("/repo/.env.template")));
        assert!(is_sensitive_path_lexical(Path::new("/repo/id_ed25519")));
        assert!(is_sensitive_path_lexical(Path::new("/repo/tls/server.PEM")));
        assert!(is_sensitive_path_lexical(Path::new("/repo/oauth_tokens.json")));

        // Code, docs, and safe manifests remain allowed.
        assert!(!is_sensitive_path_lexical(Path::new("/repo/src/oauth_client.rs")));
        assert!(!is_sensitive_path_lexical(Path::new("/repo/docs/api_key_guide.json")));
        assert!(!is_sensitive_path_lexical(Path::new("/repo/mcp_config.json")));
        assert!(!is_sensitive_path_lexical(Path::new("/repo/Cargo.toml")));

        // Legacy repo-specific entries were removed.
        assert!(!is_sensitive_path_lexical(Path::new("/repo/vstack.ini")));
        assert!(!is_sensitive_path_lexical(Path::new("/repo/servers.local.toml")));
        assert!(!is_sensitive_path_lexical(Path::new("/repo/deploy/cfg/app.toml")));
        assert!(!is_sensitive_path_lexical(Path::new("/repo/deploy/private/app.toml")));
    }
}
