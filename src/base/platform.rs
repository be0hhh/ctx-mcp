//! Cross-platform OS helpers: cached external tool resolution, hidden subprocess creation,
//! and zero-dependency RAM budget detection (Linux `/proc/meminfo`, macOS `sysctlbyname`,
//! Windows `GlobalMemoryStatusEx`).

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

const MIN_ENV_RAM_MB: usize = 16;
const MIN_AUTO_RAM_BYTES: usize = 128 << 20;
const MAX_DYNAMIC_TOOLS: usize = 16;

/// Resolves an external CLI tool (`"rg"`, `"git"`, etc.) from `PATH` first, then
/// OS-standard and bundled IDE/CLI fallback directories. Caches only positive hits so
/// newly installed binaries (e.g. `brew install ripgrep`) are discovered immediately
/// without restarting a running daemon.
pub fn resolve_tool(name: &str) -> &'static Path {
    match name {
        "rg" => {
            static P: OnceLock<PathBuf> = OnceLock::new();
            resolve_cached(&P, "rg")
        }
        "git" => {
            static P: OnceLock<PathBuf> = OnceLock::new();
            resolve_cached(&P, "git")
        }
        "curl" => {
            static P: OnceLock<PathBuf> = OnceLock::new();
            resolve_cached(&P, "curl")
        }
        other => resolve_dynamic_tool(other),
    }
}

fn resolve_cached(slot: &'static OnceLock<PathBuf>, name: &'static str) -> &'static Path {
    if let Some(cached) = slot.get() {
        return cached.as_path();
    }
    if let Some(found) = probe_tool_available(name) {
        return slot.get_or_init(|| found).as_path();
    }
    Path::new(name)
}

/// Probes whether an external CLI tool resolves to a real executable file on disk
/// (`PATH`, OS standard directories, and bundled IDE/Claude `rg` locations).
pub fn probe_tool_available(name: &str) -> Option<PathBuf> {
    let exe = tool_exe_name(name);
    resolve_tool_in_path_var(std::env::var_os("PATH").as_deref(), &exe)
        .or_else(|| resolve_tool_in_os_fallbacks(&exe))
        .or_else(|| probe_bundled_rg(&exe))
}

fn resolve_dynamic_tool(name: &str) -> &'static Path {
    static EXTRA: OnceLock<Mutex<HashMap<Box<str>, &'static Path>>> = OnceLock::new();
    let lock = EXTRA.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut map) = lock.lock() {
        if let Some(&cached) = map.get(name) {
            return cached;
        }
        if map.len() < MAX_DYNAMIC_TOOLS {
            let resolved = probe_tool_available(name)
                .unwrap_or_else(|| PathBuf::from(tool_exe_name(name).as_ref()));
            let leaked: &'static Path = Box::leak(resolved.into_boxed_path());
            map.insert(Box::from(name), leaked);
            return leaked;
        }
    }
    Path::new("")
}

#[inline]
fn tool_exe_name(name: &str) -> Cow<'_, str> {
    if cfg!(windows)
        && !(name.len() >= 4 && name.as_bytes()[name.len() - 4..].eq_ignore_ascii_case(b".exe"))
    {
        Cow::Owned(format!("{name}.exe"))
    } else {
        Cow::Borrowed(name)
    }
}

#[inline]
fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[inline]
fn probe_dir(dir: &Path, exe: &str) -> Option<PathBuf> {
    let cand = dir.join(exe);
    is_executable_file(&cand).then_some(cand)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[inline]
fn probe_exact_file(path: &Path) -> Option<PathBuf> {
    is_executable_file(path).then(|| path.to_path_buf())
}

fn probe_bundled_rg(exe: &str) -> Option<PathBuf> {
    if !(exe.eq_ignore_ascii_case("rg") || exe.eq_ignore_ascii_case("rg.exe")) {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        for app_rg in [
            "/Applications/Visual Studio Code.app/Contents/Resources/app/node_modules/@vscode/ripgrep/bin/rg",
            "/Applications/Cursor.app/Contents/Resources/app/node_modules/@vscode/ripgrep/bin/rg",
            "/Applications/Antigravity.app/Contents/Resources/app/node_modules/@vscode/ripgrep/bin/rg",
        ] {
            if let Some(found) = probe_exact_file(Path::new(app_rg)) {
                return Some(found);
            }
        }
        let arch_dir = if cfg!(target_arch = "aarch64") { "arm64-darwin" } else { "x64-darwin" };
        for prefix in ["/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules"] {
            let p = Path::new(prefix)
                .join("@anthropic-ai/claude-code/vendor/ripgrep")
                .join(arch_dir)
                .join("rg");
            if let Some(found) = probe_exact_file(&p) {
                return Some(found);
            }
        }
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()).map(PathBuf::from) {
            for rel in [
                ".claude/local/node_modules/@anthropic-ai/claude-code/vendor/ripgrep",
                ".npm-global/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep",
            ] {
                let p = home.join(rel).join(arch_dir).join("rg");
                if let Some(found) = probe_exact_file(&p) {
                    return Some(found);
                }
            }
        }
        None
    }
    #[cfg(target_os = "linux")]
    {
        for app_rg in [
            "/usr/share/code/resources/app/node_modules/@vscode/ripgrep/bin/rg",
            "/usr/share/cursor/resources/app/node_modules/@vscode/ripgrep/bin/rg",
        ] {
            if let Some(found) = probe_exact_file(Path::new(app_rg)) {
                return Some(found);
            }
        }
        let arch_dir = if cfg!(target_arch = "aarch64") { "arm64-linux" } else { "x64-linux" };
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()).map(PathBuf::from) {
            for rel in [
                ".claude/local/node_modules/@anthropic-ai/claude-code/vendor/ripgrep",
                ".npm-global/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep",
            ] {
                let p = home.join(rel).join(arch_dir).join("rg");
                if let Some(found) = probe_exact_file(&p) {
                    return Some(found);
                }
            }
        }
        None
    }
    #[cfg(windows)]
    {
        probe_env_sub("LOCALAPPDATA", &["Programs", "Microsoft VS Code", "resources", "app", "node_modules", "@vscode", "ripgrep", "bin"], exe)
            .or_else(|| probe_env_sub("LOCALAPPDATA", &["Programs", "cursor", "resources", "app", "node_modules", "@vscode", "ripgrep", "bin"], exe))
            .or_else(|| probe_env_sub("APPDATA", &["npm", "node_modules", "@anthropic-ai", "claude-code", "vendor", "ripgrep", "x64-win32"], exe))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        None
    }
}

#[cfg(unix)]
fn probe_unix_dirs(dirs: &[&str], exe: &str) -> Option<PathBuf> {
    if let Some(found) = dirs.iter().find_map(|&d| probe_dir(Path::new(d), exe)) {
        return Some(found);
    }
    let home = std::env::var_os("HOME").filter(|v| !v.is_empty()).map(PathBuf::from)?;
    probe_dir(&home.join(".cargo").join("bin"), exe)
        .or_else(|| probe_dir(&home.join(".local").join("bin"), exe))
}

#[cfg(windows)]
fn probe_env_sub(key: &str, parts: &[&str], exe: &str) -> Option<PathBuf> {
    let mut dir = PathBuf::from(std::env::var_os(key).filter(|v| !v.is_empty())?);
    for &part in parts { dir.push(part); }
    probe_dir(&dir, exe)
}

fn resolve_tool_in_path_var(path_var: Option<&OsStr>, exe: &str) -> Option<PathBuf> {
    std::env::split_paths(path_var?).find_map(|dir| probe_dir(&dir, exe))
}

fn resolve_tool_in_os_fallbacks(exe: &str) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    return probe_unix_dirs(&["/usr/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin"], exe);

    #[cfg(target_os = "macos")]
    return probe_unix_dirs(
        &["/opt/homebrew/bin", "/usr/local/bin", "/Library/Developer/CommandLineTools/usr/bin", "/usr/bin"],
        exe,
    );

    #[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
    return probe_unix_dirs(&["/usr/bin", "/usr/local/bin"], exe);

    #[cfg(windows)]
    return probe_env_sub("LOCALAPPDATA", &["Microsoft", "WinGet", "Links"], exe)
        .or_else(|| probe_env_sub("USERPROFILE", &["scoop", "shims"], exe))
        .or_else(|| probe_env_sub("ProgramFiles", &["Git", "cmd"], exe))
        .or_else(|| probe_env_sub("ProgramFiles", &["ripgrep"], exe))
        .or_else(|| probe_env_sub("ProgramData", &["chocolatey", "bin"], exe))
        .or_else(|| probe_env_sub("LOCALAPPDATA", &["Programs", "ripgrep"], exe))
        .or_else(|| probe_env_sub("USERPROFILE", &[".cargo", "bin"], exe));

    #[cfg(not(any(unix, windows)))]
    { let _ = exe; None }
}

/// Constructs a `Command` that suppresses console windows on Windows (`CREATE_NO_WINDOW`).
#[inline]
pub fn hidden_command<S: AsRef<OsStr>>(program: S) -> Command {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

#[inline]
fn clamp_auto_budget(half_bytes: usize, hard_cap: usize) -> usize {
    half_bytes.clamp(MIN_AUTO_RAM_BYTES.min(hard_cap), hard_cap)
}

#[cfg(any(target_os = "linux", test))]
fn parse_meminfo_available_kb(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let trimmed = rest.trim_start();
            let digits = trimmed.bytes().take_while(u8::is_ascii_digit).count();
            if digits > 0 {
                if let Ok(kb) = trimmed[..digits].parse::<u64>() { return Some(kb); }
            }
        }
    }
    None
}

fn detect_ram_budget_with_env(env_mb: Option<&str>, hard_cap: usize) -> usize {
    if let Some(mb) = env_mb.and_then(|v| v.trim().parse::<usize>().ok()) {
        if mb >= MIN_ENV_RAM_MB {
            return if mb > (hard_cap >> 20) { hard_cap } else { mb << 20 };
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(kb) = std::fs::read_to_string("/proc/meminfo").ok().as_deref().and_then(parse_meminfo_available_kb) {
        let half_kb = kb >> 1;
        let half = if half_kb > ((usize::MAX as u64) >> 10) { usize::MAX } else { (half_kb as usize) << 10 };
        return clamp_auto_budget(half, hard_cap);
    }

    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn sysctlbyname(
                name: *const std::ffi::c_char, oldp: *mut std::ffi::c_void, oldlenp: *mut usize,
                newp: *mut std::ffi::c_void, newlen: usize,
            ) -> i32;
        }
        let (mut memsize, mut size) = (0u64, std::mem::size_of::<u64>());
        // SAFETY: NUL-terminated key, writable `memsize` buffer of `size` bytes, read-only query.
        let rc = unsafe {
            sysctlbyname(
                b"hw.memsize\0".as_ptr().cast::<std::ffi::c_char>(),
                (&mut memsize as *mut u64).cast::<std::ffi::c_void>(),
                &mut size, std::ptr::null_mut(), 0,
            )
        };
        if rc == 0 && size == std::mem::size_of::<u64>() && memsize > 0 {
            return clamp_auto_budget((memsize >> 1).min(usize::MAX as u64) as usize, hard_cap);
        }
    }

    #[cfg(windows)]
    {
        #[repr(C)]
        #[derive(Default)]
        struct MemoryStatusEx {
            dw_length: u32, dw_memory_load: u32, ull_total_phys: u64, ull_avail_phys: u64,
            ull_total_page_file: u64, ull_avail_page_file: u64, ull_total_virtual: u64,
            ull_avail_virtual: u64, ull_avail_extended_virtual: u64,
        }
        #[link(name = "kernel32")]
        extern "system" { fn GlobalMemoryStatusEx(lp_buffer: *mut MemoryStatusEx) -> i32; }
        let mut st = MemoryStatusEx { dw_length: std::mem::size_of::<MemoryStatusEx>() as u32, ..Default::default() };
        // SAFETY: `st` has `dw_length == 64` per Win32 `MEMORYSTATUSEX` contract.
        if unsafe { GlobalMemoryStatusEx(&mut st) } != 0 && st.ull_avail_phys > 0 {
            return clamp_auto_budget((st.ull_avail_phys >> 1).min(usize::MAX as u64) as usize, hard_cap);
        }
    }

    hard_cap
}

/// Detects the RAM cache budget in bytes, respecting `AGENT_CTX_MAX_RAM_MB` (`>= 16`)
/// and clamping auto-detected OS memory to `[128 MiB, hard_cap]`.
pub fn detect_ram_budget_bytes(hard_cap: usize) -> usize {
    let env_val = std::env::var("AGENT_CTX_MAX_RAM_MB").ok();
    detect_ram_budget_with_env(env_val.as_deref(), hard_cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_ram_budget_respects_env_and_clamps_safely() {
        let cap = 4usize << 30;
        assert_eq!(detect_ram_budget_with_env(Some("64"), cap), 64 << 20);
        assert_eq!(detect_ram_budget_with_env(Some("16"), cap), 16 << 20);
        assert_eq!(detect_ram_budget_with_env(Some("8192"), cap), cap);
        assert_eq!(detect_ram_budget_with_env(Some("99999999999999999"), cap), cap);
        let low = detect_ram_budget_with_env(Some("15"), cap);
        assert!(low >= MIN_AUTO_RAM_BYTES && low <= cap);
        let bad = detect_ram_budget_with_env(Some("abc"), 256 << 20);
        assert!(bad >= MIN_AUTO_RAM_BYTES && bad <= (256 << 20));
        assert_eq!(clamp_auto_budget(512 << 20, 64 << 20), 64 << 20);
        assert_eq!(clamp_auto_budget(32 << 20, 512 << 20), MIN_AUTO_RAM_BYTES);
        assert!(detect_ram_budget_bytes(64 << 20) <= (64 << 20));
        let sample = "MemTotal: 16384000 kB\nMemAvailable:    8192000 kB\n";
        assert_eq!(parse_meminfo_available_kb(sample), Some(8_192_000));
        assert_eq!(parse_meminfo_available_kb("MemTotal: 100 kB\n"), None);
    }

    #[test]
    fn hidden_command_and_resolve_tool_behave_consistently() {
        assert_eq!(hidden_command("git").get_program(), OsStr::new("git"));
        let (g1, g2) = (resolve_tool("git"), resolve_tool("git"));
        assert!(std::ptr::eq(g1, g2));
        assert!(g1.file_name().and_then(OsStr::to_str).unwrap_or("").starts_with("git"));
        assert!(std::ptr::eq(resolve_tool("rg"), resolve_tool("rg")));

        let dir = std::env::temp_dir().join(format!("ctx-platform-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let exe = tool_exe_name("ctx_dummy_tool");
        let fake = dir.join(exe.as_ref());
        std::fs::write(&fake, b"dummy").unwrap();
        let pv = std::env::join_paths([&dir]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(resolve_tool_in_path_var(Some(pv.as_os_str()), &exe), None);
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(resolve_tool_in_path_var(Some(pv.as_os_str()), &exe), Some(fake));
        // Directories with the tool name must never match as executables.
        let dir_cand = dir.join(tool_exe_name("ctx_dir_tool").as_ref());
        let _ = std::fs::create_dir_all(&dir_cand);
        assert_eq!(
            resolve_tool_in_path_var(Some(pv.as_os_str()), &tool_exe_name("ctx_dir_tool")),
            None
        );
        // Misses are never permanently cached in `OnceLock`.
        static MISS_SLOT: OnceLock<PathBuf> = OnceLock::new();
        assert_eq!(resolve_cached(&MISS_SLOT, "ctx_nonexistent_tool_999"), Path::new("ctx_nonexistent_tool_999"));
        assert!(MISS_SLOT.get().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
