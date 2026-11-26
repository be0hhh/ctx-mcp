//! Hardened transactional file creation (`creates`) and unified atomic commit/rollback
//! for `ctx_edit`: symlink/traversal/sensitive admission, TOCTOU parent re-verification
//! under `workspace_write_lock`, and full rollback (including `overwrite: true` restoration).

use crate::base::json::Json;
use crate::base::security::{has_git_component, is_sensitive_path_lexical, is_sensitive_path_with_ws};
use crate::edit::{check_delimiter_balance, count_dir_files, ext_lower_buf, line_count_flag};
use crate::parser::{SymbolKind, SymbolSpan};
use crate::rpc::BrokerService;
use crate::store::{
    display_workspace_path, file_stat, resolve_input_path, FileMetaStamp, MAX_SINGLE_FILE_CACHE_BYTES,
};
use std::ffi::OsString;
use std::fs::{self, Permissions};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

pub(super) const MAX_CREATE_FILES: usize = 16;
pub(super) const MAX_CREATE_BYTES: usize = 512 * 1024;

pub(super) struct CreateSpec { pub raw_path: String, pub content: String, pub executable: bool, pub overwrite: bool }

pub(super) struct AdmittedCreate {
    pub canon: PathBuf, pub ws_root: PathBuf, pub canon_ancestor: PathBuf, pub missing_dirs: Vec<OsString>,
    pub raw_path: String, pub content: String, pub executable: bool, pub overwrite: bool,
}

pub(super) struct CreatePlan {
    pub canon: PathBuf, pub ws_root: PathBuf, pub canon_ancestor: PathBuf, pub missing_dirs: Vec<OsString>,
    pub rel_path: String, pub existed: bool, pub orig_stamp: Option<FileMetaStamp>,
    pub orig_perms: Option<Permissions>, pub orig_bytes: Option<Vec<u8>>, pub target_perms: Permissions,
    pub new_bytes: Vec<u8>, pub line_count: usize, pub executable: bool, pub warnings: Vec<String>,
}

pub(super) enum CommitEntry<'a> {
    Edit { canon: &'a Path, rel_path: &'a str, orig_perms: &'a Permissions, orig_bytes: &'a [u8], new_bytes: &'a [u8] },
    Overwrite { canon: &'a Path, rel_path: &'a str, orig_perms: &'a Permissions, target_perms: &'a Permissions, orig_bytes: &'a [u8], new_bytes: &'a [u8] },
    CreateNew { canon: &'a Path, rel_path: &'a str, target_perms: &'a Permissions, new_bytes: &'a [u8] },
}

pub(super) fn parse_create_specs(raw: &[Json]) -> Result<Vec<CreateSpec>, String> {
    if raw.len() > MAX_CREATE_FILES {
        return Err(format!("`creates` must contain 1..={MAX_CREATE_FILES} files"));
    }
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let raw_path = item.get_str("path").map(str::trim).filter(|s| !s.is_empty())
            .ok_or_else(|| "each create entry requires a non-empty `path`".to_string())?;
        let content = item.get_str("content")
            .ok_or_else(|| format!("`{raw_path}` create entry missing `content`"))?;
        if content.len() > MAX_CREATE_BYTES {
            return Err(format!("REFUSED: `{raw_path}` create content exceeds 512 KiB limit ({} bytes)", content.len()));
        }
        if content.as_bytes().contains(&0) {
            return Err(format!("REFUSED: `{raw_path}` create content contains NUL byte / binary content"));
        }
        let executable = opt_bool(item, "executable", raw_path)?;
        let overwrite = opt_bool(item, "overwrite", raw_path)?;
        out.push(CreateSpec { raw_path: raw_path.to_string(), content: content.to_string(), executable, overwrite });
    }
    Ok(out)
}

fn opt_bool(item: &Json, key: &str, raw_path: &str) -> Result<bool, String> {
    match item.get(key) {
        None | Some(Json::Null) => Ok(false),
        Some(v) => v.as_bool().ok_or_else(|| format!("`{raw_path}` `{key}` must be a boolean")),
    }
}

pub(super) fn admit_new_file(svc: &BrokerService, spec: CreateSpec, cwd: Option<&Path>) -> Result<AdmittedCreate, String> {
    let rp = spec.raw_path.as_str();
    if rp.ends_with('/')
        || rp.ends_with('\\')
        || rp == "."
        || rp == ".."
        || rp.ends_with("/.")
        || rp.ends_with("\\.")
        || Path::new(rp)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(format!("REFUSED: invalid create target path `{rp}`"));
    }
    let cand = resolve_input_path(rp, cwd);
    if has_git_component(Path::new(rp)) || has_git_component(&cand) {
        return Err("REFUSED: writing inside .git is forbidden".to_string());
    }
    if is_sensitive_path_lexical(&cand) {
        return Err("REFUSED: sensitive path".to_string());
    }
    let file_name = match cand.components().next_back() {
        Some(Component::Normal(n)) if !n.is_empty() => n.to_os_string(),
        _ => return Err(format!("REFUSED: invalid create target path `{rp}`")),
    };
    match fs::symlink_metadata(&cand) {
        Ok(meta) => {
            if meta.file_type().is_symlink() { return Err(format!("REFUSED: target is a symlink: {}", cand.display())); }
            if !meta.file_type().is_file() { return Err(format!("REFUSED: target is not a regular file: {}", cand.display())); }
            if !spec.overwrite { return Err(format!("REFUSED: `{rp}` already exists (pass `overwrite: true` to replace)")); }
            let (canon, ws_root) = svc.allowlist.admit_writable_file(&cand, cwd)?;
            if is_sensitive_path_with_ws(&canon, Some(&ws_root), true)
                || crate::base::ext::policy().is_extra_sensitive_path(&canon, Some(&ws_root), true)
            {
                return Err("REFUSED: sensitive write path".to_string());
            }
            let canon_ancestor = canon.parent().ok_or_else(|| "REFUSED: target has no parent directory".to_string())?.to_path_buf();
            Ok(AdmittedCreate {
                canon, ws_root, canon_ancestor, missing_dirs: Vec::new(),
                raw_path: spec.raw_path, content: spec.content, executable: spec.executable, overwrite: spec.overwrite,
            })
        }
        Err(e) if e.kind() != ErrorKind::NotFound => Err(format!("REFUSED: cannot stat create target `{rp}`: {e}")),
        Err(_) => {
            let mut missing_rev: Vec<OsString> = Vec::new();
            let mut cur = cand.parent();
            let existing = loop {
                let Some(dir) = cur else { return Err(format!("REFUSED: `{rp}` has no existing workspace ancestor")); };
                match fs::symlink_metadata(dir) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() && cwd != Some(dir) {
                            return Err(format!("REFUSED: symlink ancestor in create path: {}", dir.display()));
                        }
                        if !meta.file_type().is_symlink() && !meta.is_dir() {
                            return Err(format!("REFUSED: parent is not a directory: {}", dir.display()));
                        }
                        break dir;
                    }
                    Err(e) if e.kind() == ErrorKind::NotFound => {
                        match dir.components().next_back() {
                            Some(Component::Normal(seg)) => {
                                if seg.to_str().is_some_and(|s| s.eq_ignore_ascii_case(".git")) {
                                    return Err("REFUSED: writing inside .git is forbidden".to_string());
                                }
                                missing_rev.push(seg.to_os_string());
                            }
                            Some(Component::ParentDir) => return Err(format!("REFUSED: `..` in non-existent path tail `{rp}`")),
                            Some(Component::CurDir) => {}
                            _ => return Err(format!("REFUSED: invalid ancestor in `{rp}`")),
                        }
                        cur = dir.parent();
                    }
                    Err(e) => return Err(format!("cannot stat ancestor `{}`: {e}", dir.display())),
                }
            };
            let (canon_ancestor, ws_root) = svc.allowlist.admit_dir(existing, cwd)?;
            let mut walk = Some(existing);
            while let Some(dir) = walk {
                if fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) && cwd != Some(dir) {
                    return Err(format!("REFUSED: symlink ancestor in create path: {}", dir.display()));
                }
                if let Ok(cd) = fs::canonicalize(dir) {
                    if (cd == ws_root && !dir.components().any(|c| matches!(c, Component::ParentDir))) || !cd.starts_with(&ws_root) {
                        break;
                    }
                }
                walk = dir.parent();
            }
            let missing_dirs: Vec<OsString> = missing_rev.into_iter().rev().collect();
            let mut canon = canon_ancestor.clone();
            for seg in &missing_dirs { canon.push(seg); }
            canon.push(&file_name);
            if !canon.starts_with(&ws_root) { return Err("REFUSED: path escapes active request workspace".to_string()); }
            if has_git_component(&canon) { return Err("REFUSED: writing inside .git is forbidden".to_string()); }
            let pol = crate::base::ext::policy();
            if is_sensitive_path_with_ws(&cand, Some(&ws_root), true) || is_sensitive_path_with_ws(&canon, Some(&ws_root), true)
                || pol.is_extra_sensitive_path(&cand, Some(&ws_root), true) || pol.is_extra_sensitive_path(&canon, Some(&ws_root), true)
            {
                return Err("REFUSED: sensitive write path".to_string());
            }
            Ok(AdmittedCreate {
                canon, ws_root, canon_ancestor, missing_dirs,
                raw_path: spec.raw_path, content: spec.content, executable: spec.executable, overwrite: spec.overwrite,
            })
        }
    }
}

pub(super) fn prepare_create_plan(adm: AdmittedCreate) -> Result<CreatePlan, String> {
    let rel_path = display_workspace_path(&adm.canon, Some(&adm.ws_root));
    let (existed, orig_stamp, orig_perms, orig_bytes) = match fs::symlink_metadata(&adm.canon) {
        Ok(meta) => {
            if meta.file_type().is_symlink() { return Err(format!("REFUSED: target is a symlink: `{rel_path}`")); }
            if !meta.file_type().is_file() { return Err(format!("REFUSED: target is not a regular file: `{rel_path}`")); }
            if !adm.overwrite { return Err(format!("REFUSED: `{}` already exists (pass `overwrite: true` to replace)", adm.raw_path)); }
            let stamp = file_stat(&adm.canon)?;
            if stamp.size_bytes > MAX_SINGLE_FILE_CACHE_BYTES as u64 {
                return Err(format!("REFUSED: `{rel_path}` exceeds 1 MiB write limit ({} bytes)", stamp.size_bytes));
            }
            let perms = fs::metadata(&adm.canon).map_err(|e| format!("stat `{rel_path}`: {e}"))?.permissions();
            let bytes = fs::read(&adm.canon).map_err(|e| format!("read `{rel_path}`: {e}"))?;
            (true, Some(stamp), Some(perms), Some(bytes))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => (false, None, None, None),
        Err(e) => return Err(format!("stat `{rel_path}`: {e}")),
    };
    let target_perms = resolve_create_perms(adm.executable, orig_perms.as_ref(), &adm.ws_root)?;
    let mut ext_buf = [0u8; 16];
    let ext = ext_lower_buf(&adm.canon, &mut ext_buf);
    let mut warnings = Vec::new();
    if let Some(w) = check_delimiter_balance(&adm.content, ext) { warnings.push(w); }
    let dir_count = count_dir_files(&adm.canon).saturating_add(usize::from(!existed));
    warnings.extend(crate::base::ext::policy().post_edit_lint(&rel_path, &adm.ws_root, &adm.content, dir_count));
    let line_count = adm.content.lines().count();
    Ok(CreatePlan {
        canon: adm.canon, ws_root: adm.ws_root, canon_ancestor: adm.canon_ancestor, missing_dirs: adm.missing_dirs,
        rel_path, existed, orig_stamp, orig_perms, orig_bytes, target_perms,
        new_bytes: adm.content.into_bytes(), line_count, executable: adm.executable, warnings,
    })
}

fn resolve_create_perms(executable: bool, orig_perms: Option<&Permissions>, ws_root: &Path) -> Result<Permissions, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = ws_root;
        if executable { Ok(Permissions::from_mode(0o755)) }
        else if let Some(p) = orig_perms { Ok(p.clone()) }
        else { Ok(Permissions::from_mode(0o644)) }
    }
    #[cfg(not(unix))]
    {
        let _ = executable;
        if let Some(p) = orig_perms { return Ok(p.clone()); }
        let mut p = fs::metadata(ws_root).map_err(|e| format!("stat workspace: {e}"))?.permissions();
        p.set_readonly(false);
        Ok(p)
    }
}

pub(super) fn rollback_dirs(created_dirs: &[PathBuf]) {
    for dir in created_dirs.iter().rev() { let _ = fs::remove_dir(dir); }
}

pub(super) fn materialize_dirs_checked(plans: &[CreatePlan]) -> Result<Vec<PathBuf>, String> {
    let mut created_dirs: Vec<PathBuf> = Vec::new();
    let fail = |dirs: &[PathBuf], msg: String| -> Result<Vec<PathBuf>, String> { rollback_dirs(dirs); Err(msg) };
    for cp in plans {
        let mut cur = cp.canon_ancestor.clone();
        for seg in &cp.missing_dirs {
            cur.push(seg);
            match fs::create_dir(&cur) {
                Ok(()) => created_dirs.push(cur.clone()),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    let ok = fs::symlink_metadata(&cur).is_ok_and(|m| !m.file_type().is_symlink() && m.is_dir());
                    if !ok { return fail(&created_dirs, format!("REFUSED: symlink or non-dir raced: {}", cur.display())); }
                }
                Err(e) => return fail(&created_dirs, format!("create dir `{}`: {e}", cur.display())),
            }
        }
        let Some(expected_parent) = cp.canon.parent() else { return fail(&created_dirs, format!("REFUSED: `{}` has no parent", cp.rel_path)); };
        let canon_parent = match fs::canonicalize(expected_parent) {
            Ok(p) => p,
            Err(e) => return fail(&created_dirs, format!("canonicalize parent `{}`: {e}", expected_parent.display())),
        };
        if !canon_parent.starts_with(&cp.ws_root) || canon_parent != expected_parent {
            return fail(&created_dirs, format!("REFUSED: TOCTOU parent escape on `{}`", cp.rel_path));
        }
        match fs::symlink_metadata(&cp.canon) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.file_type().is_file() { return fail(&created_dirs, format!("REFUSED: `{}` is a symlink or non-file", cp.rel_path)); }
                if !cp.existed { return fail(&created_dirs, format!("REFUSED: `{}` appeared before commit; 0 files written", cp.rel_path)); }
                if cp.orig_stamp.is_some_and(|orig| file_stat(&cp.canon).ok() != Some(orig)) {
                    return fail(&created_dirs, format!("REFUSED: `{}` changed on disk before commit; 0 files written", cp.rel_path));
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => if cp.existed { return fail(&created_dirs, format!("REFUSED: `{}` vanished before commit; 0 files written", cp.rel_path)); },
            Err(e) => return fail(&created_dirs, format!("stat `{}` before commit: {e}", cp.rel_path)),
        }
    }
    Ok(created_dirs)
}

pub(super) fn commit_all_atomic<F>(entries: &[CommitEntry<'_>], created_dirs: &[PathBuf], mut writer: F) -> Result<(), String>
where
    F: FnMut(&Path, &[u8], &Permissions) -> Result<(), String>,
{
    for (idx, entry) in entries.iter().enumerate() {
        let (canon, rel_path, new_bytes, perms) = match entry {
            CommitEntry::Edit { canon, rel_path, orig_perms, new_bytes, .. } => (*canon, *rel_path, *new_bytes, *orig_perms),
            CommitEntry::Overwrite { canon, rel_path, target_perms, new_bytes, .. }
            | CommitEntry::CreateNew { canon, rel_path, target_perms, new_bytes } => (*canon, *rel_path, *new_bytes, *target_perms),
        };
        if let Err(commit_err) = writer(canon, new_bytes, perms) {
            let committed: Vec<&str> = entries[..idx].iter().map(CommitEntry::rel_path).collect();
            let (mut rolled_back, mut rollback_failed) = (Vec::new(), Vec::new());
            for prev in entries[..idx].iter().rev() {
                let res = match prev {
                    CommitEntry::Edit { canon, orig_bytes, orig_perms, .. }
                    | CommitEntry::Overwrite { canon, orig_bytes, orig_perms, .. } => writer(canon, orig_bytes, orig_perms),
                    CommitEntry::CreateNew { canon, .. } => fs::remove_file(canon).map_err(|e| e.to_string()),
                };
                match res { Ok(()) => rolled_back.push(prev.rel_path()), Err(e) => rollback_failed.push(format!("{} ({e})", prev.rel_path())) }
            }
            rollback_dirs(created_dirs);
            if !rollback_failed.is_empty() {
                return Err(format!("partial_commit: failed on `{rel_path}` ({commit_err}); committed=[{}]; rolled_back=[{}]; rollback_failed=[{}]",
                    committed.join(", "), rolled_back.join(", "), rollback_failed.join(", ")));
            }
            return Err(format!("commit failed on `{rel_path}` ({commit_err}); rolled back {} file(s)", rolled_back.len()));
        }
    }
    Ok(())
}

impl CommitEntry<'_> {
    fn rel_path(&self) -> &str {
        match self { Self::Edit { rel_path, .. } | Self::Overwrite { rel_path, .. } | Self::CreateNew { rel_path, .. } => rel_path }
    }
}

pub(super) fn collect_created_symbols(symbols: &[SymbolSpan]) -> Vec<String> {
    let mut out = Vec::new();
    for sym in symbols {
        if sym.kind == SymbolKind::Namespace { continue; }
        let name = sym.name.trim_start_matches("::");
        if !name.is_empty() {
            let tag = format!("@{name}");
            if !out.contains(&tag) { out.push(tag); if out.len() >= 12 { break; } }
        }
    }
    out
}

pub(super) fn render_create_line(out: &mut String, cp: &CreatePlan, syms: &[String]) {
    let exec = if cp.executable { "+x" } else { "" };
    out.push_str(&format!("CREATED {} ({}L, {}B{exec}){}", cp.rel_path, cp.line_count, cp.new_bytes.len(), line_count_flag(cp.line_count)));
    if !syms.is_empty() { out.push_str(" | Symbols: "); out.push_str(&syms.join(", ")); }
    out.push('\n');
    for w in &cp.warnings { out.push_str("Warning: "); out.push_str(w); out.push('\n'); }
}
