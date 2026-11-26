//! Scoped lexical-safe symbol rename helpers for unified `ctx_edit`, plus thin
//! backwards-compatible `op_refactor` / `op_refactor_with_session` wrappers.

use crate::base::json::Json;
use crate::base::simd::FastHashMap;
use crate::engine::walk_source_dir;
use crate::parser::{build_cleaned_code_buffer_for_ext, is_ident_char};
use crate::rpc::BrokerService;
use crate::store::{resolve_input_path, MAX_SINGLE_FILE_CACHE_BYTES};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) const MAX_RENAME_SPECS: usize = 4;
pub(super) const MAX_TOTAL_TOUCHED_FILES: usize = 64;

pub(super) struct RenameSpec {
    pub old_name: String,
    pub new_name: String,
    pub scope: Vec<String>,
}

pub(super) struct RenameSummary {
    pub old_name: String,
    pub new_name: String,
    pub occurrences: usize,
    pub files: usize,
    pub remaining_in_scope: usize,
}

#[allow(dead_code)]
pub fn op_refactor(svc: &BrokerService, req: &Json, cwd: Option<&Path>) -> Result<String, String> {
    op_refactor_with_session(svc, req, None, cwd)
}

#[allow(dead_code)]
pub fn op_refactor_with_session(
    svc: &BrokerService,
    req: &Json,
    session_key: Option<&str>,
    cwd: Option<&Path>,
) -> Result<String, String> {
    op_refactor_with_write_gate(
        svc,
        req,
        session_key,
        cwd,
        crate::base::mode::current_write_mode(None).enabled,
    )
}

#[allow(dead_code)]
fn op_refactor_with_write_gate(
    svc: &BrokerService,
    req: &Json,
    session_key: Option<&str>,
    cwd: Option<&Path>,
    write_enabled: bool,
) -> Result<String, String> {
    let dry_run = req.get_bool("dry_run").unwrap_or(true);
    if !dry_run && !write_enabled {
        return Err("REFUSED: read-only mode (run `ctx mode write` to enable edits)".to_string());
    }
    let action = match req.get("action") {
        None | Some(Json::Null) => "rename_symbol",
        Some(v) => v
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "`action` must be a non-empty string (expected `rename_symbol`)".to_string()
            })?,
    };
    if action != "rename_symbol" {
        return Err(format!(
            "unsupported refactor action `{action}` (expected `rename_symbol`)"
        ));
    }
    let mut spec_fields = Vec::with_capacity(4);
    for key in ["old_name", "new_name", "paths", "roots"] {
        if let Some(val) = req.get(key) {
            spec_fields.push((key, val.clone()));
        }
    }
    let mut wrapped = vec![("renames", Json::Arr(vec![Json::obj(spec_fields)]))];
    if let Some(dr) = req.get("dry_run") {
        wrapped.push(("dry_run", dr.clone()));
    }
    if let Some(sess) = req.get("session") {
        wrapped.push(("session", sess.clone()));
    }
    super::apply::op_edit_with_write_gate(svc, &Json::obj(wrapped), session_key, cwd, write_enabled)
}

pub(super) fn parse_rename_specs(req: &Json) -> Result<Vec<RenameSpec>, String> {
    let raw = match req.get("renames") {
        None | Some(Json::Null) => return Ok(Vec::new()),
        Some(val) => val
            .as_arr()
            .ok_or_else(|| "`renames` must be an array of {old_name, new_name, paths?/roots?}".to_string())?,
    };
    if raw.len() > MAX_RENAME_SPECS {
        return Err(format!("`renames` supports at most {MAX_RENAME_SPECS} specs"));
    }
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let old_name = item
            .get_str("old_name")
            .ok_or_else(|| "`old_name` is required in each rename spec".to_string())?;
        let new_name = item
            .get_str("new_name")
            .ok_or_else(|| "`new_name` is required in each rename spec".to_string())?;
        if !is_valid_ascii_ident(old_name) {
            return Err(format!("invalid `old_name` identifier `{old_name}`"));
        }
        if !is_valid_ascii_ident(new_name) {
            return Err(format!("invalid `new_name` identifier `{new_name}`"));
        }
        if old_name == new_name {
            return Err("`old_name` and `new_name` must differ".to_string());
        }
        let scope = parse_scope_entries(item)?;
        out.push(RenameSpec {
            old_name: old_name.to_string(),
            new_name: new_name.to_string(),
            scope,
        });
    }
    Ok(out)
}

#[inline]
fn is_valid_ascii_ident(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b[1..].iter().all(|&c| is_ident_char(c))
}

fn has_git_component(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str().to_str().is_some_and(|s| s.eq_ignore_ascii_case(".git")))
}

fn parse_scope_entries(spec: &Json) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for key in ["paths", "roots"] {
        if let Some(val) = spec.get(key) {
            if matches!(val, Json::Null) {
                continue;
            }
            let arr = val
                .as_arr()
                .ok_or_else(|| format!("`{key}` must be an array of file/directory paths"))?;
            for item in arr {
                let s = item
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| format!("`{key}` entries must be non-empty strings"))?;
                out.push(s.to_string());
            }
        }
    }
    if out.is_empty() {
        return Err("REFUSED: explicit non-empty `paths` or `roots` scope is required".to_string());
    }
    Ok(out)
}

pub(super) fn collect_scope_files(
    svc: &BrokerService,
    scope: &[String],
    cwd: Option<&Path>,
    max_total: usize,
) -> Result<Vec<(PathBuf, PathBuf, bool)>, String> {
    let mut targets: Vec<(PathBuf, PathBuf, bool)> = Vec::new();
    let mut seen: FastHashMap<PathBuf, usize> = FastHashMap::default();
    let mut admit = |path: &Path, explicit: bool| -> Result<(), String> {
        let (canon, ws_root) = svc.allowlist.admit_writable_file(path, cwd)?;
        if let Some(&idx) = seen.get(&canon) {
            targets[idx].2 |= explicit;
            return Ok(());
        }
        if targets.len() >= max_total {
            return Err(format!(
                "REFUSED: rename scope exceeds max {max_total} files; narrow `paths` or `roots`"
            ));
        }
        let idx = targets.len();
        seen.insert(canon.clone(), idx);
        targets.push((canon, ws_root, explicit));
        Ok(())
    };
    for raw in scope {
        let cleaned = raw.trim().trim_end_matches("/**").trim_end_matches("/*");
        if cleaned.is_empty() {
            return Err("REFUSED: empty path in rename scope".to_string());
        }
        let resolved = resolve_input_path(cleaned, cwd);
        if has_git_component(&resolved) {
            return Err("REFUSED: writing inside .git is forbidden".to_string());
        }
        let meta = fs::symlink_metadata(&resolved)
            .map_err(|e| format!("cannot stat `{raw}`: {e}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!("REFUSED: target is a symlink: {}", resolved.display()));
        }
        if meta.is_dir() {
            let _ = svc.allowlist.admit_dir(&resolved, cwd)?;
            let mut walked = Vec::new();
            walk_source_dir(&resolved, &mut walked, max_total + 1);
            for file in walked {
                admit(&file, false)?;
            }
        } else {
            admit(&resolved, true)?;
        }
    }
    Ok(targets)
}

fn find_ident_matches(cleaned: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let nlen = needle.len();
    if nlen == 0 || nlen > cleaned.len() {
        return hits;
    }
    let (first, last, mut i) = (needle[0], cleaned.len() - nlen, 0usize);
    while i <= last {
        let Some(rel) = cleaned[i..=last].iter().position(|&b| b == first) else {
            break;
        };
        let pos = i + rel;
        if &cleaned[pos..pos + nlen] == needle {
            let after = pos + nlen;
            if (pos == 0 || !is_ident_char(cleaned[pos - 1]))
                && (after == cleaned.len() || !is_ident_char(cleaned[after]))
            {
                hits.push(pos);
                i = after;
                continue;
            }
        }
        i = pos + 1;
    }
    hits
}

pub(super) fn apply_rename_to_body(
    body: &str,
    ext: &str,
    old_name: &str,
    new_name: &str,
    bom_len: usize,
    rel_path: &str,
) -> Result<Option<(String, usize)>, String> {
    let cleaned = build_cleaned_code_buffer_for_ext(body, ext);
    debug_assert_eq!(cleaned.len(), body.len());
    let hits = find_ident_matches(cleaned.as_bytes(), old_name.as_bytes());
    if hits.is_empty() {
        return Ok(None);
    }
    let extra = new_name
        .len()
        .saturating_sub(old_name.len())
        .saturating_mul(hits.len());
    let mut out = String::with_capacity(body.len().saturating_add(extra));
    let mut cursor = 0usize;
    for &pos in &hits {
        out.push_str(&body[cursor..pos]);
        out.push_str(new_name);
        cursor = pos + old_name.len();
    }
    out.push_str(&body[cursor..]);
    if out.len().saturating_add(bom_len) > MAX_SINGLE_FILE_CACHE_BYTES {
        return Err(format!(
            "REFUSED: `{rel_path}` rewritten size exceeds 1 MiB limit ({} bytes)",
            out.len().saturating_add(bom_len)
        ));
    }
    Ok(Some((out, hits.len())))
}

pub(super) fn count_ident_in_body(body: &str, ext: &str, needle: &str) -> usize {
    let cleaned = build_cleaned_code_buffer_for_ext(body, ext);
    find_ident_matches(cleaned.as_bytes(), needle.as_bytes()).len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_req(old: &str, new: &str, key: &'static str, items: &[&str], dry_run: Option<bool>) -> Json {
        let mut fields = vec![
            ("old_name", Json::Str(old.into())),
            ("new_name", Json::Str(new.into())),
            (key, Json::Arr(items.iter().map(|s| Json::Str((*s).into())).collect())),
        ];
        if let Some(dr) = dry_run {
            fields.push(("dry_run", Json::Bool(dr)));
        }
        Json::obj(fields)
    }

    #[test]
    fn wrapper_word_boundary_dry_run_commit_bom_crlf_and_ramstore_refresh() {
        let ws = std::env::temp_dir().join(format!("ctx-ref-{}-{}", std::process::id(), crate::store::now_ms_u64()));
        fs::create_dir_all(ws.join("src")).unwrap();
        let (f_calc, f_call) = (ws.join("src/calc.rs"), ws.join("src/caller.rs"));
        let orig_calc = "\u{FEFF}// compute_fee in comment\r\npub fn compute_fee(x: i32) -> i32 {\r\n    let _ = \"compute_fee in str\";\r\n    compute_fee_extra(x) + pre_compute_fee(x)\r\n}\r\n";
        let orig_call = "fn run_it() -> i32 { compute_fee(compute_fee(1)) }";
        fs::write(&f_calc, orig_calc).unwrap();
        fs::write(&f_call, orig_call).unwrap();

        let svc = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();
        let _ = svc.store.get_full_entry(&fs::canonicalize(&f_calc).unwrap(), Some(&ws)).unwrap();

        let req_default = mk_req("compute_fee", "calc_fee", "roots", &["src"], None);
        let preview = op_refactor_with_write_gate(&svc, &req_default, None, Some(&ws), false).unwrap();
        assert!(preview.contains("[DRY RUN — 0 files modified]"));
        assert!(preview.contains("rename compute_fee -> calc_fee: 3 occurrences across 2 files (remaining_in_scope: 0)"));
        assert!(preview.contains("-L1 fn run_it()") && !preview.contains("-L1 //") && !preview.contains("-L3 ") && !preview.contains("calc_fee in comment") && !preview.contains("calc_fee in str") && !preview.contains("calc_fee_extra"));
        assert_eq!(fs::read_to_string(&f_calc).unwrap(), orig_calc);
        assert_eq!(fs::read_to_string(&f_call).unwrap(), orig_call);

        let req_commit = mk_req("compute_fee", "calc_fee", "roots", &["src"], Some(false));
        assert!(op_refactor_with_write_gate(&svc, &req_commit, Some("s1"), Some(&ws), false).unwrap_err().contains("REFUSED: read-only mode"));

        let out = op_refactor_with_write_gate(&svc, &req_commit, Some("s1"), Some(&ws), true).unwrap();
        assert!(out.contains("[COMMITTED] 2 file(s) modified"));
        assert!(out.contains("rename compute_fee -> calc_fee: 3 occurrences across 2 files (remaining_in_scope: 0)"));
        assert!(out.contains("@calc_fee") && out.contains("@run_it"));
        assert_eq!(fs::read(&f_calc).unwrap(), b"\xEF\xBB\xBF// compute_fee in comment\r\npub fn calc_fee(x: i32) -> i32 {\r\n    let _ = \"compute_fee in str\";\r\n    compute_fee_extra(x) + pre_compute_fee(x)\r\n}\r\n");
        assert_eq!(fs::read(&f_call).unwrap(), b"fn run_it() -> i32 { calc_fee(calc_fee(1)) }");
        let cached = svc.store.get_full_entry(&fs::canonicalize(&f_calc).unwrap(), Some(&ws)).unwrap();
        assert!(cached.content.as_deref().unwrap().contains("pub fn calc_fee"));
        let again = op_refactor_with_write_gate(&svc, &req_default, None, Some(&ws), true).unwrap();
        assert!(again.contains("rename compute_fee -> calc_fee: 0 occurrences across 0 files (remaining_in_scope: 0)"));
        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn wrapper_rejects_empty_scope_invalid_idents_and_bad_action() {
        let ws = std::env::temp_dir().join(format!("ctx-ref-err-{}-{}", std::process::id(), crate::store::now_ms_u64()));
        fs::create_dir_all(ws.join(".git")).unwrap();
        let a = ws.join("a.rs");
        fs::write(&a, "fn foo() {}\n").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();

        assert!(op_refactor_with_write_gate(&svc, &mk_req("foo", "baz", "paths", &[], None), None, Some(&ws), true).unwrap_err().contains("REFUSED"));
        assert!(op_refactor_with_write_gate(&svc, &mk_req("foo", "baz", "roots", &[".git"], None), None, Some(&ws), true).unwrap_err().contains("REFUSED"));
        for (old, new) in [("", "b"), ("1bad", "b"), ("a-b", "b"), ("foo", "foo")] {
            assert!(op_refactor_with_write_gate(&svc, &mk_req(old, new, "paths", &["a.rs"], None), None, Some(&ws), true).is_err());
        }
        let bad_act = Json::obj(vec![
            ("action", Json::Str("extract_fn".into())),
            ("old_name", Json::Str("foo".into())),
            ("new_name", Json::Str("baz".into())),
            ("paths", Json::Arr(vec![Json::Str("a.rs".into())])),
        ]);
        assert!(op_refactor_with_write_gate(&svc, &bad_act, None, Some(&ws), true).is_err());
        let _ = fs::remove_dir_all(&ws);
    }
}
