//! Unified atomic transactional file edit, scoped lexical-safe symbol rename, hardened
//! file creation (`creates`), and bounded `verify_absent` scanning (`ctx_edit`).

mod create;
#[cfg(test)]
mod tests;

use super::hashline::{append_anchor_windows, format_conflict_window_lines, hash3_str, line_anchor_hash};
use super::refactor::{apply_rename_to_body, collect_scope_files, count_ident_in_body, parse_rename_specs, RenameSpec, RenameSummary, MAX_TOTAL_TOUCHED_FILES};
use super::{
    atomic_write_file, cap_utf8, check_delimiter_balance, collect_overlapping_symbol_spans,
    collect_overlapping_symbols, count_dir_files, detect_line_ending, ext_lower_buf,
    format_conflict_window, join_body_lines, line_count_flag, line_offsets_for_text,
    parse_line_anchor, push_diff_line, push_merged_range,
};
use crate::base::json::Json;
use crate::base::security::is_sensitive_path_with_ws;
use crate::base::simd::{push_usize, FastHashMap};
use crate::parser::{build_cleaned_code_buffer_for_ext, is_ident_char};
use crate::rpc::BrokerService;
use crate::store::{display_workspace_path, file_stat, resolve_input_path, FileMetaStamp, MAX_SINGLE_FILE_CACHE_BYTES};
use create::{
    admit_new_file, collect_created_symbols, commit_all_atomic, materialize_dirs_checked,
    parse_create_specs, prepare_create_plan, render_create_line, AdmittedCreate, CommitEntry, CreatePlan,
};
use std::fs::{self, Permissions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_EDIT_FILES: usize = 32; const MAX_OPS_PER_FILE: usize = 64;
const CONFLICT_RADIUS: usize = 4; const MAX_REPORT_BYTES: usize = 32_768;
const MAX_VERIFY_ABSENT: usize = 4; const MAX_VERIFY_SYM_LEN: usize = 96;
const MAX_VERIFY_WS_FILES: usize = 256; const MAX_VERIFY_LOCS: usize = 4;

enum EditOp {
    Replace { start_ln: usize, start_h: [u8; 3], end_ln: usize, end_h: [u8; 3], lines: Vec<String> },
    InsertAfter { anchor_ln: usize, anchor_h: [u8; 3], lines: Vec<String> },
}

struct TargetFile { canon: PathBuf, ws_root: PathBuf, explicit: bool, ops: Vec<EditOp>, rename_indices: Vec<usize> }

struct FilePlan {
    canon: PathBuf, ws_root: PathBuf, rel_path: String, stamp: FileMetaStamp,
    orig_perms: Permissions, orig_bytes: Vec<u8>, new_bytes: Vec<u8>, new_lines: Vec<String>,
    added: usize, removed: usize, edited_ranges: Vec<(usize, usize)>, diff_preview: String, warnings: Vec<String>,
}

#[allow(dead_code)]
pub fn op_edit(svc: &BrokerService, req: &Json, cwd: Option<&Path>) -> Result<String, String> { op_edit_with_session(svc, req, None, cwd) }

#[allow(dead_code)]
pub fn op_edit_with_session(svc: &BrokerService, req: &Json, session_key: Option<&str>, cwd: Option<&Path>) -> Result<String, String> {
    op_edit_with_write_gate(svc, req, session_key, cwd, crate::base::mode::current_write_mode(None).enabled)
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn op_edit_full(svc: &BrokerService, cwd: Option<&Path>, raw_edits: &[Json], raw_renames: &[Json], raw_creates: &[Json], verify_absent: &[String], dry_run: Option<bool>, session_key: Option<&str>) -> Json {
    match op_edit_core(svc, cwd, raw_edits, raw_renames, raw_creates, verify_absent, dry_run, session_key.filter(|s| !s.is_empty()), crate::base::mode::current_write_mode(None).enabled) {
        Ok(text) => Json::obj(vec![("ok", Json::Bool(true)), ("text", Json::Str(text))]),
        Err(e) => Json::obj(vec![("ok", Json::Bool(false)), ("error", Json::Str(e))]),
    }
}

pub(super) fn op_edit_with_write_gate(svc: &BrokerService, req: &Json, session_key: Option<&str>, cwd: Option<&Path>, write_enabled: bool) -> Result<String, String> {
    let raw_edits = parse_raw_array(req, "edits", "`edits` must be an array of {path, ops}")?;
    let raw_renames = parse_raw_array(req, "renames", "`renames` must be an array of {old_name, new_name, paths?/roots?}")?;
    let raw_creates = parse_raw_array(req, "creates", "`creates` must be an array of {path, content, executable?, overwrite?}")?;
    let verify_absent = parse_verify_absent(req)?;
    let sess = session_key.filter(|s| !s.is_empty()).or_else(|| req.get_str("session").filter(|s| !s.is_empty()));
    op_edit_core(svc, cwd, raw_edits, raw_renames, raw_creates, &verify_absent, req.get_bool("dry_run"), sess, write_enabled)
}

#[allow(clippy::too_many_arguments)]
fn op_edit_core(svc: &BrokerService, cwd: Option<&Path>, raw_edits: &[Json], raw_renames: &[Json], raw_creates: &[Json], verify_absent: &[String], dry_run: Option<bool>, session_key: Option<&str>, write_enabled: bool) -> Result<String, String> {
    if raw_edits.len() > MAX_EDIT_FILES { return Err(format!("`edits` must contain 1..={MAX_EDIT_FILES} files")); }
    let dry_run = dry_run.unwrap_or(raw_edits.is_empty() && raw_creates.is_empty());
    if !dry_run && !write_enabled { return Err("REFUSED: read-only mode (run `ctx mode write` to enable edits)".to_string()); }
    let renames = if raw_renames.is_empty() { Vec::new() } else { parse_rename_specs(&Json::obj(vec![("renames", Json::Arr(raw_renames.to_vec()))]))? };
    let create_specs = parse_create_specs(raw_creates)?;
    validate_verify_absent(verify_absent)?;
    if raw_edits.is_empty() && renames.is_empty() && create_specs.is_empty() {
        return Err("`ctx_edit` requires at least one non-empty `edits`, `renames`, or `creates` array".to_string());
    }
    let (targets, admitted_creates) = collect_union_targets(svc, raw_edits, &renames, create_specs, cwd)?;
    let mut ws_roots: Vec<PathBuf> = targets.iter().map(|t| t.ws_root.clone()).chain(admitted_creates.iter().map(|c| c.ws_root.clone())).collect();
    ws_roots.sort(); ws_roots.dedup();
    let locks: Vec<Arc<Mutex<()>>> = ws_roots.iter().map(|ws| svc.workspace_write_lock(ws)).collect::<Result<Vec<_>, _>>()?;
    let mut _guards = Vec::with_capacity(locks.len());
    for lock in &locks { _guards.push(lock.lock().map_err(|_| "workspace write lock poisoned".to_string())?); }
    let mut summaries: Vec<RenameSummary> = renames.iter().map(|r| RenameSummary { old_name: r.old_name.clone(), new_name: r.new_name.clone(), occurrences: 0, files: 0, remaining_in_scope: 0 }).collect();
    let mut plans = Vec::with_capacity(targets.len());
    for target in targets { if let Some(plan) = prepare_file_plan(svc, target, &renames, &mut summaries)? { plans.push(plan); } }
    let mut create_plans = Vec::with_capacity(admitted_creates.len());
    for adm in admitted_creates { create_plans.push(prepare_create_plan(adm)?); }
    if dry_run {
        let vl = run_verify_absent(svc, &ws_roots, &plans, &create_plans, verify_absent, true);
        return Ok(render_report(&plans, &create_plans, &summaries, vl.as_deref(), None, None, true));
    }
    for plan in &plans {
        if file_stat(&plan.canon)? != plan.stamp { return Err(format!("REFUSED: `{}` changed on disk before commit; 0 files written", plan.rel_path)); }
    }
    let created_dirs = materialize_dirs_checked(&create_plans)?;
    let mut entries: Vec<CommitEntry<'_>> = Vec::with_capacity(plans.len() + create_plans.len());
    for p in &plans { entries.push(CommitEntry::Edit { canon: &p.canon, rel_path: &p.rel_path, orig_perms: &p.orig_perms, orig_bytes: &p.orig_bytes, new_bytes: &p.new_bytes }); }
    for cp in &create_plans {
        entries.push(if cp.existed {
            CommitEntry::Overwrite { canon: &cp.canon, rel_path: &cp.rel_path, orig_perms: cp.orig_perms.as_ref().expect("orig_perms"), target_perms: &cp.target_perms, orig_bytes: cp.orig_bytes.as_deref().expect("orig_bytes"), new_bytes: &cp.new_bytes }
        } else { CommitEntry::CreateNew { canon: &cp.canon, rel_path: &cp.rel_path, target_perms: &cp.target_perms, new_bytes: &cp.new_bytes } });
    }
    commit_all_atomic(&entries, &created_dirs, atomic_write_file)?;
    if !create_plans.is_empty() { svc.store.invalidate_workspace_indices(); }
    let out = render_report(&plans, &create_plans, &summaries, None, Some(svc), session_key, false);
    if let Some(vl) = run_verify_absent(svc, &ws_roots, &plans, &create_plans, verify_absent, false) {
        let mut combined = String::with_capacity(out.len() + vl.len());
        combined.push_str(&out); combined.push_str(&vl);
        return Ok(cap_utf8(&combined, MAX_REPORT_BYTES));
    }
    Ok(out)
}

fn parse_raw_array<'a>(req: &'a Json, key: &str, err_msg: &str) -> Result<&'a [Json], String> {
    match req.get(key) { None | Some(Json::Null) => Ok(&[]), Some(v) => v.as_arr().ok_or_else(|| err_msg.to_string()) }
}

fn parse_verify_absent(req: &Json) -> Result<Vec<String>, String> {
    let raw = parse_raw_array(req, "verify_absent", "`verify_absent` must be an array of 1..=4 identifiers")?;
    raw.iter().map(|i| i.as_str().map(|s| s.trim().to_string()).ok_or_else(|| "`verify_absent` entries must be strings".to_string())).collect()
}

fn validate_verify_absent(syms: &[String]) -> Result<(), String> {
    if syms.len() > MAX_VERIFY_ABSENT { return Err(format!("`verify_absent` supports at most {MAX_VERIFY_ABSENT} symbols")); }
    for s in syms {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > MAX_VERIFY_SYM_LEN || !(b[0].is_ascii_alphabetic() || b[0] == b'_') || !b[1..].iter().all(|&c| is_ident_char(c)) {
            return Err(format!("invalid `verify_absent` identifier `{s}`"));
        }
    }
    Ok(())
}

fn collect_union_targets(
    svc: &BrokerService, raw_edits: &[Json], renames: &[RenameSpec], create_specs: Vec<create::CreateSpec>, cwd: Option<&Path>,
) -> Result<(Vec<TargetFile>, Vec<AdmittedCreate>), String> {
    let (mut targets, mut idx_map) = (Vec::with_capacity(raw_edits.len()), FastHashMap::<PathBuf, usize>::default());
    for item in raw_edits {
        let raw_path = item.get_str("path").filter(|s| !s.trim().is_empty()).ok_or_else(|| "each edit entry requires a non-empty `path`".to_string())?;
        let ops = parse_file_ops(item, raw_path)?;
        let (canon, ws_root) = svc.allowlist.admit_writable_file(&resolve_input_path(raw_path, cwd), cwd)?;
        if idx_map.contains_key(&canon) { return Err(format!("duplicate target `{}` in edits batch", display_workspace_path(&canon, Some(&ws_root)))); }
        idx_map.insert(canon.clone(), targets.len());
        targets.push(TargetFile { canon, ws_root, explicit: true, ops, rename_indices: Vec::new() });
    }
    for (ri, spec) in renames.iter().enumerate() {
        for (canon, ws_root, explicit) in collect_scope_files(svc, &spec.scope, cwd, MAX_TOTAL_TOUCHED_FILES)? {
            if let Some(&idx) = idx_map.get(&canon) {
                targets[idx].explicit |= explicit;
                if targets[idx].rename_indices.last() != Some(&ri) { targets[idx].rename_indices.push(ri); }
            } else {
                if targets.len() >= MAX_TOTAL_TOUCHED_FILES { return Err(format!("REFUSED: total target scope exceeds max {MAX_TOTAL_TOUCHED_FILES} files across edits+renames")); }
                idx_map.insert(canon.clone(), targets.len());
                targets.push(TargetFile { canon, ws_root, explicit, ops: Vec::new(), rename_indices: vec![ri] });
            }
        }
    }
    let (mut creates, mut c_seen) = (Vec::with_capacity(create_specs.len()), FastHashMap::<PathBuf, ()>::default());
    for spec in create_specs {
        let adm = admit_new_file(svc, spec, cwd)?;
        if idx_map.contains_key(&adm.canon) || c_seen.insert(adm.canon.clone(), ()).is_some() {
            return Err(format!("duplicate target `{}` across creates/edits/renames", display_workspace_path(&adm.canon, Some(&adm.ws_root))));
        }
        if targets.len() + creates.len() >= MAX_TOTAL_TOUCHED_FILES { return Err(format!("REFUSED: total target scope exceeds max {MAX_TOTAL_TOUCHED_FILES} files")); }
        creates.push(adm);
    }
    Ok((targets, creates))
}

fn parse_file_ops(item: &Json, raw_path: &str) -> Result<Vec<EditOp>, String> {
    let raw_ops = item.get("ops").and_then(Json::as_arr).ok_or_else(|| format!("`{raw_path}` requires a non-empty `ops` array"))?;
    if raw_ops.is_empty() || raw_ops.len() > MAX_OPS_PER_FILE { return Err(format!("`{raw_path}` ops must contain 1..={MAX_OPS_PER_FILE} operations")); }
    let mut ops = Vec::with_capacity(raw_ops.len());
    for raw_op in raw_ops {
        let kind = raw_op.get_str("op").ok_or_else(|| format!("`{raw_path}` op missing `op`"))?;
        let content = raw_op.get_str("content").ok_or_else(|| format!("`{raw_path}` op `{kind}` missing `content`"))?;
        let lines: Vec<String> = if content.is_empty() { Vec::new() } else { content.lines().map(str::to_string).collect() };
        match kind {
            "replace_lines" => {
                let s_raw = raw_op.get_str("start").ok_or_else(|| format!("`{raw_path}` replace_lines missing `start`"))?;
                let (start_ln, start_h) = parse_line_anchor(s_raw)?;
                if start_ln == 0 { return Err(format!("`{raw_path}` replace_lines requires start line >= 1 (got `{s_raw}`)")); }
                let (end_ln, end_h) = match raw_op.get_str("end").filter(|s| !s.trim().is_empty()) {
                    Some(e_raw) => parse_line_anchor(e_raw)?,
                    None => (start_ln, start_h),
                };
                if end_ln < start_ln { return Err(format!("`{raw_path}` replace_lines end ({end_ln}) < start ({start_ln})")); }
                ops.push(EditOp::Replace { start_ln, start_h, end_ln, end_h, lines });
            }
            "insert_after" => {
                let (anchor_ln, anchor_h) = parse_line_anchor(raw_op.get_str("anchor").ok_or_else(|| format!("`{raw_path}` insert_after missing `anchor`"))?)?;
                ops.push(EditOp::InsertAfter { anchor_ln, anchor_h, lines });
            }
            other => return Err(format!("`{raw_path}` unsupported op `{other}` (use `replace_lines` or `insert_after`)")),
        }
    }
    Ok(ops)
}

fn prepare_file_plan(
    svc: &BrokerService, mut target: TargetFile, renames: &[RenameSpec], summaries: &mut [RenameSummary],
) -> Result<Option<FilePlan>, String> {
    let rel_path = display_workspace_path(&target.canon, Some(&target.ws_root));
    let orig_perms = fs::metadata(&target.canon).map_err(|e| format!("stat `{rel_path}`: {e}"))?.permissions();
    let stamp = file_stat(&target.canon)?;
    if stamp.size_bytes > MAX_SINGLE_FILE_CACHE_BYTES as u64 { return Err(format!("REFUSED: `{rel_path}` exceeds 1 MiB write limit ({} bytes)", stamp.size_bytes)); }
    let orig_bytes = fs::read(&target.canon).map_err(|e| format!("read `{rel_path}`: {e}"))?;
    if orig_bytes.iter().take(8192).any(|&b| b == 0) { return if target.explicit { Err(format!("REFUSED: `{rel_path}` is a binary file")) } else { Ok(None) }; }
    let orig_text = match std::str::from_utf8(&orig_bytes) {
        Ok(t) => t,
        Err(_) => return if target.explicit { Err(format!("REFUSED: `{rel_path}` is not valid UTF-8")) } else { Ok(None) },
    };
    let has_bom = orig_text.starts_with('\u{FEFF}');
    let bom_len = if has_bom { '\u{FEFF}'.len_utf8() } else { 0 };
    let orig_body = &orig_text[bom_len..];
    let has_edits = !target.ops.is_empty();
    let orig_lines: Vec<String> = if has_edits { orig_body.lines().map(str::to_string).collect() } else { Vec::new() };
    let mut cur_body: Option<String> = None;
    if has_edits {
        validate_anchors(svc, &target.canon, &target.ws_root, &rel_path, stamp, &orig_lines, &target.ops)?;
        validate_no_overlaps(&target.ops, &rel_path)?;
        target.ops.sort_by_key(|op| match op { EditOp::InsertAfter { anchor_ln, .. } => (*anchor_ln, 0u8), EditOp::Replace { start_ln, .. } => (*start_ln, 1u8) });
        let mut edited = orig_lines.clone();
        for op in target.ops.iter().rev() {
            match op {
                EditOp::Replace { start_ln, end_ln, lines, .. } => { edited.splice((start_ln - 1)..*end_ln, lines.iter().cloned()); }
                EditOp::InsertAfter { anchor_ln, lines, .. } => { edited.splice(*anchor_ln..*anchor_ln, lines.iter().cloned()); }
            }
        }
        cur_body = Some(join_body_lines(&edited, detect_line_ending(orig_body), orig_body.ends_with('\n'), orig_body.is_empty()));
    }
    let (mut eb, mut rename_hits) = ([0u8; 16], 0usize);
    let ext = ext_lower_buf(&target.canon, &mut eb);
    for &ri in &target.rename_indices {
        if let Some((next, count)) = apply_rename_to_body(cur_body.as_deref().unwrap_or(orig_body), ext, &renames[ri].old_name, &renames[ri].new_name, bom_len, &rel_path)? {
            summaries[ri].occurrences += count; summaries[ri].files += 1; rename_hits += count; cur_body = Some(next);
        }
    }
    if !has_edits && rename_hits == 0 { return Ok(None); }
    let final_body = cur_body.unwrap_or_else(|| orig_body.to_string());
    for &ri in &target.rename_indices { summaries[ri].remaining_in_scope += count_ident_in_body(&final_body, ext, &renames[ri].old_name); }
    if !has_edits && final_body == orig_body { return Ok(None); }
    if final_body.len().saturating_add(bom_len) > MAX_SINGLE_FILE_CACHE_BYTES {
        return Err(format!("REFUSED: `{rel_path}` rewritten size exceeds 1 MiB limit ({} bytes)", final_body.len().saturating_add(bom_len)));
    }
    let orig_lines = if has_edits { orig_lines } else { orig_body.lines().map(str::to_string).collect() };
    let new_lines: Vec<String> = final_body.lines().map(str::to_string).collect();
    let (diff_preview, edited_ranges, added, removed) = build_diff_and_ranges(&orig_lines, &new_lines, &target.ops);
    let mut new_text = String::with_capacity(final_body.len().saturating_add(bom_len));
    if has_bom { new_text.push('\u{FEFF}'); }
    new_text.push_str(&final_body);
    let mut warnings = Vec::new();
    if let Some(w) = check_delimiter_balance(&new_text, ext) { warnings.push(w); }
    warnings.extend(crate::base::ext::policy().post_edit_lint(&rel_path, &target.ws_root, &new_text, count_dir_files(&target.canon)));
    Ok(Some(FilePlan {
        canon: target.canon, ws_root: target.ws_root, rel_path, stamp, orig_perms, orig_bytes,
        new_bytes: new_text.into_bytes(), new_lines, added, removed, edited_ranges, diff_preview, warnings,
    }))
}

fn build_diff_and_ranges(orig: &[String], final_lines: &[String], ops: &[EditOp]) -> (String, Vec<(usize, usize)>, usize, usize) {
    let (mut diff, mut ranges, mut em, mut om, mut add, mut rem, mut oc, mut nc) = (String::new(), Vec::new(), 0, 0, 0, 0, 1, 1);
    let scan = |end: usize, oc: &mut usize, nc: &mut usize, d: &mut String, r: &mut Vec<(usize, usize)>, em: &mut usize, om: &mut usize, add: &mut usize, rem: &mut usize| {
        while *oc < end && *oc <= orig.len() {
            let (ol, nl) = (&orig[*oc - 1], final_lines.get(*nc - 1).map(String::as_str).unwrap_or(""));
            if ol != nl {
                push_diff_line(d, em, om, '-', *oc, ol); push_diff_line(d, em, om, '+', *nc, nl);
                *rem += 1; *add += 1; push_merged_range(r, *nc, *nc);
            }
            *oc += 1; *nc += 1;
        }
    };
    for op in ops {
        match op {
            EditOp::Replace { start_ln, end_ln, lines, .. } => {
                scan(*start_ln, &mut oc, &mut nc, &mut diff, &mut ranges, &mut em, &mut om, &mut add, &mut rem);
                rem += end_ln - start_ln + 1; add += lines.len();
                for ln in *start_ln..=*end_ln { push_diff_line(&mut diff, &mut em, &mut om, '-', ln, &orig[ln - 1]); }
                for k in 0..lines.len() { push_diff_line(&mut diff, &mut em, &mut om, '+', nc + k, final_lines.get(nc + k - 1).map(String::as_str).unwrap_or(&lines[k])); }
                if !final_lines.is_empty() {
                    let ns = nc.min(final_lines.len());
                    let ne = if lines.is_empty() { ns.saturating_sub(1).max(1) } else { (nc + lines.len() - 1).min(final_lines.len()) };
                    push_merged_range(&mut ranges, ns.min(ne), ns.max(ne));
                }
                oc = end_ln + 1; nc += lines.len();
            }
            EditOp::InsertAfter { anchor_ln, lines, .. } => {
                scan(*anchor_ln + 1, &mut oc, &mut nc, &mut diff, &mut ranges, &mut em, &mut om, &mut add, &mut rem);
                add += lines.len();
                for k in 0..lines.len() { push_diff_line(&mut diff, &mut em, &mut om, '+', nc + k, final_lines.get(nc + k - 1).map(String::as_str).unwrap_or(&lines[k])); }
                if !final_lines.is_empty() {
                    let ns = nc.min(final_lines.len());
                    let ne = if lines.is_empty() { ns } else { (nc + lines.len() - 1).min(final_lines.len()) };
                    push_merged_range(&mut ranges, ns, ne);
                }
                nc += lines.len();
            }
        }
    }
    scan(orig.len() + 1, &mut oc, &mut nc, &mut diff, &mut ranges, &mut em, &mut om, &mut add, &mut rem);
    if om > 0 { diff.push_str("... (+"); push_usize(&mut diff, om); diff.push_str(" more diff lines)\n"); }
    (diff, ranges, add, rem)
}

#[allow(clippy::too_many_arguments)]
fn validate_anchors(svc: &BrokerService, canon: &Path, ws_root: &Path, rel_path: &str, stamp: FileMetaStamp, orig_lines: &[String], ops: &[EditOp]) -> Result<(), String> {
    let total = orig_lines.len();
    let conflict = |focus: usize, reason: String| -> String {
        let win = match svc.store.get_full_entry(canon, Some(ws_root)) {
            Ok(e) if e.mtime_ns == stamp.mtime_ns && e.size_bytes as u64 == stamp.size_bytes => format_conflict_window(&e, focus, CONFLICT_RADIUS),
            _ => format_conflict_window_lines(orig_lines, focus, CONFLICT_RADIUS),
        };
        format!("CONFLICT in `{rel_path}`: {reason}\nCurrent lines:\n{win}")
    };
    let check = |ln: usize, want: [u8; 3]| -> Result<(), String> {
        let got = line_anchor_hash(ln, &orig_lines[ln - 1]);
        if got != want { return Err(conflict(ln, format!("L{ln} hash mismatch: expected `{}`, got `{}`", hash3_str(&want), hash3_str(&got)))); }
        Ok(())
    };
    for op in ops {
        match op {
            EditOp::Replace { start_ln, start_h, end_ln, end_h, .. } => {
                if *start_ln > total || *end_ln > total { return Err(conflict((*start_ln).min(total), format!("range {start_ln}..={end_ln} out of bounds ({total} lines)"))); }
                check(*start_ln, *start_h)?; check(*end_ln, *end_h)?;
            }
            EditOp::InsertAfter { anchor_ln, anchor_h, .. } => {
                if *anchor_ln > total { return Err(conflict(total, format!("anchor L{anchor_ln} out of bounds ({total} lines)"))); }
                if *anchor_ln > 0 { check(*anchor_ln, *anchor_h)?; }
            }
        }
    }
    Ok(())
}

fn validate_no_overlaps(ops: &[EditOp], rel_path: &str) -> Result<(), String> {
    for (i, a) in ops.iter().enumerate() {
        for b in &ops[i + 1..] {
            let clash = match (a, b) {
                (EditOp::Replace { start_ln: s1, end_ln: e1, .. }, EditOp::Replace { start_ln: s2, end_ln: e2, .. }) => *s1 <= *e2 && *s2 <= *e1,
                (EditOp::Replace { start_ln: s, end_ln: e, .. }, EditOp::InsertAfter { anchor_ln: anc, .. })
                | (EditOp::InsertAfter { anchor_ln: anc, .. }, EditOp::Replace { start_ln: s, end_ln: e, .. }) => *anc >= *s && *anc <= *e,
                (EditOp::InsertAfter { anchor_ln: a1, .. }, EditOp::InsertAfter { anchor_ln: a2, .. }) => a1 == a2,
            };
            if clash { return Err(format!("CONFLICT in `{rel_path}`: overlapping or duplicate edit anchors")); }
        }
    }
    Ok(())
}

fn scan_ident_lines(cleaned: &[u8], needle: &[u8], out_lines: &mut Vec<usize>, cap: usize) -> usize {
    let nlen = needle.len();
    if nlen == 0 || nlen > cleaned.len() { return 0; }
    let (first, last, mut i, mut count, mut line_no, mut scanned) = (needle[0], cleaned.len() - nlen, 0, 0, 1, 0);
    while i <= last {
        let Some(rel) = cleaned[i..=last].iter().position(|&b| b == first) else { break; };
        let pos = i + rel;
        if &cleaned[pos..pos + nlen] == needle && (pos == 0 || !is_ident_char(cleaned[pos - 1])) && (pos + nlen == cleaned.len() || !is_ident_char(cleaned[pos + nlen])) {
            count += 1;
            if out_lines.len() < cap {
                line_no += cleaned[scanned..pos].iter().filter(|&&b| b == b'\n').count();
                scanned = pos; out_lines.push(line_no);
            }
            i = pos + nlen; continue;
        }
        i = pos + 1;
    }
    count
}

fn run_verify_absent(svc: &BrokerService, ws_roots: &[PathBuf], plans: &[FilePlan], create_plans: &[CreatePlan], syms: &[String], dry_run: bool) -> Option<String> {
    if syms.is_empty() { return None; }
    let (mut counts, mut locs, mut seen) = (vec![0usize; syms.len()], (0..syms.len()).map(|_| Vec::<String>::new()).collect::<Vec<_>>(), FastHashMap::<PathBuf, ()>::default());
    let mut scan_text = |path: &Path, rel: &str, text: &str| {
        if !syms.iter().any(|s| text.contains(s.as_str())) { return; }
        let mut eb = [0u8; 16];
        let cleaned = build_cleaned_code_buffer_for_ext(text, ext_lower_buf(path, &mut eb));
        let mut lns = Vec::new();
        for (si, sym) in syms.iter().enumerate() {
            if !text.contains(sym.as_str()) { continue; }
            lns.clear();
            counts[si] += scan_ident_lines(cleaned.as_bytes(), sym.as_bytes(), &mut lns, MAX_VERIFY_LOCS.saturating_sub(locs[si].len()));
            for ln in &lns { locs[si].push(format!("{rel}:L{ln}")); }
        }
    };
    for (canon, ws, rel, bytes) in plans.iter().map(|p| (&p.canon, &p.ws_root, p.rel_path.as_str(), p.new_bytes.as_slice()))
        .chain(create_plans.iter().map(|c| (&c.canon, &c.ws_root, c.rel_path.as_str(), c.new_bytes.as_slice()))) {
        seen.insert(canon.clone(), ());
        if !dry_run {
            if let Ok(fe) = svc.store.get_full_entry(canon, Some(ws)) {
                if let Some(t) = fe.content.as_deref() { scan_text(canon, rel, t); continue; }
            }
        }
        if let Ok(t) = std::str::from_utf8(bytes) { scan_text(canon, rel, t); }
    }
    let mut ws_scanned = 0usize;
    for ws in ws_roots {
        let idx = svc.store.workspace_index(ws);
        for it in idx.entries.iter() {
            if ws_scanned >= MAX_VERIFY_WS_FILES { break; }
            let abs = idx.abs_path(it);
            if seen.contains_key(&abs) || is_sensitive_path_with_ws(&abs, Some(ws), false) { continue; }
            ws_scanned += 1;
            if let Ok(fe) = svc.store.get_full_entry(&abs, Some(ws)) {
                if let Some(t) = fe.content.as_deref() { scan_text(&abs, &fe.rel_path, t); }
            }
        }
    }
    let mut out = String::from("verify_absent: ");
    for (i, sym) in syms.iter().enumerate() {
        if i > 0 { out.push_str(", "); }
        out.push_str(sym); out.push('='); push_usize(&mut out, counts[i]);
        if !locs[i].is_empty() {
            out.push_str(" ("); out.push_str(&locs[i].join(", "));
            if counts[i] > locs[i].len() { out.push_str(", ..."); }
            out.push(')');
        }
    }
    out.push('\n');
    Some(out)
}

#[allow(clippy::too_many_arguments)]
fn render_report(
    plans: &[FilePlan], create_plans: &[CreatePlan], summaries: &[RenameSummary],
    verify_line: Option<&str>, sync_svc: Option<&BrokerService>, session_key: Option<&str>, dry_run: bool,
) -> String {
    let mut out = String::with_capacity(plans.len() * 320 + create_plans.len() * 96 + summaries.len() * 80 + 64);
    match (dry_run, plans.is_empty(), create_plans.is_empty()) {
        (true, _, true) => out.push_str(&format!("[DRY RUN — 0 files modified] ({} file(s) planned)\n", plans.len())),
        (true, true, false) => out.push_str(&format!("[DRY RUN — 0 files modified] ({} file(s) to create)\n", create_plans.len())),
        (true, false, false) => out.push_str(&format!("[DRY RUN — 0 files modified] ({} file(s) planned, {} file(s) to create)\n", plans.len(), create_plans.len())),
        (false, _, true) => out.push_str(&format!("[COMMITTED] {} file(s) modified\n", plans.len())),
        (false, true, false) => out.push_str(&format!("[COMMITTED] {} file(s) created\n", create_plans.len())),
        (false, false, false) => out.push_str(&format!("[COMMITTED] {} file(s) modified, {} file(s) created\n", plans.len(), create_plans.len())),
    }
    for rs in summaries {
        out.push_str(&format!("rename {} -> {}: {} occurrences across {} files (remaining_in_scope: {})\n", rs.old_name, rs.new_name, rs.occurrences, rs.files, rs.remaining_in_scope));
    }
    for p in plans {
        let total = p.new_lines.len();
        out.push_str(&format!("=== {} (+{}/-{} lines, {total}L{}) ===\n", p.rel_path, p.added, p.removed, line_count_flag(total)));
        out.push_str(&p.diff_preview);
        let syms = if dry_run {
            std::str::from_utf8(&p.new_bytes).map(|t| collect_overlapping_symbol_spans(&crate::parser::extract_symbols(&p.canon, t, &line_offsets_for_text(t)), &p.edited_ranges)).unwrap_or_default()
        } else if let Some(svc) = sync_svc {
            let s = svc.store.refresh_file_content(&p.canon, Some(&p.ws_root)).map(|e| collect_overlapping_symbols(&e, &p.edited_ranges)).unwrap_or_default();
            let _ = svc.broker.changes.record_change(&crate::store::norm_key_from_canon(&p.ws_root), &p.rel_path, s.clone(), session_key.unwrap_or(""), crate::store::now_ms_u64());
            s
        } else { Vec::new() };
        if !syms.is_empty() { out.push_str("Symbols: "); out.push_str(&syms.join(", ")); out.push('\n'); }
        for w in &p.warnings { out.push_str("Warning: "); out.push_str(w); out.push('\n'); }
        append_anchor_windows(&mut out, &p.new_lines, &p.edited_ranges);
    }
    for cp in create_plans {
        let syms = if dry_run {
            std::str::from_utf8(&cp.new_bytes).map(|t| collect_created_symbols(&crate::parser::extract_symbols(&cp.canon, t, &line_offsets_for_text(t)))).unwrap_or_default()
        } else if let Some(svc) = sync_svc {
            let s = svc.store.refresh_file_content(&cp.canon, Some(&cp.ws_root)).map(|e| collect_created_symbols(&e.symbols)).unwrap_or_default();
            let _ = svc.broker.changes.record_change(&crate::store::norm_key_from_canon(&cp.ws_root), &cp.rel_path, s.clone(), session_key.unwrap_or(""), crate::store::now_ms_u64());
            s
        } else { Vec::new() };
        render_create_line(&mut out, cp, &syms);
    }
    if let Some(vl) = verify_line { out.push_str(vl); }
    cap_utf8(&out, MAX_REPORT_BYTES)
}
