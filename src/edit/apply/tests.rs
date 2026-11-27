//! Unit tests for `ctx_edit` (`edits`, `renames`, `creates`, rollback, and `verify_absent`).

use super::create::{commit_all_atomic, CommitEntry};
use super::{op_edit_full, op_edit_with_write_gate};
use crate::base::json::Json;
use crate::base::simd::line_hash3;
use crate::edit::{atomic_write_file, check_delimiter_balance, hashline::hash3_str};
use crate::rpc::BrokerService;
use std::fs;
#[cfg(unix)]
use std::fs::Permissions;
use std::path::PathBuf;

fn anc(ln: usize, line: &str) -> String {
    format!("{ln}:{}", hash3_str(&line_hash3(line)))
}

fn mk_ws(tag: &str) -> (PathBuf, BrokerService) {
    let ws = std::env::temp_dir().join(format!(
        "ctx-edit-{tag}-{}-{}",
        std::process::id(),
        crate::store::now_ms_u64()
    ));
    fs::create_dir_all(&ws).unwrap();
    let svc = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
    svc.allowlist.register_hint(&ws, true).unwrap();
    (ws, svc)
}

#[test]
fn gate0_dry_run_commit_bom_crlf_conflict_and_syntax() {
    let (ws, svc) = mk_ws("gate0");
    let (f_main, f_empty) = (ws.join("sample.rs"), ws.join("empty.rs"));
    fs::write(&f_main, "\u{FEFF}fn one() {}\r\nfn two() {}\r\n").unwrap();
    fs::write(&f_empty, "").unwrap();
    let edits = Json::Arr(vec![
        Json::obj(vec![("path", Json::Str("sample.rs".into())), ("ops", Json::Arr(vec![Json::obj(vec![
            ("op", Json::Str("replace_lines".into())), ("start", Json::Str(anc(2, "fn two() {}"))), ("content", Json::Str("fn two() { let x = 1; }".into())),
        ])]))]),
        Json::obj(vec![("path", Json::Str("empty.rs".into())), ("ops", Json::Arr(vec![Json::obj(vec![
            ("op", Json::Str("insert_after".into())), ("anchor", Json::Str("0:000".into())), ("content", Json::Str("fn boot() {}".into())),
        ])]))]),
    ]);
    let req = Json::obj(vec![("edits", edits.clone())]);
    assert!(op_edit_with_write_gate(&svc, &req, None, Some(&ws), false).unwrap_err().contains("REFUSED: read-only mode"));
    let dry_out = op_edit_with_write_gate(&svc, &Json::obj(vec![("dry_run", Json::Bool(true)), ("edits", edits)]), None, Some(&ws), false).unwrap();
    assert!(dry_out.contains("[DRY RUN — 0 files modified]") && dry_out.contains("-L2 fn two() {}") && dry_out.contains("+L2 fn two() { let x = 1; }") && dry_out.contains("@two"));
    assert_eq!(fs::read_to_string(&f_empty).unwrap(), "");
    let out = op_edit_with_write_gate(&svc, &req, Some("s-edit"), Some(&ws), true).unwrap();
    assert!(out.contains("[COMMITTED] 2 file(s) modified") && out.contains("sample.rs (+1/-1 lines") && out.contains("@two"));
    assert!(out.contains(&format!("{}| fn two() {{ let x = 1; }}", anc(2, "fn two() { let x = 1; }"))));
    assert_eq!(fs::read(&f_main).unwrap(), b"\xEF\xBB\xBFfn one() {}\r\nfn two() { let x = 1; }\r\n");
    assert_eq!(fs::read_to_string(&f_empty).unwrap(), "fn boot() {}\n");
    assert!(svc.store.get_full_entry(&fs::canonicalize(&f_main).unwrap(), Some(&ws)).unwrap().content().unwrap().contains("let x = 1;"));
    let wrong = if line_hash3("fn two() { let x = 1; }") == *b"fff" { "2:000" } else { "2:fff" };
    let bad = Json::obj(vec![("edits", Json::Arr(vec![Json::obj(vec![("path", Json::Str("sample.rs".into())), ("ops", Json::Arr(vec![Json::obj(vec![
        ("op", Json::Str("replace_lines".into())), ("start", Json::Str(wrong.into())), ("content", Json::Str("x".into())),
    ])]))])]))]);
    let conf = op_edit_with_write_gate(&svc, &bad, None, Some(&ws), true).unwrap_err();
    assert!(conf.contains("CONFLICT") && conf.contains("fn two() { let x = 1; }"));
    assert!(check_delimiter_balance("#ifdef X\nvoid f() {\n#endif\n", "cpp").is_none() && check_delimiter_balance("fn f() {\n", "rs").is_some());
    let _ = fs::remove_dir_all(&ws);
}

#[test]
fn unified_combined_edits_renames_and_verify_absent_dry_and_commit() {
    let (ws, svc) = mk_ws("uni");
    fs::create_dir_all(ws.join("src")).unwrap();
    let (f_calc, f_call, f_other) = (ws.join("src/calc.rs"), ws.join("src/caller.rs"), ws.join("src/other.rs"));
    let orig_calc = "\u{FEFF}// compute_fee in comment\r\npub fn compute_fee(x: i32) -> i32 {\r\n    let _ = \"compute_fee in str\";\r\n    x + 1\r\n}\r\n";
    fs::write(&f_calc, orig_calc).unwrap();
    fs::write(&f_call, "fn run_it() -> i32 { compute_fee(compute_fee(1)) }").unwrap();
    fs::write(&f_other, "// stale_sym in comment\nfn keep() { stale_sym(); }\n").unwrap();
    assert!(op_edit_with_write_gate(&svc, &Json::obj(vec![]), None, Some(&ws), true).is_err());
    let rename_spec = Json::obj(vec![("old_name", Json::Str("compute_fee".into())), ("new_name", Json::Str("calc_fee".into())), ("roots", Json::Arr(vec![Json::Str("src".into())]))]);
    let va = Json::Arr(vec![Json::Str("compute_fee".into()), Json::Str("stale_sym".into())]);
    let prev = op_edit_with_write_gate(&svc, &Json::obj(vec![("renames", Json::Arr(vec![rename_spec.clone()])), ("verify_absent", va.clone())]), None, Some(&ws), false).unwrap();
    assert!(prev.contains("[DRY RUN — 0 files modified]") && prev.contains("rename compute_fee -> calc_fee: 3 occurrences across 2 files (remaining_in_scope: 0)"));
    assert!(prev.contains("verify_absent: compute_fee=0, stale_sym=1 (src/other.rs:L2)") && fs::read_to_string(&f_calc).unwrap() == orig_calc);
    let combined = Json::obj(vec![
        ("edits", Json::Arr(vec![Json::obj(vec![("path", Json::Str("src/calc.rs".into())), ("ops", Json::Arr(vec![Json::obj(vec![
            ("op", Json::Str("replace_lines".into())), ("start", Json::Str(anc(4, "    x + 1"))), ("content", Json::Str("    if x == 0 { return compute_fee(1); }\n    x + 2".into())),
        ])]))])])),
        ("renames", Json::Arr(vec![rename_spec])), ("verify_absent", va),
    ]);
    assert!(op_edit_with_write_gate(&svc, &combined, Some("s-comb"), Some(&ws), false).unwrap_err().contains("REFUSED: read-only mode"));
    let out = op_edit_with_write_gate(&svc, &combined, Some("s-comb"), Some(&ws), true).unwrap();
    assert!(out.contains("[COMMITTED] 2 file(s) modified") && out.contains("rename compute_fee -> calc_fee: 4 occurrences across 2 files (remaining_in_scope: 0)"));
    assert!(out.contains("verify_absent: compute_fee=0, stale_sym=1 (src/other.rs:L2)") && out.contains("@calc_fee") && out.contains("@run_it"));
    assert_eq!(fs::read(&f_call).unwrap(), b"fn run_it() -> i32 { calc_fee(calc_fee(1)) }");
    assert_eq!(svc.broker.changes.changes_since(&crate::store::norm_key_from_canon(&fs::canonicalize(&ws).unwrap()), 0, 16).1.len(), 2);
    let _ = fs::remove_dir_all(&ws);
}

#[test]
fn creates_commit_exec_bit_refuse_overwrite_and_pure_create_defaults() {
    let (ws, svc) = mk_ws("main");
    let body = "#!/bin/sh\ncheck_ok() {\n  echo ok\n}\n";
    let cr = vec![Json::obj(vec![("path", Json::Str("scripts/check.sh".into())), ("content", Json::Str(body.into())), ("executable", Json::Bool(true))])];
    let req = Json::obj(vec![("creates", Json::Arr(cr.clone()))]);
    assert!(op_edit_with_write_gate(&svc, &req, None, Some(&ws), false).unwrap_err().contains("REFUSED: read-only mode"));
    let dry_full = op_edit_full(&svc, Some(&ws), &[], &[], &cr, &["missing_sym".into()], Some(true), None);
    assert_eq!(dry_full.get_bool("ok"), Some(true));
    assert!(dry_full.get_str("text").unwrap().contains("verify_absent: missing_sym=0") && !ws.join("scripts").exists());
    let out = op_edit_with_write_gate(&svc, &req, Some("s-cr"), Some(&ws), true).unwrap();
    assert!(out.contains("[COMMITTED]") && out.contains(&format!("CREATED scripts/check.sh (4L, {}B+x)", body.len())) && out.contains("@check_ok") && !out.contains("echo ok"));
    let f = ws.join("scripts/check.sh");
    assert_eq!(fs::read_to_string(&f).unwrap(), body);
    #[cfg(unix)]
    { use std::os::unix::fs::PermissionsExt; assert_eq!(fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o755); }
    assert!(op_edit_with_write_gate(&svc, &req, None, Some(&ws), true).unwrap_err().contains("already exists"));
    let _ = fs::remove_dir_all(&ws);
}

#[test]
fn creates_rejects_traversal_git_symlink_sensitive_nul_and_dup_with_edits() {
    let (ws, svc) = mk_ws("sec");
    fs::create_dir_all(ws.join(".git")).unwrap();
    fs::write(ws.join("exist.rs"), "fn a() {}\n").unwrap();
    for bad in ["sub/../escape.rs", "../outside.rs", ".git/hooks/pre-commit", ".env", "sub/id_rsa"] {
        let r = Json::obj(vec![("creates", Json::Arr(vec![Json::obj(vec![("path", Json::Str(bad.into())), ("content", Json::Str("x\n".into()))])]))]);
        assert!(op_edit_with_write_gate(&svc, &r, None, Some(&ws), true).unwrap_err().contains("REFUSED"), "must reject {bad}");
    }
    let nul_r = Json::obj(vec![("creates", Json::Arr(vec![Json::obj(vec![("path", Json::Str("bin.txt".into())), ("content", Json::Str("a\0b".into()))])]))]);
    assert!(op_edit_with_write_gate(&svc, &nul_r, None, Some(&ws), true).unwrap_err().contains("NUL"));
    #[cfg(unix)]
    {
        let real_dir = ws.join("real"); fs::create_dir_all(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, ws.join("symdir")).unwrap();
        std::os::unix::fs::symlink(ws.join("exist.rs"), ws.join("symfile.rs")).unwrap();
        for bad in ["symdir/new.rs", "symdir/sub/new.rs", "symfile.rs"] {
            let r = Json::obj(vec![("creates", Json::Arr(vec![Json::obj(vec![
                ("path", Json::Str(bad.into())), ("content", Json::Str("fn x() {}\n".into())), ("overwrite", Json::Bool(true)),
            ])]))]);
            assert!(op_edit_with_write_gate(&svc, &r, None, Some(&ws), true).unwrap_err().contains("symlink"), "must reject {bad}");
        }
    }
    let dup = Json::obj(vec![
        ("edits", Json::Arr(vec![Json::obj(vec![("path", Json::Str("exist.rs".into())), ("ops", Json::Arr(vec![Json::obj(vec![
            ("op", Json::Str("replace_lines".into())), ("start", Json::Str(anc(1, "fn a() {}"))), ("content", Json::Str("fn b() {}".into())),
        ])]))])])),
        ("creates", Json::Arr(vec![Json::obj(vec![("path", Json::Str("exist.rs".into())), ("content", Json::Str("fn c() {}\n".into())), ("overwrite", Json::Bool(true))])])),
    ]);
    assert!(op_edit_with_write_gate(&svc, &dup, None, Some(&ws), true).unwrap_err().contains("duplicate target"));
    let _ = fs::remove_dir_all(&ws);
}

#[test]
fn overwrite_rollback_restores_orig_bytes_perms_and_cleans_created_dirs() {
    let (ws, _) = mk_ws("rb");
    let existing = ws.join("keep.rs");
    fs::write(&existing, "orig-data\n").unwrap();
    let orig_perms = fs::metadata(&existing).unwrap().permissions();
    #[cfg(unix)]
    let exec_perms = { use std::os::unix::fs::PermissionsExt; Permissions::from_mode(0o755) };
    #[cfg(not(unix))]
    let exec_perms = orig_perms.clone();
    let new_dir = ws.join("nested/dir");
    fs::create_dir_all(&new_dir).unwrap();
    let created_dirs = vec![ws.join("nested"), new_dir.clone()];
    let (f_new, f_fail) = (new_dir.join("a.rs"), new_dir.join("b.rs"));
    let entries = [
        CommitEntry::Overwrite { canon: &existing, rel_path: "keep.rs", orig_perms: &orig_perms, target_perms: &exec_perms, orig_bytes: b"orig-data\n", new_bytes: b"replaced\n" },
        CommitEntry::CreateNew { canon: &f_new, rel_path: "nested/dir/a.rs", target_perms: &orig_perms, new_bytes: b"new\n" },
        CommitEntry::CreateNew { canon: &f_fail, rel_path: "nested/dir/b.rs", target_perms: &orig_perms, new_bytes: b"boom\n" },
    ];
    let err = commit_all_atomic(&entries, &created_dirs, |p, data, perms| {
        if p == f_fail.as_path() { return Err("disk full".into()); }
        atomic_write_file(p, data, perms)
    }).unwrap_err();
    assert!(err.contains("rolled back 2 file(s)"));
    assert_eq!(fs::read(&existing).unwrap(), b"orig-data\n");
    #[cfg(unix)]
    { use std::os::unix::fs::PermissionsExt; assert_eq!(fs::metadata(&existing).unwrap().permissions().mode() & 0o777, orig_perms.mode() & 0o777); }
    assert!(!f_new.exists() && !ws.join("nested").exists());
    let _ = fs::remove_dir_all(&ws);
}
