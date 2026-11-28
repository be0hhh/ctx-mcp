//! Strictly read-only, symbol- and hash-enriched Git inspection (`ctx_git`:
//! `diff` | `status` | `log` | `show`) with flag-injection guards and `SubprocSemaphore` bounds.

use super::hashline::push_hashed_line;
use super::{cap_utf8, collect_overlapping_symbols, count_dir_files, line_count_flag};
use crate::base::json::Json;
use crate::base::security::is_sensitive_path_with_ws;
use crate::base::simd::push_usize;
use crate::engine::DEFAULT_READ_MAX_BYTES;
use crate::rpc::BrokerService;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const GIT_TIMEOUT: Duration = Duration::from_secs(5);
const GIT_STDOUT_LIMIT: usize = 512 * 1024;
const GIT_STDERR_LIMIT: usize = 8 * 1024;
const MAX_STATUS_ENTRIES: usize = 60;

struct GitProcess(Child);

impl Drop for GitProcess {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

pub fn op_git(svc: &BrokerService, req: &Json, cwd: Option<&Path>) -> Result<String, String> {
    let action = req
        .get_str("action")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("diff");
    if !matches!(action, "diff" | "status" | "log" | "show") {
        return Err(format!(
            "REFUSED: unsupported git action `{action}` (read-only only: diff | status | log | show)"
        ));
    }
    let base = cwd
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let (_canon, ws_root) = svc.allowlist.admit_dir(&base, Some(&base))?;
    let is_agy = req.get_str("host") == Some("agy");
    let cap = if is_agy {
        crate::engine::AGY_MCP_DEFAULT_MAX_BYTES
    } else {
        DEFAULT_READ_MAX_BYTES
    };
    let max_bytes = req
        .get_usize("max_bytes")
        .filter(|&v| v > 0)
        .unwrap_or(8192)
        .clamp(512, cap);

    match action {
        "diff" => run_git_diff(svc, &ws_root, req, max_bytes),
        "status" => run_git_status(svc, &ws_root, max_bytes),
        "log" => run_git_log(svc, &ws_root, req, max_bytes),
        "show" => run_git_show(svc, &ws_root, req, max_bytes),
        _ => unreachable!(),
    }
}

fn run_git_diff(svc: &BrokerService, ws_root: &Path, req: &Json, max_bytes: usize) -> Result<String, String> {
    let staged = req.get_bool("staged").unwrap_or(false);
    let hashes = req.get_bool("hashes").unwrap_or(true);
    let stat_only = req.get_bool("stat").unwrap_or(false);
    let rev = req.get_str("rev").or_else(|| req.get_str("ref")).map(str::trim).filter(|s| !s.is_empty());
    let paths = extract_paths(req)?;

    let mut args = vec!["diff".into(), "--no-color".into()];
    if stat_only {
        args.push("--stat".into());
    } else {
        args.push("--unified=1".into());
    }
    if staged { args.push("--cached".into()); }
    if let Some(r) = rev {
        validate_git_rev(r)?;
        args.push(r.into());
    }
    args.push("--".into());
    for p in paths {
        validate_git_path(&p)?;
        args.push(p);
    }

    let raw = run_git_readonly(svc, ws_root, &args)?;
    if raw.trim().is_empty() {
        return Ok("No diff changes.\n".to_string());
    }
    if stat_only {
        let mut out = String::with_capacity(raw.len().min(max_bytes));
        for line in raw.lines() {
            let candidate = line.split('|').next().unwrap_or("").trim();
            if !candidate.is_empty() && is_sensitive_path_with_ws(&ws_root.join(candidate), Some(ws_root), false) {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        return Ok(cap_utf8(if out.is_empty() { "No non-sensitive diff changes.\n" } else { &out }, max_bytes));
    }
    Ok(cap_utf8(&render_enriched_diff(svc, ws_root, &raw, hashes), max_bytes))
}

fn run_git_status(svc: &BrokerService, ws_root: &Path, max_bytes: usize) -> Result<String, String> {
    let raw = run_git_readonly(svc, ws_root, &["status".into(), "--porcelain=v1".into(), "-b".into()])?;
    let mut rendered = render_status_porcelain(&raw);
    let conflicts = scan_dirty_conflict_markers(svc, ws_root, &raw);
    if !conflicts.is_empty() {
        rendered.push_str("Conflict markers (");
        push_usize(&mut rendered, conflicts.len());
        rendered.push_str("):\n");
        for c in conflicts {
            rendered.push_str("  ");
            rendered.push_str(&c);
            rendered.push('\n');
        }
    }
    Ok(cap_utf8(&rendered, max_bytes))
}

fn scan_dirty_conflict_markers(svc: &BrokerService, ws_root: &Path, porcelain: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let mut checked = 0usize;
    for line in porcelain.lines() {
        if checked >= 32 || hits.len() >= 16 { break; }
        let b = line.as_bytes();
        if b.len() < 4 || line.starts_with("## ") || b[0] == b'D' || b[1] == b'D' { continue; }
        let rel = line[3..].trim();
        let rel = rel.rsplit_once(" -> ").map_or(rel, |(_, dst)| dst);
        let cand = ws_root.join(rel);
        if is_sensitive_path_with_ws(&cand, Some(ws_root), false) { continue; }
        let Ok((canon, wr)) = svc.allowlist.admit_file(&cand, Some(ws_root)) else { continue; };
        if !canon.is_file() { continue; }
        checked += 1;
        let Ok(entry) = svc.store.get_full_entry(&canon, Some(&wr)) else { continue; };
        let Some(text) = entry.content() else { continue; };
        for (idx, l) in text.lines().enumerate() {
            if l.starts_with("<<<<<<< ") || l.starts_with(">>>>>>> ") {
                hits.push(format!("{}:{}: {}", entry.rel_path, idx + 1, l.trim()));
                break;
            }
        }
    }
    hits
}

fn run_git_log(svc: &BrokerService, ws_root: &Path, req: &Json, max_bytes: usize) -> Result<String, String> {
    let limit = req.get_usize("limit").unwrap_or(10).clamp(1, 40);
    let mut args = vec![
        "log".into(), "-n".into(), limit.to_string(),
        "--date=short".into(), "--pretty=format:%h %ad %s".into(),
    ];
    if let Some(sym) = req.get_str("symbol").map(str::trim).filter(|s| !s.is_empty()) {
        validate_git_symbol(sym)?;
        args.push(format!("-S{sym}"));
    }
    if let Some(path) = req.get_str("path").map(str::trim).filter(|s| !s.is_empty()) {
        validate_git_path(path)?;
        args.push("--".into());
        args.push(path.into());
    }
    let mut raw = run_git_readonly(svc, ws_root, &args)?;
    if raw.trim().is_empty() {
        return Ok("No matching commits.\n".to_string());
    }
    if !raw.ends_with('\n') { raw.push('\n'); }
    Ok(cap_utf8(&raw, max_bytes))
}

fn run_git_show(svc: &BrokerService, ws_root: &Path, req: &Json, max_bytes: usize) -> Result<String, String> {
    let rev = req
        .get_str("rev")
        .or_else(|| req.get_str("ref"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "`show` requires `rev`".to_string())?;
    validate_git_rev(rev)?;
    let hashes = req.get_bool("hashes").unwrap_or(false);
    let args = vec![
        "show".into(), "--unified=1".into(), "--no-color".into(),
        "--date=short".into(), "--format=commit %h %ad %an%n%s%n".into(),
        rev.into(), "--".into(),
    ];
    let raw = run_git_readonly(svc, ws_root, &args)?;
    let (header, diff_body) = match raw.find("\ndiff --git ") {
        Some(idx) => (&raw[..idx + 1], &raw[idx + 1..]),
        None if raw.starts_with("diff --git ") => ("", raw.as_str()),
        None => (raw.as_str(), ""),
    };
    let mut out = String::with_capacity(max_bytes.min(8192));
    out.push_str(header);
    if !diff_body.is_empty() {
        out.push_str(&render_enriched_diff(svc, ws_root, diff_body, hashes));
    }
    Ok(cap_utf8(&out, max_bytes))
}

fn extract_paths(req: &Json) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    if let Some(arr) = req.get("paths").and_then(Json::as_arr) {
        for v in arr {
            let s = v.as_str().map(str::trim).filter(|s| !s.is_empty())
                .ok_or_else(|| "`paths` entries must be non-empty strings".to_string())?;
            if s == "--" {
                continue;
            }
            out.push(s.to_string());
        }
    } else if let Some(single) = req.get_str("path").map(str::trim).filter(|s| !s.is_empty()) {
        if single != "--" {
            out.push(single.to_string());
        }
    }
    Ok(out)
}

fn validate_git_rev(rev: &str) -> Result<(), String> {
    if rev.is_empty() || rev.len() > 256 || rev.starts_with('-') || rev.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("REFUSED: invalid git revision `{rev}`"));
    }
    Ok(())
}

fn validate_git_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > 512 || path.starts_with('-') || path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("REFUSED: invalid git path `{path}`"));
    }
    Ok(())
}

fn validate_git_symbol(sym: &str) -> Result<(), String> {
    if sym.is_empty() || sym.len() > 256 || sym.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("REFUSED: invalid git symbol filter `{sym}`"));
    }
    Ok(())
}

fn run_git_readonly(svc: &BrokerService, ws_root: &Path, args: &[String]) -> Result<String, String> {
    let deadline = Instant::now() + GIT_TIMEOUT;
    let _permit = svc.subproc_sem.acquire_until(deadline)?
        .ok_or_else(|| "git subprocess semaphore saturated".to_string())?;
    let child = crate::base::platform::hidden_command(crate::base::platform::resolve_tool("git"))
        .arg("-C").arg(ws_root).arg("--no-pager").args(args)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run git: {e}"))?;
    collect_git_output(GitProcess(child), deadline)
}

fn collect_git_output(mut proc: GitProcess, deadline: Instant) -> Result<String, String> {
    let stdout = proc.0.stdout.take().ok_or_else(|| "missing piped git stdout".to_string())?;
    let stderr = proc.0.stderr.take().ok_or_else(|| "missing piped git stderr".to_string())?;
    let (tx, rx) = mpsc::sync_channel::<(bool, io::Result<Vec<u8>>)>(2);
    let out_tx = tx.clone();
    thread::Builder::new().spawn(move || { let _ = out_tx.send((true, read_capped(stdout, GIT_STDOUT_LIMIT))); })
        .map_err(|e| format!("git stdout reader: {e}"))?;
    thread::Builder::new().spawn(move || { let _ = tx.send((false, read_capped(stderr, GIT_STDERR_LIMIT))); })
        .map_err(|e| format!("git stderr reader: {e}"))?;

    let (mut out_b, mut err_b) = (None, None);
    while out_b.is_none() || err_b.is_none() {
        let rem = deadline.checked_duration_since(Instant::now())
            .ok_or_else(|| "git command timed out after 5s".to_string())?;
        let (is_out, res) = rx.recv_timeout(rem).map_err(|_| "git command timed out after 5s".to_string())?;
        let data = res.map_err(|e| format!("read git output: {e}"))?;
        if is_out { out_b = Some(data); } else { err_b = Some(data); }
    }
    let status = loop {
        let rem = deadline.checked_duration_since(Instant::now())
            .ok_or_else(|| "git command timed out after 5s".to_string())?;
        match proc.0.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => thread::sleep(rem.min(Duration::from_millis(5))),
            Err(e) => return Err(format!("wait for git: {e}")),
        }
    };
    if !status.success() {
        let diag = String::from_utf8_lossy(&err_b.unwrap_or_default()).trim().to_string();
        return Err(if diag.is_empty() { format!("git failed ({status})") } else { format!("git failed ({status}): {diag}") });
    }
    Ok(String::from_utf8_lossy(&out_b.unwrap_or_default()).into_owned())
}

fn read_capped(mut input: impl Read, cap: usize) -> io::Result<Vec<u8>> {
    let (mut out, mut buf) = (Vec::new(), [0u8; 4096]);
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 { return Ok(out); }
        let keep = n.min(cap.saturating_sub(out.len()));
        if keep > 0 { out.extend_from_slice(&buf[..keep]); }
    }
}

fn render_status_porcelain(raw: &str) -> String {
    let (mut branch, mut staged, mut modified, mut untracked) = (String::new(), Vec::new(), Vec::new(), Vec::new());
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            branch = rest.trim().to_string();
            continue;
        }
        let b = line.as_bytes();
        if b.len() < 4 { continue; }
        let (x, y, path) = (b[0], b[1], line[3..].trim());
        if x == b'?' && y == b'?' {
            untracked.push(path.to_string());
        } else {
            if x != b' ' { staged.push(format!("{} {path}", x as char)); }
            if y != b' ' { modified.push(format!("{} {path}", y as char)); }
        }
    }
    let mut out = String::new();
    if !branch.is_empty() { out.push_str("Branch: "); out.push_str(&branch); out.push('\n'); }
    if staged.is_empty() && modified.is_empty() && untracked.is_empty() {
        out.push_str("Clean working tree.\n");
        return out;
    }
    let mut left = MAX_STATUS_ENTRIES;
    for (title, items) in [("Staged", &staged), ("Modified", &modified), ("Untracked", &untracked)] {
        if items.is_empty() { continue; }
        out.push_str(title);
        out.push_str(" (");
        push_usize(&mut out, items.len());
        out.push_str("):\n");
        let show = items.len().min(left);
        for item in &items[..show] { out.push_str("  "); out.push_str(item); out.push('\n'); }
        left -= show;
        if items.len() > show {
            out.push_str("  ... (+");
            push_usize(&mut out, items.len() - show);
            out.push_str(" more)\n");
        }
    }
    out
}

fn render_enriched_diff(svc: &BrokerService, ws_root: &Path, raw_diff: &str, hashes: bool) -> String {
    let mut out = String::with_capacity(raw_diff.len().min(16_384));
    let mut chunk: Vec<&str> = Vec::new();
    for line in raw_diff.lines() {
        if line.starts_with("diff --git ") && !chunk.is_empty() {
            render_file_diff(svc, ws_root, &chunk, hashes, &mut out);
            chunk.clear();
        }
        chunk.push(line);
    }
    if !chunk.is_empty() {
        render_file_diff(svc, ws_root, &chunk, hashes, &mut out);
    }
    if out.is_empty() { "No non-sensitive diff changes.\n".to_string() } else { out }
}

fn render_file_diff(svc: &BrokerService, ws_root: &Path, lines: &[&str], hashes: bool, out: &mut String) {
    let (mut old_p, mut new_p, mut is_bin) = ("", "", false);
    for &l in lines {
        if let Some(p) = l.strip_prefix("--- ") { old_p = clean_diff_path(p); }
        else if let Some(p) = l.strip_prefix("+++ ") { new_p = clean_diff_path(p); }
        else if l.starts_with("Binary files ") { is_bin = true; }
        else if l.starts_with("@@ ") { break; }
    }
    let deleted = new_p == "/dev/null";
    let rel = if !new_p.is_empty() && !deleted { new_p } else if !old_p.is_empty() && old_p != "/dev/null" { old_p } else { return; };
    if (!old_p.is_empty() && old_p != "/dev/null" && is_sensitive_path_with_ws(&ws_root.join(old_p), Some(ws_root), false))
        || (!new_p.is_empty() && !deleted && is_sensitive_path_with_ws(&ws_root.join(new_p), Some(ws_root), false))
    {
        return;
    }

    let (mut added, mut removed, mut new_ln, mut in_hunk) = (0usize, 0usize, 0usize, false);
    let mut changed_ranges: Vec<(usize, usize)> = Vec::new();
    let mut body = String::new();
    for &line in lines {
        if line.starts_with("@@ ") {
            in_hunk = true;
            new_ln = parse_hunk_new_start(line).unwrap_or(1);
            body.push_str(line);
            body.push('\n');
            continue;
        }
        if !in_hunk { continue; }
        if let Some(rest) = line.strip_prefix('+') {
            added += 1;
            changed_ranges.push((new_ln, new_ln));
            if hashes {
                body.push('+');
                push_hashed_line(&mut body, new_ln, rest);
            } else {
                body.push_str(line);
                body.push('\n');
            }
            new_ln += 1;
        } else if line.starts_with('-') {
            removed += 1;
            body.push_str(line);
            body.push('\n');
        } else if line.starts_with(' ') {
            body.push_str(line);
            body.push('\n');
            new_ln += 1;
        }
    }

    if is_bin {
        out.push_str(&format!("=== {rel} (binary) ===\n"));
        return;
    }
    let cand = ws_root.join(rel);
    let entry = (!deleted).then(|| {
        svc.allowlist.admit_file(&cand, Some(ws_root)).ok()
            .and_then(|(c, wr)| svc.store.get_full_entry(&c, Some(&wr)).ok().map(|e| (c, wr, e)))
    }).flatten();

    if let Some((canon, wr, e)) = entry {
        let total = e.line_count as usize;
        out.push_str(&format!("=== {rel} (+{added}/-{removed}, {total}L{}) ===\n", line_count_flag(total)));
        let syms = collect_overlapping_symbols(&e, &changed_ranges);
        if !syms.is_empty() {
            out.push_str("Symbols: ");
            out.push_str(&syms.join(", "));
            out.push('\n');
        }
        if let Some(content) = e.content() {
            let df = count_dir_files(&canon);
            for w in crate::base::ext::policy().post_edit_lint(&e.rel_path, &wr, content, df) {
                out.push_str("Warning: ");
                out.push_str(&w);
                out.push('\n');
            }
        }
    } else if deleted {
        out.push_str(&format!("=== {rel} (deleted, -{removed}) ===\n"));
    } else {
        out.push_str(&format!("=== {rel} (+{added}/-{removed}) ===\n"));
    }
    out.push_str(&body);
}

fn clean_diff_path(raw: &str) -> &str {
    let t = raw.trim().trim_matches('"');
    t.strip_prefix("a/").or_else(|| t.strip_prefix("b/")).unwrap_or(t)
}

fn parse_hunk_new_start(header: &str) -> Option<usize> {
    let plus = header.split_once(" +")?.1;
    let digits = plus.bytes().take_while(u8::is_ascii_digit).count();
    (digits > 0).then(|| plus[..digits].parse::<usize>().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::simd::line_hash3;
    use crate::edit::hashline::hash3_str;
    use std::fs;

    #[test]
    fn validates_inputs_and_refuses_mutating_actions() {
        assert!(validate_git_rev("HEAD").is_ok() && validate_git_rev("main..HEAD").is_ok());
        assert!(validate_git_rev("--exec=sh").is_err() && validate_git_rev("-n").is_err() && validate_git_rev("a\nb").is_err());
        assert!(validate_git_path("src/lib.rs").is_ok() && validate_git_path("-rf").is_err());
        assert!(validate_git_symbol("op_edit").is_ok() && validate_git_symbol("bad\0sym").is_err());

        let svc = BrokerService::new_ephemeral_inproc(PathBuf::from("unused"));
        for bad in ["commit", "push", "reset", "checkout", "clean", "apply"] {
            let req = Json::obj(vec![("action", Json::Str(bad.into()))]);
            assert!(op_git(&svc, &req, None).unwrap_err().contains("REFUSED: unsupported git action"));
        }

        // Defensively ignore bare `--` separator entries from MCP/CLI callers.
        let with_dd = Json::obj(vec![(
            "paths",
            Json::Arr(vec![Json::Str("--".into()), Json::Str("src/a.rs".into())]),
        )]);
        assert_eq!(extract_paths(&with_dd).unwrap(), vec!["src/a.rs".to_string()]);
        let only_dd = Json::obj(vec![("paths", Json::Arr(vec![Json::Str("--".into())]))]);
        assert!(extract_paths(&only_dd).unwrap().is_empty());
        let single_dd = Json::obj(vec![("path", Json::Str("--".into()))]);
        assert!(extract_paths(&single_dd).unwrap().is_empty());
    }

    #[test]
    fn parses_hunks_status_and_enriches_diff_filtering_secrets() {
        assert_eq!(parse_hunk_new_start("@@ -10,3 +22,5 @@ fn x"), Some(22));
        assert_eq!(parse_hunk_new_start("@@ -1 +1 @@"), Some(1));

        let st = render_status_porcelain("## main...origin/main\nM  a.rs\n M b.rs\n?? c.rs\n");
        assert!(st.contains("Branch: main...origin/main") && st.contains("Staged (1):\n  M a.rs"));
        assert!(st.contains("Modified (1):\n  M b.rs") && st.contains("Untracked (1):\n  c.rs"));

        let ws = std::env::temp_dir().join(format!("ctx-git-{}-{}", std::process::id(), crate::store::now_ms_u64()));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("demo.rs"), "fn alpha() {\n    let v = 42;\n}\n").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();

        let sample = concat!(
            "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-SECRET=old\n+SECRET=new\n",
            "diff --git a/demo.rs b/demo.rs\n--- a/demo.rs\n+++ b/demo.rs\n@@ -1,3 +1,3 @@\n fn alpha() {\n-    let v = 1;\n+    let v = 42;\n }\n",
        );
        let rendered = render_enriched_diff(&svc, &ws, sample, true);
        assert!(!rendered.contains(".env") && !rendered.contains("SECRET=new"));
        assert!(rendered.contains("=== demo.rs (+1/-1, 3L) ===") && rendered.contains("Symbols: @alpha"));
        let h = line_hash3("    let v = 42;");
        assert!(rendered.contains(&format!("+2:{}|     let v = 42;", hash3_str(&h))));
        let _ = fs::remove_dir_all(&ws);
    }
}
