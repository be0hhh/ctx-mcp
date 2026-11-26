//! Structured compiler, linker, and test-runner root-cause extractor (`ctx diag`).
//! Supports Clang/GCC/MSVC/Rust/Python/TS/Go, CMake, ld/lld, cargo test, pytest, ctest, go test.

use super::logs::{clip_str, strip_ansi_and_cr, truncate_utf8_bytes, MAX_UNIQUE_TEMPLATES};
use crate::base::security::is_sensitive_path_with_ws;
use crate::base::simd::{fast_hash64, line_hash3, push_usize, FastHashMap};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_SRC_BYTES: u64 = 1 << 20;

struct UniqueError {
    norm_path: String, raw_path: String, line: usize, col: Option<usize>, msg: String, dup_count: usize,
}

struct DiagState<'a> {
    cwd: &'a Path, canon_cwd: Option<PathBuf>, unique: Vec<UniqueError>,
    index: FastHashMap<(String, usize, u64), usize>, summary_lines: Vec<String>,
    raw_errors: usize, notes_collapsed: usize,
}

impl<'a> DiagState<'a> {
    fn new(cwd: &'a Path) -> Self {
        Self {
            cwd, canon_cwd: fs::canonicalize(cwd).ok(), unique: Vec::new(),
            index: FastHashMap::default(), summary_lines: Vec::new(), raw_errors: 0, notes_collapsed: 0,
        }
    }
    fn candidate(&self, raw: &str) -> PathBuf {
        let p = Path::new(raw); if p.is_absolute() { p.to_path_buf() } else { self.cwd.join(p) }
    }
    fn resolves_in_cwd(&self, raw: &str) -> bool {
        self.canon_cwd.as_deref().is_some_and(|r| fs::canonicalize(self.candidate(raw)).ok().is_some_and(|c| c.starts_with(r) && c.is_file()))
    }
    fn push_error(&mut self, raw_path: &str, line: usize, col: Option<usize>, msg: String) {
        self.raw_errors += 1;
        let norm_path = if line == 0 && !raw_path.contains(['/', '\\', '.']) { raw_path.to_string() }
            else { normalize_diag_path(raw_path, self.cwd, self.canon_cwd.as_deref()) };
        let key = (norm_path.clone(), line, if line == 0 { fast_hash64(msg.as_bytes()) } else { 0 });
        if let Some(&slot) = self.index.get(&key) { self.unique[slot].dup_count += 1; }
        else if self.unique.len() < MAX_UNIQUE_TEMPLATES {
            self.index.insert(key, self.unique.len());
            self.unique.push(UniqueError { norm_path, raw_path: raw_path.to_string(), line, col, msg, dup_count: 0 });
        }
    }
    fn push_summary(&mut self, line: &str) {
        if self.summary_lines.len() < 8 && !self.summary_lines.iter().any(|s| s == line) {
            self.summary_lines.push(clip_str(line, 200).to_string());
        }
    }
    fn flush_py(&mut self, frames: &mut Vec<(String, usize, Option<String>)>, exc: &str) {
        if frames.is_empty() { return; }
        let idx = frames.iter().rposition(|(p, _, _)| self.resolves_in_cwd(p)).unwrap_or(frames.len() - 1);
        self.notes_collapsed += frames.len().saturating_sub(1);
        let (path, line, func) = frames[idx].clone();
        frames.clear();
        let msg = func.filter(|f| !f.is_empty()).map_or_else(|| exc.to_string(), |f| format!("{exc} (in {f})"));
        self.push_error(&path, line, None, msg);
    }
    fn load_safe_lines<'c>(&self, raw: &str, cache: &'c mut FastHashMap<PathBuf, Option<Vec<String>>>) -> Option<&'c [String]> {
        let root = self.canon_cwd.as_deref()?;
        let cand = self.candidate(raw);
        if is_sensitive_path_with_ws(&cand, Some(root), false) { return None; }
        let canon = fs::canonicalize(&cand).ok()?;
        if !canon.starts_with(root) || is_sensitive_path_with_ws(&canon, Some(root), false) { return None; }
        cache.entry(canon.clone()).or_insert_with(|| {
            let meta = fs::metadata(&canon).ok()?;
            if !meta.is_file() || meta.len() > MAX_SRC_BYTES { return None; }
            Some(fs::read_to_string(&canon).ok()?.lines().map(str::to_string).collect())
        }).as_deref()
    }
}

pub fn try_compress_compiler_and_tests(
    raw: &str, cwd: &Path, max_errors: usize, context_lines: usize, hashes: bool, max_bytes: usize,
) -> Option<String> {
    let (max_errors, context_lines) = (max_errors.clamp(1, 60), context_lines.clamp(0, 4));
    let mut st = DiagState::new(cwd);
    let (mut pending_rust, mut last_py_e) = (None::<String>, None::<String>);
    let mut pending_cmake: Option<(String, usize, String)> = None;
    let mut pending_panic: Option<(String, usize, Option<usize>, String)> = None;
    let (mut py_frames, mut cargo_failed) = (Vec::new(), Vec::<String>::new());
    let (mut go_test, mut in_ctest) = (None::<(String, bool)>, false);

    for raw_line in raw.lines() {
        let line_cow = strip_ansi_and_cr(raw_line);
        let (line, trimmed) = (line_cow.as_ref(), line_cow.trim());
        if trimmed.is_empty() { in_ctest = false; continue; }
        if matches!(trimmed.as_bytes().first(), Some(b'{' | b'"')) || trimmed.starts_with("[{") { continue; }
        if let Some((p, ln, col, thr)) = pending_panic.take() {
            let msg = if thr.is_empty() { format!("panicked: {trimmed}") } else { format!("test {thr} panicked: {trimmed}") };
            st.push_error(&p, ln, col, msg); continue;
        }
        if let Some((p, ln, pfx)) = pending_cmake.take() { st.push_error(&p, ln, None, format!("{pfx}{trimmed}")); continue; }
        if in_ctest {
            if let Some(entry) = parse_ctest_entry(trimmed) { st.push_error("ctest", 0, None, entry); continue; }
            in_ctest = false;
        }
        if let Some(frame) = parse_python_frame(trimmed) { py_frames.push(frame); pending_rust = None; continue; }
        if !py_frames.is_empty() && handle_py_cont(&mut st, &mut py_frames, line, trimmed) { continue; }

        if let Some((p, ln, col)) = trimmed.strip_prefix("--> ").and_then(parse_path_line_col) {
            if let Some(msg) = pending_rust.take() { st.push_error(&p, ln, col, msg); }
        } else if trimmed.starts_with("error[") && trimmed.contains("]: ") {
            pending_rust = Some(trimmed.to_string());
        } else if let Some(msg) = trimmed.strip_prefix("error: ").map(str::trim).filter(|s| !s.is_empty()) {
            pending_rust = Some(msg.to_string());
        } else if is_note_line(trimmed) {
            st.notes_collapsed += 1; pending_rust = None;
        } else if trimmed.starts_with("warning:") || trimmed.starts_with("warning[") {
            pending_rust = None;
        } else if let Some(cm) = parse_cmake_error(trimmed) {
            pending_cmake = Some(cm);
        } else if let Some((p, ln, col, thr, inline_msg)) = parse_rust_panic(trimmed) {
            if let Some(m) = inline_msg {
                let msg = if thr.is_empty() { format!("panicked: {m}") } else { format!("test {thr} panicked: {m}") };
                st.push_error(&p, ln, col, msg);
            } else { pending_panic = Some((p, ln, col, thr)); }
        } else if let Some(name) = trimmed.strip_prefix("test ").and_then(|s| s.strip_suffix(" ... FAILED")).filter(|s| !s.is_empty() && !s.contains(' ')) {
            if !cargo_failed.iter().any(|n| n == name) { cargo_failed.push(name.to_string()); }
        } else if is_summary_line(trimmed) {
            st.push_summary(trimmed);
        } else if trimmed == "The following tests FAILED:" {
            in_ctest = true;
        } else if let Some(name) = trimmed.strip_prefix("--- FAIL: ").and_then(|s| s.split_whitespace().next()).filter(|s| !s.is_empty()) {
            if let Some((prev, false)) = go_test.take() { st.push_error("go test", 0, None, format!("FAIL: {prev}")); }
            go_test = Some((name.to_string(), false));
        } else if let Some((p, msg)) = parse_pytest_failed(trimmed, last_py_e.as_deref()) {
            last_py_e = None; st.push_error(&p, 0, None, msg);
        } else if let Some(exc) = trimmed.strip_prefix("E   ").map(str::trim).filter(|s| !s.is_empty()) {
            if last_py_e.is_none() { last_py_e = Some(exc.to_string()); }
        } else if let Some((p, ln, msg)) = parse_pytest_loc(trimmed, last_py_e.as_deref()) {
            last_py_e = None; st.push_error(&p, ln, None, msg);
        } else if let Some((p, ln, col, is_note, msg)) = parse_colon_diag(trimmed) {
            pending_rust = None;
            if is_note { st.notes_collapsed += 1; } else { st.push_error(&p, ln, col, msg); }
        } else if let Some((p, ln, col, msg)) = parse_go_loc(trimmed) {
            let full = match &mut go_test { Some((n, h)) => { *h = true; format!("{n}: {msg}") } None => msg };
            st.push_error(&p, ln, col, full);
        } else if let Some((p, ln, msg)) = parse_linker_error(trimmed) {
            st.push_error(&p, ln, None, msg);
        }
    }

    if let Some((p, ln, col, thr)) = pending_panic.take() { st.push_error(&p, ln, col, format!("test {thr} panicked")); }
    if let Some((p, ln, pfx)) = pending_cmake.take() { st.push_error(&p, ln, None, pfx.trim_end_matches(": ").to_string()); }
    if !py_frames.is_empty() { st.flush_py(&mut py_frames, "python traceback"); }
    if let Some((prev, false)) = go_test.take() { st.push_error("go test", 0, None, format!("FAIL: {prev}")); }
    for name in cargo_failed {
        if !st.unique.iter().any(|e| e.msg.contains(&name)) { st.push_error("cargo test", 0, None, format!("test {name} FAILED")); }
    }
    (!st.unique.is_empty()).then(|| format_diag_output(&st, max_errors, context_lines, hashes, max_bytes))
}
fn handle_py_cont(st: &mut DiagState<'_>, frames: &mut Vec<(String, usize, Option<String>)>, line: &str, trimmed: &str) -> bool {
    let indented = line.starts_with(' ') || line.starts_with('\t');
    if trimmed.starts_with("Traceback (most recent call last):") { st.flush_py(frames, "python traceback"); return true; }
    if !indented && !trimmed.starts_with('^') && !trimmed.starts_with('~') {
        if let Some((p, ln, col, is_note, msg)) = parse_colon_diag(trimmed) {
            st.flush_py(frames, "python traceback");
            if is_note { st.notes_collapsed += 1; } else { st.push_error(&p, ln, col, msg); }
            return true;
        }
        if !trimmed.starts_with("During handling of the above") && !trimmed.starts_with("The above exception was the direct") {
            st.flush_py(frames, trimmed); return true;
        }
    } else if let Some(exc) = trimmed.strip_prefix("E   ") { st.flush_py(frames, exc.trim()); return true; }
    indented
}
fn is_note_line(t: &str) -> bool {
    ["note:", "= note:", "help:", "= help:", ">>> referenced by ", "Call Stack (most recent call first):"]
        .iter().any(|p| t.starts_with(p))
}
fn is_summary_line(t: &str) -> bool {
    t.starts_with("test result: FAILED") || t.contains("% tests passed,") || t.starts_with("FAIL\t")
        || (t.starts_with("===") && t.ends_with("===") && t.contains(" failed"))
}
fn format_diag_output(st: &DiagState<'_>, max_errors: usize, ctx: usize, hashes: bool, max_bytes: usize) -> String {
    let summary_reserve: usize = st.summary_lines.iter().map(|s| s.len() + 1).sum();
    let body_limit = max_bytes.saturating_sub(summary_reserve.min(max_bytes >> 2));
    let mut out = String::with_capacity(max_bytes.min(2048));
    out.push_str("Diagnostics: "); push_usize(&mut out, st.unique.len());
    out.push_str(" unique errors (from "); push_usize(&mut out, st.raw_errors);
    out.push_str(" raw, "); push_usize(&mut out, st.notes_collapsed); out.push_str(" notes collapsed)\n");
    let (mut cache, mut shown) = (FastHashMap::<PathBuf, Option<Vec<String>>>::default(), 0usize);
    for err in st.unique.iter().take(max_errors) {
        if shown > 0 && out.len().saturating_add(err.norm_path.len() + err.msg.len() + 32) > body_limit { break; }
        out.push_str(&err.norm_path);
        if err.line > 0 {
            out.push(':'); push_usize(&mut out, err.line);
            if let Some(c) = err.col { out.push(':'); push_usize(&mut out, c); }
        }
        out.push_str(": "); out.push_str(&err.msg);
        if err.dup_count > 0 { out.push_str(" (+"); push_usize(&mut out, err.dup_count); out.push_str(" similar)"); }
        out.push('\n');
        if err.line > 0 {
            if let Some(lines) = st.load_safe_lines(&err.raw_path, &mut cache) { append_context(&mut out, lines, err.line, ctx, hashes); }
        }
        shown += 1;
    }
    if st.unique.len() > shown && out.len().saturating_add(48) <= body_limit {
        out.push_str("... (+"); push_usize(&mut out, st.unique.len() - shown); out.push_str(" more unique errors omitted)\n");
    }
    for s in &st.summary_lines {
        if out.len().saturating_add(s.len() + 1) > max_bytes { break; }
        out.push_str(s); out.push('\n');
    }
    truncate_utf8_bytes(&mut out, max_bytes);
    out
}
fn append_context(out: &mut String, lines: &[String], err_line: usize, ctx: usize, hashes: bool) {
    if err_line == 0 || err_line > lines.len() { return; }
    let (start, end) = (err_line.saturating_sub(ctx).max(1), err_line.saturating_add(ctx).min(lines.len()));
    for ln in start..=end {
        let raw = lines[ln - 1].as_str();
        let text = if ln == 1 { raw.strip_prefix('\u{FEFF}').unwrap_or(raw) } else { raw };
        out.push_str(if ln == err_line { "> " } else { "  " }); push_usize(out, ln);
        if hashes {
            let h = line_hash3(text);
            out.extend([':', h[0] as char, h[1] as char, h[2] as char]); out.push_str("| ");
        } else { out.push_str(": "); }
        out.push_str(text); out.push('\n');
    }
}
fn normalize_diag_path(raw: &str, cwd: &Path, canon_cwd: Option<&Path>) -> String {
    let p = Path::new(raw);
    if p.is_absolute() {
        if let Some(root) = canon_cwd {
            if let Ok(rel) = fs::canonicalize(p).ok().as_deref().unwrap_or(p).strip_prefix(root) { return rel.to_string_lossy().replace('\\', "/"); }
        }
        if let Ok(rel) = p.strip_prefix(cwd) { return rel.to_string_lossy().replace('\\', "/"); }
    }
    let mut norm = raw.replace('\\', "/");
    while let Some(s) = norm.strip_prefix("./") { norm = s.to_string(); }
    norm
}
fn parse_colon_diag(trimmed: &str) -> Option<(String, usize, Option<usize>, bool, String)> {
    const MARKERS: &[(&str, bool, usize)] = &[
        (": fatal error:", false, 0), (": error:", false, 0), (" - error ", false, 0),
        ("): fatal error ", false, 1), ("): error ", false, 1), ("): note:", true, 1), (": note:", true, 0),
    ];
    let (pos, pat_len, is_note, keep) = MARKERS.iter()
        .filter_map(|&(pat, note, keep)| trimmed.find(pat).map(|pos| (pos, pat.len(), note, keep)))
        .min_by_key(|x| x.0)?;
    let (path, line, col) = parse_path_line_col(&trimmed[..pos + keep])?;
    Some((path, line, col, is_note, trimmed[pos + pat_len..].trim().to_string()))
}
fn is_valid_diag_path(path: &str) -> bool {
    !path.is_empty() && !path.contains("://") && !path.contains(['"', '{', '}'])
        && (path.contains(['/', '\\', '.']) || (!path.contains(' ') && !path.bytes().all(|b| b.is_ascii_digit() || b == b'-')))
}
fn parse_path_line_col(loc: &str) -> Option<(String, usize, Option<usize>)> {
    let loc = loc.trim();
    if let Some((path, coords)) = loc.strip_suffix(')').and_then(|s| s.rsplit_once('(')) {
        let path = path.trim();
        if is_valid_diag_path(path) {
            if let Some((l_s, c_s)) = coords.split_once(',') { return Some((path.to_string(), parse_pos_usize(l_s)?, Some(parse_pos_usize(c_s)?))); }
            if let Some(ln) = parse_pos_usize(coords) { return Some((path.to_string(), ln, None)); }
        }
    }
    let (left, last) = loc.rsplit_once(':')?;
    let last_num = parse_pos_usize(last)?;
    if let Some((path, mid)) = left.rsplit_once(':') {
        if let Some(ln) = parse_pos_usize(mid) {
            let path = path.trim();
            if is_valid_diag_path(path) { return Some((path.to_string(), ln, Some(last_num))); }
        }
    }
    let path = left.trim();
    is_valid_diag_path(path).then(|| (path.to_string(), last_num, None))
}
fn parse_pos_usize(s: &str) -> Option<usize> {
    let s = s.trim();
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<usize>().ok()).flatten().filter(|&v| v > 0)
}
fn parse_python_frame(trimmed: &str) -> Option<(String, usize, Option<String>)> {
    let rest = trimmed.strip_prefix("File \"")?;
    let quote = rest.find('"')?;
    let after = rest[quote + 1..].strip_prefix(", line ")?;
    let digits = after.bytes().take_while(u8::is_ascii_digit).count();
    let line = parse_pos_usize(&after[..digits])?;
    let func = after[digits..].strip_prefix(", in ").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    Some((rest[..quote].to_string(), line, func))
}
fn parse_cmake_error(trimmed: &str) -> Option<(String, usize, String)> {
    let rest = trimmed.strip_prefix("CMake Error at ")?.strip_suffix(':')?;
    let (loc, cmd) = rest.rsplit_once(" (").map_or((rest, ""), |(l, c)| (l, c.strip_suffix(')').unwrap_or(c)));
    let (path, ln, _) = parse_path_line_col(loc)?;
    Some((path, ln, if cmd.is_empty() { "CMake Error: ".to_string() } else { format!("CMake Error ({cmd}): ") }))
}
fn parse_linker_error(trimmed: &str) -> Option<(String, usize, String)> {
    for pfx in ["ld.lld: error: ", "lld-link: error: ", "ld: error: ", "ld: "] {
        if let Some(msg) = trimmed.strip_prefix(pfx) {
            if pfx != "ld: " || msg.contains("duplicate symbol") || msg.contains("undefined") { return Some(("ld".to_string(), 0, msg.trim().to_string())); }
        }
    }
    for kw in ["undefined reference to ", "duplicate symbol:", "multiple definition of "] {
        if let Some(pos) = trimmed.find(kw) {
            if let Some((p, ln, _)) = trimmed[..pos].trim_end().strip_suffix(':').and_then(parse_path_line_col) { return Some((p, ln, trimmed[pos..].trim().to_string())); }
            return Some(("ld".to_string(), 0, trimmed[pos..].trim().to_string()));
        }
    }
    None
}
fn parse_rust_panic(trimmed: &str) -> Option<(String, usize, Option<usize>, String, Option<String>)> {
    let pos = trimmed.find("panicked at ")?;
    let thr = trimmed[..pos].trim().strip_prefix("thread '").and_then(|s| s.strip_suffix('\'')).unwrap_or("").to_string();
    let rest = trimmed[pos + "panicked at ".len()..].trim();
    if let Some(loc) = rest.strip_suffix(':') {
        let (p, ln, col) = parse_path_line_col(loc)?; return Some((p, ln, col, thr, None));
    }
    let (msg_part, loc) = rest.rsplit_once("', ")?;
    let (p, ln, col) = parse_path_line_col(loc)?;
    Some((p, ln, col, thr, Some(msg_part.strip_prefix('\'').unwrap_or(msg_part).to_string())))
}
fn parse_pytest_failed(trimmed: &str, pending_e: Option<&str>) -> Option<(String, String)> {
    let rest = trimmed.strip_prefix("FAILED ")?;
    let (target, reason) = rest.split_once(" - ").map_or((rest.trim(), pending_e), |(t, r)| (t.trim(), Some(r.trim())));
    let (path, test_name) = target.split_once("::")?;
    let msg = reason.filter(|r| !r.is_empty()).map_or_else(|| format!("FAILED {test_name}"), |r| format!("FAILED {test_name} - {r}"));
    Some((path.to_string(), msg))
}
fn parse_pytest_loc(trimmed: &str, pending_e: Option<&str>) -> Option<(String, usize, String)> {
    let (loc, kind) = trimmed.split_once(": ")?;
    if !loc.contains(".py:") || kind.starts_with("in ") || !kind.as_bytes().first().is_some_and(u8::is_ascii_uppercase) { return None; }
    let (p, ln, _) = parse_path_line_col(loc)?;
    Some((p, ln, pending_e.map_or_else(|| kind.to_string(), str::to_string)))
}
fn parse_ctest_entry(trimmed: &str) -> Option<String> {
    let (num, rest) = trimmed.split_once(" - ")?;
    parse_pos_usize(num)?;
    (!rest.trim().is_empty()).then(|| format!("{} - {}", num.trim(), rest.trim()))
}
fn parse_go_loc(trimmed: &str) -> Option<(String, usize, Option<usize>, String)> {
    let (loc, msg) = trimmed.split_once(": ")?;
    if !loc.contains(".go:") || msg.starts_with("warning:") { return None; }
    let (p, ln, col) = parse_path_line_col(loc)?;
    Some((p, ln, col, msg.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msvc_cmake_and_linker_dedup() {
        let log = "src\\app.cpp(42): error C2065: 'x': undeclared identifier\n\
                   src\\inc.cpp(10,5): fatal error C1083: Cannot open include file\n\
                   CMake Error at CMakeLists.txt:15 (find_package):\n  Could not find package Foo\n\
                   ld.lld: error: undefined symbol: Foo::bar()\n>>> referenced by a.o\n\
                   ld.lld: error: undefined symbol: Foo::bar()\n\
                   foo.o:(.text+0x8): undefined reference to `baz'\nduplicate symbol: _dup\n";
        let out = try_compress_compiler_and_tests(log, Path::new("."), 20, 0, false, 8192).unwrap();
        assert!(out.contains("src/app.cpp:42: C2065:") && out.contains("src/inc.cpp:10:5: C1083:"));
        assert!(out.contains("CMakeLists.txt:15: CMake Error (find_package): Could not find package Foo"));
        assert!(out.contains("ld: undefined symbol: Foo::bar() (+1 similar)"));
        assert!(out.contains("ld: undefined reference to `baz'") && out.contains("ld: duplicate symbol: _dup"));
    }

    #[test]
    fn test_runners_cargo_pytest_ctest_and_go() {
        let cargo = "test math::sub ... FAILED\nthread 'math::sub' panicked at src/math.rs:27:9:\nassertion failed\ntest result: FAILED. 3 passed; 1 failed; 0 ignored\n";
        let out = try_compress_compiler_and_tests(cargo, Path::new("."), 15, 0, false, 8192).unwrap();
        assert!(out.contains("src/math.rs:27:9: test math::sub panicked: assertion failed") && out.contains("test result: FAILED. 3 passed; 1 failed"));
        let pytest = "E   AssertionError: assert 1 == 2\nFAILED tests/test_calc.py::test_div - AssertionError: assert 1 == 2\n=== 1 failed, 5 passed in 0.12s ===\n";
        let out = try_compress_compiler_and_tests(pytest, Path::new("."), 15, 0, false, 8192).unwrap();
        assert!(out.contains("tests/test_calc.py: FAILED test_div - AssertionError: assert 1 == 2") && out.contains("1 failed, 5 passed"));
        let ctest = "50% tests passed, 1 tests failed out of 2\nThe following tests FAILED:\n\t  2 - OrderTableTest (Failed)\n";
        let out = try_compress_compiler_and_tests(ctest, Path::new("."), 15, 0, false, 8192).unwrap();
        assert!(out.contains("ctest: 2 - OrderTableTest (Failed)") && out.contains("50% tests passed"));
        let go = "--- FAIL: TestBook (0.01s)\n    book_test.go:18: got 3, want 4\nFAIL\tpkg/book\t0.02s\n";
        let out = try_compress_compiler_and_tests(go, Path::new("."), 15, 0, false, 8192).unwrap();
        assert!(out.contains("book_test.go:18: TestBook: got 3, want 4") && out.contains("FAIL\tpkg/book"));
    }
}
