//! Universal zero-dependency CLI diagnostic compressor (`ctx diag`).
//! Dispatches structured compiler/linker/test diagnostics -> large JSON/NDJSON ->
//! template-deduplicated generic logs, with ANSI/CR cleanup and exit-0 summary collapse.

pub mod compiler;
pub mod json_compact;
pub mod logs;

use crate::base::security::is_sensitive_path_with_ws;
use crate::base::simd::push_usize;
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

pub const MAX_LOG_BYTES: u64 = 8 << 20;
pub const DEFAULT_MAX_BYTES: usize = 8192;

pub fn run_diag_cli(args: &[String]) -> i32 {
    let (opt_args, cmd_slice) = match args.iter().position(|a| a == "--") {
        Some(pos) => (&args[..pos], Some(&args[pos + 1..])),
        None => (args, None),
    };
    let (mut file_path, mut hashes, mut max_errors, mut ctx, mut max_bytes, mut i) =
        (None::<String>, false, 15usize, 2usize, DEFAULT_MAX_BYTES, 0usize);

    while i < opt_args.len() {
        match opt_args[i].as_str() {
            "-h" | "--help" => {
                eprintln!(
                    "Usage: ctx diag [--file <path>] [--hashes] [--max-errors 15] [--context 2] [--max-bytes 8192]\n       \
                     ctx diag [--hashes] [--max-errors 15] [--context 2] [--max-bytes 8192] -- <cmd> [args...]"
                );
                return 0;
            }
            "--hashes" => hashes = true,
            "--file" | "-f" => {
                i += 1;
                let Some(p) = opt_args.get(i) else { eprintln!("ctx diag: missing value for --file"); return 2; };
                file_path = Some(p.clone());
            }
            "--max-errors" | "--context" | "--max-bytes" => {
                let flag = opt_args[i].as_str();
                i += 1;
                let Some(v) = opt_args.get(i).and_then(|s| s.parse::<usize>().ok()) else {
                    eprintln!("ctx diag: {flag} expects a non-negative integer"); return 2;
                };
                match flag {
                    "--max-errors" => max_errors = v.clamp(1, 60),
                    "--context" => ctx = v.clamp(0, 4),
                    _ => max_bytes = v.clamp(512, 32768),
                }
            }
            other if !other.starts_with('-') && file_path.is_none() => file_path = Some(other.to_string()),
            other => { eprintln!("ctx diag: unknown option `{other}`"); return 2; }
        }
        i += 1;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Some(cmd_parts) = cmd_slice {
        if file_path.is_some() { eprintln!("ctx diag: cannot combine --file with `-- <cmd>`"); return 2; }
        if cmd_parts.is_empty() || cmd_parts[0].is_empty() {
            eprintln!("ctx diag: missing command after `--`"); return 2;
        }
        let (code, out) = run_diag_command(cmd_parts, &cwd, max_errors, ctx, hashes, max_bytes);
        print_with_nl(&out);
        return code;
    }

    let mut buf = Vec::new();
    let read_res = match file_path.as_deref() {
        Some(p) if is_sensitive_path_with_ws(Path::new(p), Some(&cwd), false) => Err(format!("REFUSED sensitive log path `{p}`")),
        Some(p) => fs::File::open(p)
            .map_err(|e| format!("cannot open `{p}`: {e}"))
            .and_then(|f| f.take(MAX_LOG_BYTES).read_to_end(&mut buf).map_err(|e| format!("read `{p}`: {e}"))),
        None => io::stdin().take(MAX_LOG_BYTES).read_to_end(&mut buf).map_err(|e| format!("read stdin: {e}")),
    };
    if let Err(e) = read_res { eprintln!("ctx diag: {e}"); return 1; }
    let out = compress_diagnostics_capped(&String::from_utf8_lossy(&buf), &cwd, max_errors, ctx, hashes, max_bytes);
    print_with_nl(&out);
    0
}

fn print_with_nl(out: &str) {
    print!("{out}");
    if !out.is_empty() && !out.ends_with('\n') { println!(); }
}

#[allow(dead_code)]
pub fn compress_diagnostics(
    raw: &str, cwd: &Path, max_errors: usize, context_lines: usize, hashes: bool,
) -> String {
    compress_diagnostics_capped(raw, cwd, max_errors, context_lines, hashes, DEFAULT_MAX_BYTES)
}

pub fn compress_diagnostics_capped(
    raw: &str, cwd: &Path, max_errors: usize, context_lines: usize, hashes: bool, max_bytes: usize,
) -> String {
    let cap = max_bytes.max(256);
    if let Some(out) = compiler::try_compress_compiler_and_tests(raw, cwd, max_errors, context_lines, hashes, cap) {
        return out;
    }
    if json_compact::looks_like_large_json_or_ndjson(raw) {
        return json_compact::compress_json_output(raw, cap);
    }
    logs::compress_generic_logs(raw, cap)
}

fn spawn_cmd(program: &str, args: &[String]) -> Command {
    let mut cmd = crate::base::platform::hidden_command(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

fn drain_capped(mut reader: impl Read, shared: &Mutex<Vec<u8>>, cap: usize) {
    let mut chunk = [0u8; 8192];
    while let Ok(n) = reader.read(&mut chunk) {
        if n == 0 { break; }
        if let Ok(mut buf) = shared.lock() {
            let avail = cap.saturating_sub(buf.len());
            if avail > 0 { buf.extend_from_slice(&chunk[..n.min(avail)]); }
        }
    }
}

fn is_ok_test_summary(t: &str) -> bool {
    t.starts_with("test result: ok") || t.contains(" passed")
        || (t.starts_with("Ran ") && t.contains(" test"))
        || t == "PASS" || t.starts_with("PASS ") || t.starts_with("PASS:")
        || t.starts_with("--- PASS:") || t.starts_with("ok  \t")
}

fn format_ok_summary(combined: &str, max_bytes: usize) -> String {
    let (mut total_lines, mut summaries, mut tail) = (0usize, Vec::<String>::new(), VecDeque::with_capacity(6));
    for raw_line in combined.lines() {
        total_lines += 1;
        let clean = logs::strip_ansi_and_cr(raw_line);
        let trimmed_end = logs::clip_str(clean.trim_end(), 512);
        let trimmed = trimmed_end.trim();
        if trimmed.is_empty() { continue; }
        if is_ok_test_summary(trimmed) && summaries.len() < 12 && !summaries.iter().any(|s| s == trimmed_end) {
            summaries.push(trimmed_end.to_string());
        }
        if tail.len() == 5 { tail.pop_front(); }
        tail.push_back(trimmed_end.to_string());
    }
    let mut out = String::with_capacity(256);
    out.push_str("[ctx diag: OK (exit 0), "); push_usize(&mut out, total_lines); out.push_str(" lines]\n");
    for s in summaries {
        if !tail.iter().any(|t| t == &s) && out.len().saturating_add(s.len() + 1) <= max_bytes {
            out.push_str(&s); out.push('\n');
        }
    }
    for line in tail {
        if out.len().saturating_add(line.len() + 1) > max_bytes { break; }
        out.push_str(&line); out.push('\n');
    }
    logs::truncate_utf8_bytes(&mut out, max_bytes);
    out
}

fn run_diag_command(
    cmd_parts: &[String], cwd: &Path, max_errors: usize, ctx: usize, hashes: bool, max_bytes: usize,
) -> (i32, String) {
    let mut child = match spawn_cmd(&cmd_parts[0], &cmd_parts[1..]).spawn() {
        Ok(c) => c,
        Err(e) => { eprintln!("ctx diag: failed to spawn `{}`: {e}", cmd_parts[0]); return (1, String::new()); }
    };
    let (stdout, stderr, shared) = (child.stdout.take(), child.stderr.take(), Mutex::new(Vec::<u8>::new()));
    std::thread::scope(|scope| {
        let err_h = stderr.map(|r| scope.spawn(|| drain_capped(r, &shared, MAX_LOG_BYTES as usize)));
        if let Some(r) = stdout { drain_capped(r, &shared, MAX_LOG_BYTES as usize); }
        if let Some(h) = err_h { let _ = h.join(); }
    });
    let code = match child.wait() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => { eprintln!("ctx diag: wait failed: {e}"); return (1, String::new()); }
    };
    let buf = shared.into_inner().unwrap_or_default();
    let combined = String::from_utf8_lossy(&buf);
    if code == 0 { (0, format_ok_summary(&combined, max_bytes)) }
    else { (code, compress_diagnostics_capped(&combined, cwd, max_errors, ctx, hashes, max_bytes)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::simd::line_hash3;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let tok = crate::base::security::generate_csprng_token().unwrap();
            let dir = std::env::temp_dir().join(format!("ctx-diag-test-{tok}"));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TempDir { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    fn sv(xs: &[&str]) -> Vec<String> { xs.iter().map(|s| (*s).to_string()).collect() }

    #[test]
    fn clang_cascade_dedup_hashes_and_sensitive_skip() {
        let tmp = TempDir::new();
        fs::create_dir_all(tmp.0.join("src")).unwrap();
        fs::write(tmp.0.join("src/vec.hpp"), "int a = 1;\nint b = 2;\nint c = bad();\nint d = 4;\n").unwrap();
        fs::write(tmp.0.join(".env"), "TOP_SECRET=do_not_leak\n").unwrap();
        let log = "src/vec.hpp:3:9: error: undeclared 'bad'\nsrc/vec.hpp:10:5: note: in instantiation\n\
                   src/vec.hpp:3:9: error: undeclared 'bad'\nsrc/vec.hpp:12:5: note: requested here\n\
                   \x1b[1;31m.env:1:1: error:\x1b[0m parse failed\n";
        let out = compress_diagnostics(log, &tmp.0, 15, 1, true);
        assert!(out.contains("Diagnostics: 2 unique errors (from 3 raw, 2 notes collapsed)"));
        assert!(out.contains("src/vec.hpp:3:9: undeclared 'bad' (+1 similar)"));
        let h3 = line_hash3("int c = bad();");
        assert!(out.contains(&format!("> 3:{}| int c = bad();", std::str::from_utf8(&h3).unwrap())));
        assert!(out.contains("  2:") && out.contains("  4:") && !out.contains("TOP_SECRET"));
    }

    #[test]
    fn rust_and_python_tracebacks_extract_context() {
        let tmp = TempDir::new();
        fs::create_dir_all(tmp.0.join("src")).unwrap();
        fs::write(tmp.0.join("src/lib.rs"), "fn demo() {\n    let x: u32 = \"no\";\n}\n").unwrap();
        fs::write(tmp.0.join("src/app.py"), "def run():\n    x = 1\n    raise ValueError('boom')\n").unwrap();

        let rust_log = "error[E0308]: mismatched types\n --> src/lib.rs:2:20\n  |\n  = note: expected u32\nerror: could not compile `demo`\n";
        let rust_out = compress_diagnostics(rust_log, &tmp.0, 15, 1, false);
        assert!(rust_out.contains("Diagnostics: 1 unique errors (from 1 raw, 1 notes collapsed)"));
        assert!(rust_out.contains("src/lib.rs:2:20: error[E0308]: mismatched types") && rust_out.contains("> 2:     let x: u32 = \"no\";"));

        let py_log = "Traceback (most recent call last):\n  File \"/external/runner.py\", line 99, in dispatch\n    run()\n  File \"src/app.py\", line 3, in run\n    raise ValueError('boom')\nValueError: boom\n";
        let py_out = compress_diagnostics(py_log, &tmp.0, 15, 1, true);
        assert!(py_out.contains("Diagnostics: 1 unique errors (from 1 raw, 1 notes collapsed)"));
        assert!(py_out.contains("src/app.py:3: ValueError: boom (in run)"));
        let h3 = line_hash3("    raise ValueError('boom')");
        assert!(py_out.contains(&format!("> 3:{}|     raise ValueError('boom')", std::str::from_utf8(&h3).unwrap())));
    }

    #[test]
    fn fallback_dedups_generic_logs_and_rejects_bad_cli() {
        let mut raw = String::new();
        for i in 1..=20 { raw.push_str(&format!("plain line {i}\n\n")); }
        let out = compress_diagnostics(&raw, Path::new("."), 15, 2, false);
        assert!(out.starts_with("[ctx diag: logs, 20 lines -> 1 unique templates]\n"));
        assert!(out.contains("(\u{00d7}20)") && out.contains("plain line 16\n") && out.contains("plain line 20\n"));
        assert_eq!(run_diag_cli(&sv(&["--file", "a.log", "--", "true"])), 2);
        assert_eq!(run_diag_cli(&sv(&["--"])), 2);
    }

    #[cfg(unix)]
    #[test]
    fn diag_cli_command_wrapper_handles_ok_and_nonzero_exit() {
        let tmp = TempDir::new();
        fs::create_dir_all(tmp.0.join("src")).unwrap();
        fs::write(tmp.0.join("src/fail.cpp"), "int ok = 1;\nint bad = missing();\nint tail = 3;\n").unwrap();

        let ok_cmd = sv(&["sh", "-c", "printf 'test result: ok. 4 passed\\nl1\\n\\033[32ml2\\033[0m\\n\\nl3\\nl4\\nl5\\nl6\\n\\033[1ml7\\033[0m\\n'"]);
        let (ok_code, ok_out) = run_diag_command(&ok_cmd, &tmp.0, 15, 2, false, DEFAULT_MAX_BYTES);
        assert_eq!(ok_code, 0);
        assert!(ok_out.starts_with("[ctx diag: OK (exit 0), 9 lines]\n") && ok_out.contains("test result: ok. 4 passed\n"));
        assert!(!ok_out.contains("l2\n") && ok_out.contains("l3\n") && ok_out.contains("l7\n") && !ok_out.contains('\x1b'));
        assert_eq!(run_diag_cli(&sv(&["--", "true"])), 0);

        let fail_cmd = sv(&["sh", "-c", "printf 'src/fail.cpp:2:11: error: undeclared missing\\nsrc/fail.cpp:2:11: note: detail\\n' >&2; exit 7"]);
        let (fail_code, fail_out) = run_diag_command(&fail_cmd, &tmp.0, 15, 1, true, DEFAULT_MAX_BYTES);
        assert_eq!(fail_code, 7);
        assert!(fail_out.contains("Diagnostics: 1 unique errors (from 1 raw, 1 notes collapsed)"));
        let h3 = line_hash3("int bad = missing();");
        assert!(fail_out.contains(&format!("> 2:{}| int bad = missing();", std::str::from_utf8(&h3).unwrap())));
        assert_eq!(run_diag_cli(&sv(&["--hashes", "--max-bytes", "4096", "--", "sh", "-c", "exit 7"])), 7);
    }
}
