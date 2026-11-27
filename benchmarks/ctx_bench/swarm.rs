//! Realistic multi-agent swarm replay benchmark (`ctx-bench swarm`):
//! Copies a bounded source slice of `--repo` into a temporary git repository with `K` real
//! linked `git worktree`s (never mutating `--repo`), spawns one isolated `ctx daemon`, and
//! replays `10, 50, 100` concurrent workers exercising:
//!   1. Scout Shared Context Pack (`pack:swarm-scope`) + linked memos
//!   2. `hook agy` `SessionStart` with `pack:swarm-scope`
//!   3. Concurrent 4-query batch `search` (coalescer + 2s micro-cache + fair-share)
//!   4. `hook agy` `PreToolUse` `read_file` on `>=350L` code files (Large-Read Gate Strike 1)
//!   5. `symbols` across linked worktrees (`ParsedBody` cross-worktree RAM dedup)
//!   6. `memo pack_get` (repeat dedup) + `memo list` cross-worktree visibility
//!   7. `impact` + `git` (`status` / `diff --stat`)
//!   8. Controlled `edit` + cross-worktree `ChangeFeed` & `[STALE]` memo verification

use ctx::base::json::{self, Json};
use ctx::base::simd::{line_hash3, scan_source_bytes};
use ctx::parser::{extract_symbols, SymbolKind};
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Barrier;
use std::thread;
use std::time::{Duration, Instant};

const MAX_REPO_FILES: usize = 200;
const MAX_SINGLE_FILE_BYTES: u64 = 256 * 1024;
const LARGE_READ_THRESHOLD_LINES: usize = 350;
const MIN_LARGE_NON_NS_SYMS: usize = 4;
const PACK_NAME: &str = "swarm-scope";
const MEMO_HOT_TOPIC: &str = "swarm:hot-scope";
const MEMO_EDIT_TOPIC: &str = "swarm:edit-target";
const EDIT_TARGET_REL: &str = "bench_synthetic/bench_target_edit.rs";
const EDIT_INITIAL_LINE3: &str = "    const BENCH_REV: u64 = 10;";

struct SwarmGuard {
    root: PathBuf,
    daemon: Option<Child>,
    port: u16,
    token: String,
}

impl Drop for SwarmGuard {
    fn drop(&mut self) {
        if self.port != 0 && !self.token.is_empty() {
            let _ = send_swarm_rpc(
                self.port,
                &self.token,
                &Json::obj(vec![("op", Json::Str("shutdown".to_string()))]),
            );
        }
        if let Some(ref mut child) = self.daemon {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone)]
struct CorpusFile {
    rel_path: String,
    size_bytes: usize,
    line_count: usize,
    non_ns_symbols: usize,
    primary_symbol: String,
    search_token: String,
}

struct SwarmWorkspace {
    main_repo: PathBuf,
    worktrees: Vec<PathBuf>,
    hot_files: Vec<CorpusFile>,
    unique_files: Vec<CorpusFile>,
    large_files: Vec<CorpusFile>,
    corpus_count: usize,
    large_count: usize,
}

#[derive(Default)]
struct WorkerStats {
    lats_us: Vec<u64>,
    errors: usize,
    search_busy: usize,
    large_read_redirects: usize,
    pack_dedup_hits: usize,
    cross_worktree_memo_ok: usize,
    change_feed_visible: bool,
    stale_detected: bool,
    naive_bytes: u64,
    v252_est_bytes: u64,
    multiagent_bytes: u64,
}

fn send_swarm_rpc(port: u16, token: &str, req: &Json) -> Result<Json, String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    for attempt in 0..6 {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            Ok(mut stream) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let mut fields = match req {
                    Json::Obj(items) => items.clone(),
                    _ => Vec::new(),
                };
                fields.push((Cow::Borrowed("token"), Json::Str(token.to_string())));
                let mut line = Json::Obj(fields).to_json_string();
                line.push('\n');
                stream
                    .write_all(line.as_bytes())
                    .map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
                let mut reader = BufReader::new(stream);
                let mut resp = String::new();
                reader.read_line(&mut resp).map_err(|e| e.to_string())?;
                return json::parse(resp.trim());
            }
            Err(e) => {
                if attempt == 5 {
                    return Err(e.to_string());
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    Err("swarm bench RPC exhausted retries".to_string())
}

fn resolve_ctx_binary(explicit: Option<&str>) -> Result<PathBuf, String> {
    if let Some(raw) = explicit {
        let p = PathBuf::from(raw);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!("--ctx-bin does not exist: {}", p.display()));
    }
    let exe_name = if cfg!(windows) { "ctx.exe" } else { "ctx" };
    if let Ok(cur) = std::env::current_exe() {
        if let Some(dir) = cur.parent() {
            let sibling = dir.join(exe_name);
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }
    Ok(PathBuf::from(exe_name))
}

fn is_code_ext(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    let mut buf = [0u8; 8];
    if ext.is_empty() || ext.len() > buf.len() || !ext.is_ascii() {
        return false;
    }
    for (i, b) in ext.bytes().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    let low = std::str::from_utf8(&buf[..ext.len()]).unwrap_or("");
    matches!(
        low,
        "rs" | "c"
            | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hh"
            | "hpp"
            | "hxx"
            | "py"
            | "go"
            | "ts"
            | "tsx"
            | "js"
            | "jsx"
            | "java"
            | "cs"
            | "kt"
            | "swift"
            | "zig"
    )
}

fn is_safe_rel_code_path(rel: &str) -> bool {
    if rel.is_empty() || rel.len() > 240 || rel.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    let lower = rel.to_ascii_lowercase();
    for bad in [
        "secret",
        "credential",
        ".env",
        "id_rsa",
        "id_ed25519",
        ".pem",
        ".key",
        "token",
        "password",
    ] {
        if lower.contains(bad) {
            return false;
        }
    }
    let p = Path::new(rel);
    if !is_code_ext(p) {
        return false;
    }
    let mut has_component = false;
    for comp in p.components() {
        match comp {
            Component::Normal(seg) => {
                let Some(s) = seg.to_str() else {
                    return false;
                };
                if s.is_empty() || s.starts_with('.') {
                    return false;
                }
                if matches!(
                    s,
                    "target" | "build" | "node_modules" | "dist" | "vendor" | "__pycache__"
                ) {
                    return false;
                }
                has_component = true;
            }
            _ => return false,
        }
    }
    has_component
}

fn collect_repo_candidates(repo: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(output) = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["ls-files", "-z"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        if output.status.success() {
            for raw in output.stdout.split(|&b| b == 0) {
                if raw.is_empty() {
                    continue;
                }
                if let Ok(rel) = std::str::from_utf8(raw) {
                    if is_safe_rel_code_path(rel) {
                        out.push(rel.to_string());
                    }
                }
            }
        }
    }
    if out.is_empty() {
        walk_repo_fallback(repo, repo, &mut out, MAX_REPO_FILES * 4);
    }
    out.sort();
    out.dedup();
    out
}

fn walk_repo_fallback(root: &Path, dir: &Path, out: &mut Vec<String>, cap: usize) {
    if out.len() >= cap {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|x| x.path())).collect();
    entries.sort();
    for path in entries {
        if out.len() >= cap {
            break;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !name.starts_with('.')
                && !matches!(
                    name,
                    "target" | "build" | "node_modules" | "dist" | "vendor" | "__pycache__"
                )
            {
                walk_repo_fallback(root, &path, out, cap);
            }
        } else if meta.is_file() && meta.len() <= MAX_SINGLE_FILE_BYTES {
            if let Ok(rel) = path.strip_prefix(root) {
                if let Some(rel_str) = rel.to_str() {
                    let norm = rel_str.replace('\\', "/");
                    if is_safe_rel_code_path(&norm) {
                        out.push(norm);
                    }
                }
            }
        }
    }
}

fn bare_symbol_ident(name: &str) -> &str {
    let tail = name
        .rsplit("::")
        .next()
        .unwrap_or(name)
        .rsplit('.')
        .next()
        .unwrap_or(name)
        .trim();
    let end = tail
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))
        .unwrap_or(tail.len());
    &tail[..end]
}

fn is_usable_symbol_ident(ident: &str) -> bool {
    if ident.len() < 4 || ident.len() > 64 {
        return false;
    }
    let bytes = ident.as_bytes();
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return false;
    }
    if !bytes.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_') {
        return false;
    }
    !matches!(
        ident,
        "main" | "init" | "drop" | "clone" | "from" | "into" | "default" | "test" | "constexpr"
    )
}

fn analyze_code_file(rel_path: &str, raw_bytes: Vec<u8>) -> Option<CorpusFile> {
    let size_bytes = raw_bytes.len();
    if size_bytes == 0 || size_bytes as u64 > MAX_SINGLE_FILE_BYTES {
        return None;
    }
    let scanned = scan_source_bytes(raw_bytes).ok()?;
    let syms = extract_symbols(Path::new(rel_path), &scanned.text, &scanned.line_offsets);
    let mut non_ns_symbols = 0usize;
    let mut best_sym: Option<(String, String)> = None;
    for s in syms.iter() {
        if s.kind == SymbolKind::Namespace {
            continue;
        }
        non_ns_symbols += 1;
        if best_sym.is_none() {
            let ident = bare_symbol_ident(&s.name);
            if is_usable_symbol_ident(ident) && scanned.text.contains(ident) {
                best_sym = Some((s.name.to_string(), ident.to_string()));
            }
        }
    }
    let (primary_symbol, search_token) = best_sym?;
    Some(CorpusFile {
        rel_path: rel_path.to_string(),
        size_bytes,
        line_count: scanned.line_count as usize,
        non_ns_symbols,
        primary_symbol,
        search_token,
    })
}

fn synthesize_large_rs(idx: usize) -> String {
    let mut s = String::with_capacity(18 * 1024);
    s.push_str("// Synthetic large module for deterministic multi-agent benchmark replay.\n");
    s.push_str(&format!("pub struct LargeWorkerUnit_{idx} {{\n"));
    for f in 0..8usize {
        s.push_str(&format!("    pub field_{idx}_{f}: u64,\n"));
    }
    s.push_str("}\n\n");
    for fn_i in 0..10usize {
        s.push_str(&format!(
            "pub fn large_compute_{idx}_{fn_i}(seed: u64, lane: u64) -> u64 {{\n"
        ));
        s.push_str("    let mut acc = seed.wrapping_add(lane);\n");
        for step in 0..34usize {
            let mix = (idx * 37 + fn_i * 13 + step * 7) as u64;
            s.push_str(&format!(
                "    acc = acc.wrapping_mul(6364136223846793005u64).wrapping_add({mix}u64);\n"
            ));
        }
        s.push_str("    acc ^ (acc >> 17)\n}\n\n");
    }
    s
}

fn synthesize_unit_rs(idx: usize) -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("// Synthetic worker-unique module for benchmark replay.\n");
    s.push_str(&format!(
        "pub fn unique_worker_step_{idx}(input: u64) -> u64 {{\n"
    ));
    s.push_str(&format!(
        "    let base = input.wrapping_add({});\n",
        (idx + 1) * 17
    ));
    s.push_str(&format!(
        "    crate::large_helper_call_{idx}(base) ^ 0x{:04x}\n}}\n\n",
        idx * 257 + 19
    ));
    s.push_str(&format!(
        "pub fn large_helper_call_{idx}(v: u64) -> u64 {{\n    v.rotate_left(7)\n}}\n"
    ));
    s
}

fn edit_target_body(line3: &str) -> String {
    format!(
        "// Controlled benchmark edit target.\n\
         pub fn bench_target_alpha(x: u64) -> u64 {{\n\
         {line3}\n\
         \x20   x.wrapping_add(BENCH_REV)\n\
         }}\n\
         pub fn bench_target_beta(v: u64) -> u64 {{\n\
         \x20   v ^ 0x55aa\n\
         }}\n"
    )
}

fn run_git(repo: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("spawn git {:?}: {e}", args))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "git {:?} failed ({}): {}",
            args,
            out.status,
            stderr.trim()
        ));
    }
    Ok(())
}

fn prepare_swarm_workspace(
    root: &Path,
    src_repo: &Path,
    worktree_count: usize,
) -> Result<SwarmWorkspace, String> {
    let main_repo = root.join("main_repo");
    fs::create_dir_all(&main_repo).map_err(|e| format!("create main_repo: {e}"))?;

    let candidates = collect_repo_candidates(src_repo);
    let mut large_from_repo: Vec<(String, Vec<u8>, CorpusFile)> = Vec::new();
    let mut regular_from_repo: Vec<(String, Vec<u8>, CorpusFile)> = Vec::new();

    for rel in candidates {
        if large_from_repo.len() >= 32 && regular_from_repo.len() >= MAX_REPO_FILES {
            break;
        }
        let full = src_repo.join(&rel);
        let Ok(meta) = fs::symlink_metadata(&full) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_SINGLE_FILE_BYTES {
            continue;
        }
        let Ok(bytes) = fs::read(&full) else {
            continue;
        };
        let Some(info) = analyze_code_file(&rel, bytes.clone()) else {
            continue;
        };
        if info.line_count >= LARGE_READ_THRESHOLD_LINES
            && info.non_ns_symbols >= MIN_LARGE_NON_NS_SYMS
        {
            if large_from_repo.len() < 32 {
                large_from_repo.push((rel, bytes, info));
            }
        } else if regular_from_repo.len() < MAX_REPO_FILES {
            regular_from_repo.push((rel, bytes, info));
        }
    }

    let mut chosen: Vec<(String, Vec<u8>, CorpusFile)> = Vec::with_capacity(MAX_REPO_FILES);
    for item in large_from_repo {
        if chosen.len() < MAX_REPO_FILES {
            chosen.push(item);
        }
    }
    for item in regular_from_repo {
        if chosen.len() < MAX_REPO_FILES {
            chosen.push(item);
        }
    }

    let mut all_files: Vec<CorpusFile> = Vec::with_capacity(chosen.len() + 16);
    for (rel, bytes, info) in chosen {
        let dest = main_repo.join(&rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(&dest, &bytes).map_err(|e| format!("write {}: {e}", dest.display()))?;
        all_files.push(info);
    }

    let synth_dir = main_repo.join("bench_synthetic");
    fs::create_dir_all(&synth_dir).map_err(|e| format!("mkdir bench_synthetic: {e}"))?;

    let mut existing_large = all_files
        .iter()
        .filter(|f| {
            f.line_count >= LARGE_READ_THRESHOLD_LINES && f.non_ns_symbols >= MIN_LARGE_NON_NS_SYMS
        })
        .count();
    let mut synth_large_idx = 0usize;
    while existing_large < 4 {
        let rel = format!("bench_synthetic/large_mod_{synth_large_idx}.rs");
        let body = synthesize_large_rs(synth_large_idx);
        let bytes = body.into_bytes();
        fs::write(main_repo.join(&rel), &bytes).map_err(|e| format!("write {rel}: {e}"))?;
        if let Some(info) = analyze_code_file(&rel, bytes) {
            all_files.push(info);
            existing_large += 1;
        }
        synth_large_idx += 1;
    }

    let mut synth_unit_idx = 0usize;
    while all_files.len() < 18 {
        let rel = format!("bench_synthetic/unit_mod_{synth_unit_idx}.rs");
        let body = synthesize_unit_rs(synth_unit_idx);
        let bytes = body.into_bytes();
        fs::write(main_repo.join(&rel), &bytes).map_err(|e| format!("write {rel}: {e}"))?;
        if let Some(info) = analyze_code_file(&rel, bytes) {
            all_files.push(info);
        }
        synth_unit_idx += 1;
    }

    let target_body = edit_target_body(EDIT_INITIAL_LINE3);
    fs::write(main_repo.join(EDIT_TARGET_REL), target_body.as_bytes())
        .map_err(|e| format!("write {EDIT_TARGET_REL}: {e}"))?;

    run_git(&main_repo, &["-c", "core.autocrlf=false", "init", "-q"])?;
    run_git(&main_repo, &["config", "core.autocrlf", "false"])?;
    run_git(
        &main_repo,
        &[
            "-c",
            "user.name=bench",
            "-c",
            "user.email=bench@local",
            "-c",
            "commit.gpgsign=false",
            "add",
            "-A",
        ],
    )?;
    run_git(
        &main_repo,
        &[
            "-c",
            "user.name=bench",
            "-c",
            "user.email=bench@local",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "init",
        ],
    )?;

    let wt_parent = root.join("worktrees");
    fs::create_dir_all(&wt_parent).map_err(|e| format!("mkdir worktrees: {e}"))?;
    let mut worktrees = Vec::with_capacity(worktree_count);
    for k in 0..worktree_count {
        let wt_dir = wt_parent.join(format!("wt-{k}"));
        let wt_str = wt_dir.to_string_lossy().into_owned();
        run_git(&main_repo, &["worktree", "add", "-q", "--detach", &wt_str, "HEAD"])?;
        let canon_wt = fs::canonicalize(&wt_dir).unwrap_or(wt_dir);
        worktrees.push(canon_wt);
    }

    let canon_main = fs::canonicalize(&main_repo).unwrap_or(main_repo);

    let mut large_files: Vec<CorpusFile> = Vec::new();
    let mut other_files: Vec<CorpusFile> = Vec::new();
    for f in &all_files {
        if f.line_count >= LARGE_READ_THRESHOLD_LINES && f.non_ns_symbols >= MIN_LARGE_NON_NS_SYMS {
            large_files.push(f.clone());
        } else {
            other_files.push(f.clone());
        }
    }
    let large_count = large_files.len();
    let corpus_count = all_files.len() + 1;

    let mut hot_files: Vec<CorpusFile> = Vec::new();
    for f in large_files.iter().take(4) {
        hot_files.push(f.clone());
    }
    for f in other_files.iter().take(2) {
        hot_files.push(f.clone());
    }
    if hot_files.len() < 4 {
        for f in &all_files {
            if hot_files.len() >= 4 {
                break;
            }
            if !hot_files.iter().any(|h| h.rel_path == f.rel_path) {
                hot_files.push(f.clone());
            }
        }
    }

    let mut unique_files: Vec<CorpusFile> = Vec::new();
    for f in &all_files {
        if !hot_files.iter().any(|h| h.rel_path == f.rel_path) {
            unique_files.push(f.clone());
        }
    }
    if unique_files.is_empty() {
        unique_files = hot_files.clone();
    }

    Ok(SwarmWorkspace {
        main_repo: canon_main,
        worktrees,
        hot_files,
        unique_files,
        large_files,
        corpus_count,
        large_count,
    })
}

fn reply_payload_bytes(rep: &Json) -> usize {
    if let Some(txt) = rep.get_str("text") {
        return txt.len();
    }
    if let Some(hr) = rep.get("hook_reply") {
        if let Some(reason) = hr.get_str("reason") {
            return reason.len();
        }
        return hr.to_json_string().len();
    }
    if let Some(memos) = rep.get("memos") {
        return memos.to_json_string().len();
    }
    if let Some(memo) = rep.get("memo") {
        return memo.to_json_string().len();
    }
    if let Some(changes) = rep.get("changes") {
        return changes.to_json_string().len();
    }
    rep.to_json_string().len()
}

fn is_busy_reply(rep: &Json) -> bool {
    matches!(rep.get_str("code"), Some("search_busy" | "daemon_busy"))
        || rep
            .get_str("text")
            .is_some_and(|t| t.lines().any(|l| l == "Error: search busy"))
        || rep
            .get_str("error")
            .is_some_and(|e| e.contains("semaphore saturated"))
}

fn us_to_ms_token(us: u64) -> Json {
    // Fixed powers of ten (1000, 10) for compact decimal millisecond JSON numbers without f64.
    let whole = us / 1_000;
    let hundredths = (us % 1_000) / 10;
    Json::NumberToken(format!("{whole}.{hundredths:02}").into())
}

fn tenths_pct_token(tenths: u64) -> Json {
    Json::NumberToken(format!("{}.{}", tenths / 10, tenths % 10).into())
}

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct) / 100; // fixed power-of-ten scale (100)
    sorted[idx.min(sorted.len() - 1)]
}

fn line3_anchor(line3: &str) -> String {
    let h = line_hash3(line3);
    let hex = std::str::from_utf8(&h).unwrap_or("000");
    format!("3:{hex}")
}

pub fn run_swarm_cli(args: &[String]) -> i32 {
    let mut agent_levels: Vec<usize> = vec![10, 50, 100];
    let mut worktree_count: usize = 8;
    let mut repo_arg: Option<String> = None;
    let mut explicit_ctx: Option<String> = None;
    let mut as_json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => as_json = true,
            "--ctx-bin" if i + 1 < args.len() => {
                i += 1;
                explicit_ctx = Some(args[i].clone());
            }
            "--repo" if i + 1 < args.len() => {
                i += 1;
                repo_arg = Some(args[i].clone());
            }
            "--worktrees" if i + 1 < args.len() => {
                i += 1;
                if let Ok(v) = args[i].parse::<usize>() {
                    worktree_count = v.clamp(1, 32);
                }
            }
            "--agents" if i + 1 < args.len() => {
                i += 1;
                let parsed: Vec<usize> = args[i]
                    .split(',')
                    .filter_map(|s| s.trim().parse::<usize>().ok())
                    .filter(|&n| (1..=512).contains(&n))
                    .collect();
                if !parsed.is_empty() {
                    agent_levels = parsed;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let ctx_bin = match resolve_ctx_binary(explicit_ctx.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ctx-bench swarm error: {e}");
            return 1;
        }
    };
    let repo_dir = match repo_arg {
        Some(raw) => PathBuf::from(raw),
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    if !repo_dir.is_dir() {
        eprintln!("ctx-bench swarm error: --repo does not exist: {}", repo_dir.display());
        return 1;
    }

    let root = std::env::temp_dir().join(format!("ctx-swarm-bench-{}", std::process::id()));
    let rt = root.join("runtime");
    let snap = root.join("snapshot.bin");
    let _ = fs::remove_dir_all(&root);
    if let Err(e) = fs::create_dir_all(&rt) {
        eprintln!("ctx-bench swarm setup error: {e}");
        return 1;
    }

    let mut guard = SwarmGuard {
        root: root.clone(),
        daemon: None,
        port: 0,
        token: String::new(),
    };

    let ws = match prepare_swarm_workspace(&root, &repo_dir, worktree_count) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("ctx-bench swarm workspace error: {e}");
            return 1;
        }
    };

    let child = match Command::new(&ctx_bin)
        .arg("daemon")
        .env("AGENT_CTX_RUNTIME_DIR", &rt)
        .env("AGENT_CTX_SNAPSHOT_PATH", &snap)
        .env("AGENT_CTX_MAX_RAM_MB", "512")
        .env("AGENT_CTX_WRITE", "1")
        .env("AGENT_CTX_LARGE_READ_LINES", "350")
        .env("AGENT_CTX_NO_UPDATE_CHECK", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "ctx-bench swarm daemon spawn error ({}): {e}",
                ctx_bin.display()
            );
            return 1;
        }
    };
    guard.daemon = Some(child);

    let info_path = rt.join("daemon.json");
    for _ in 0..150 {
        if let Ok(txt) = fs::read_to_string(&info_path) {
            if let Ok(parsed) = json::parse(&txt) {
                if let (Some(p), Some(tok)) = (parsed.get_usize("port"), parsed.get_str("token")) {
                    guard.port = p as u16;
                    guard.token = tok.to_string();
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    if guard.port == 0 {
        eprintln!("ctx-bench swarm error: isolated daemon did not publish daemon.json");
        return 1;
    }

    let port = guard.port;
    let token = guard.token.clone();
    let main_repo_str = ws.main_repo.to_string_lossy().into_owned();
    let wt_strs: Vec<String> = ws
        .worktrees
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    // Register main repo and linked worktrees with daemon allowlist upfront
    let _ = send_swarm_rpc(
        port,
        &token,
        &Json::obj(vec![
            ("op", Json::Str("ping".to_string())),
            ("cwd", Json::Str(main_repo_str.clone())),
            ("explicit_root", Json::Bool(true)),
        ]),
    );
    for wt in &wt_strs {
        let _ = send_swarm_rpc(
            port,
            &token,
            &Json::obj(vec![
                ("op", Json::Str("ping".to_string())),
                ("cwd", Json::Str(wt.clone())),
                ("explicit_root", Json::Bool(true)),
            ]),
        );
    }

    let pack_selectors: Vec<String> = ws
        .hot_files
        .iter()
        .take(4)
        .map(|f| format!("{}#{}", f.rel_path, f.primary_symbol))
        .collect();
    let pack_files: Vec<&CorpusFile> = ws.hot_files.iter().take(4).collect();
    let hot_zero_bytes = ws.hot_files.first().map(|f| f.size_bytes as u64).unwrap_or(0);

    if !as_json {
        println!(
            "ctx-bench swarm (repo={}, corpus={} files [{} >=350L], {} linked worktrees):",
            repo_dir.display(),
            ws.corpus_count,
            ws.large_count,
            worktree_count
        );
        println!(
            "{:>6} | {:>9} | {:>7} | {:>7} | {:>7} | {:>6} | {:>6} | {:>6} | {:>6} | {:>8} | {:>7} | {:>7}",
            "agents",
            "ops/sec",
            "p50_ms",
            "p95_ms",
            "p99_ms",
            "errs",
            "lrg_rd",
            "pk_ded",
            "wt_mem",
            "ram_kib",
            "subproc",
            "save_%"
        );
        println!("{}", "-".repeat(116));
    }

    let mut wave_json_rows: Vec<Json> = Vec::with_capacity(agent_levels.len());
    let mut total_errors = 0usize;

    for (wave_idx, &n_agents) in agent_levels.iter().enumerate() {
        // Restore controlled edit target in wt-0 before each wave so line 3 anchor is deterministic
        let wt0_target = ws.worktrees[0].join(EDIT_TARGET_REL);
        let _ = fs::write(&wt0_target, edit_target_body(EDIT_INITIAL_LINE3).as_bytes());
        let main_target = ws.main_repo.join(EDIT_TARGET_REL);
        let _ = fs::write(&main_target, edit_target_body(EDIT_INITIAL_LINE3).as_bytes());

        // Phase 1: Scout publishes Shared Context Pack + 2 linked memos from main_repo
        let scout_session = format!("agy:bench-scout-w{wave_idx}");
        let pack_req = Json::obj(vec![
            ("op", Json::Str("memo".to_string())),
            ("action", Json::Str("pack".to_string())),
            ("cwd", Json::Str(main_repo_str.clone())),
            ("session", Json::Str(scout_session.clone())),
            ("topic", Json::Str(PACK_NAME.to_string())),
            (
                "summary",
                Json::Str(format!("Scout scope pack for wave {wave_idx}")),
            ),
            (
                "paths",
                Json::Arr(pack_selectors.iter().cloned().map(Json::Str).collect()),
            ),
        ]);
        let mut wave_setup_errors = 0usize;
        if send_swarm_rpc(port, &token, &pack_req)
            .ok()
            .and_then(|r| r.get_bool("ok"))
            != Some(true)
        {
            wave_setup_errors += 1;
        }

        if let Some(hot0) = ws.hot_files.first() {
            let memo_hot = Json::obj(vec![
                ("op", Json::Str("memo".to_string())),
                ("action", Json::Str("put".to_string())),
                ("cwd", Json::Str(main_repo_str.clone())),
                ("session", Json::Str(scout_session.clone())),
                ("topic", Json::Str(MEMO_HOT_TOPIC.to_string())),
                (
                    "summary",
                    Json::Str(format!(
                        "Primary symbol {} audited for wave {}",
                        hot0.primary_symbol, wave_idx
                    )),
                ),
                ("paths", Json::Arr(vec![Json::Str(hot0.rel_path.clone())])),
            ]);
            if send_swarm_rpc(port, &token, &memo_hot)
                .ok()
                .and_then(|r| r.get_bool("ok"))
                != Some(true)
            {
                wave_setup_errors += 1;
            }
        }

        let memo_edit = Json::obj(vec![
            ("op", Json::Str("memo".to_string())),
            ("action", Json::Str("put".to_string())),
            ("cwd", Json::Str(main_repo_str.clone())),
            ("session", Json::Str(scout_session)),
            ("topic", Json::Str(MEMO_EDIT_TOPIC.to_string())),
            (
                "summary",
                Json::Str(format!("Controlled edit baseline for wave {wave_idx}")),
            ),
            (
                "paths",
                Json::Arr(vec![Json::Str(EDIT_TARGET_REL.to_string())]),
            ),
        ]);
        if send_swarm_rpc(port, &token, &memo_edit)
            .ok()
            .and_then(|r| r.get_bool("ok"))
            != Some(true)
        {
            wave_setup_errors += 1;
        }

        let baseline_change_seq = send_swarm_rpc(
            port,
            &token,
            &Json::obj(vec![
                ("op", Json::Str("memo".to_string())),
                ("action", Json::Str("changes".to_string())),
                ("cwd", Json::Str(main_repo_str.clone())),
                ("since_seq", Json::Int(0)),
            ]),
        )
        .ok()
        .and_then(|r| r.get("changes")?.get_i64("head_seq"))
        .unwrap_or(0)
        .max(0);

        // Pre-assign per-worker indices using wrap counters (zero runtime % / div)
        let mut assignments: Vec<(usize, usize, usize, usize, bool)> = Vec::with_capacity(n_agents);
        let mut wt_idx = 0usize;
        let mut large_idx = 0usize;
        let mut hot_idx = 0usize;
        let mut uniq_idx = 0usize;
        let mut overlap_slot = 0usize;
        for _ in 0..n_agents {
            let use_hot_third = overlap_slot < 7; // 70% overlapping hot, 30% worker-unique
            let third_idx = if use_hot_third { hot_idx } else { uniq_idx };
            assignments.push((wt_idx, large_idx, hot_idx, third_idx, use_hot_third));
            wt_idx += 1;
            if wt_idx == wt_strs.len() {
                wt_idx = 0;
            }
            large_idx += 1;
            if large_idx == ws.large_files.len() {
                large_idx = 0;
            }
            hot_idx += 1;
            if hot_idx == ws.hot_files.len() {
                hot_idx = 0;
            }
            uniq_idx += 1;
            if uniq_idx == ws.unique_files.len() {
                uniq_idx = 0;
            }
            overlap_slot += 1;
            if overlap_slot == 10 {
                overlap_slot = 0;
            }
        }

        let start_barrier = Barrier::new(n_agents);
        let search_barrier = Barrier::new(n_agents);
        let edit_barrier = Barrier::new(n_agents);
        let post_edit_barrier = Barrier::new(n_agents);
        let edit_anchor = line3_anchor(EDIT_INITIAL_LINE3);
        let edited_line3 = format!("    const BENCH_REV: u64 = 10000{wave_idx}; // wave-{wave_idx}");

        let hot_q0 = ws
            .hot_files
            .first()
            .map(|f| format!("{}:{}", f.rel_path, f.search_token))
            .unwrap_or_default();
        let hot_q1 = ws
            .hot_files
            .get(1)
            .or_else(|| ws.hot_files.first())
            .map(|f| format!("{}:{}", f.rel_path, f.search_token))
            .unwrap_or_default();
        let hot_q2 = ws
            .hot_files
            .get(2)
            .or_else(|| ws.hot_files.first())
            .map(|f| format!("{}:{}", f.rel_path, f.search_token))
            .unwrap_or_default();

        let wave_start = Instant::now();
        let worker_results: Vec<WorkerStats> = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(n_agents);
            for (worker_id, &(w_wt, w_large, w_hot, w_third, use_hot_third)) in
                assignments.iter().enumerate()
            {
                let sb = &start_barrier;
                let srb = &search_barrier;
                let eb = &edit_barrier;
                let peb = &post_edit_barrier;
                let tok = token.as_str();
                let wt_str = wt_strs[w_wt].as_str();
                let large_f = &ws.large_files[w_large];
                let hot_b = &ws.hot_files[w_hot];
                let third_f = if use_hot_third {
                    &ws.hot_files[w_third]
                } else {
                    &ws.unique_files[w_third]
                };
                let p_files = &pack_files;
                let hq0 = hot_q0.as_str();
                let hq1 = hot_q1.as_str();
                let hq2 = hot_q2.as_str();
                let ea = edit_anchor.as_str();
                let el3 = edited_line3.as_str();

                handles.push(scope.spawn(move || {
                    let mut st = WorkerStats::default();
                    st.lats_us.reserve(11);
                    let conv_id = format!("bench-w{wave_idx}-{worker_id}");
                    let session = format!("agy:{conv_id}");

                    // Exact raw naive read_file bytes if worker read all distinct files in its scope
                    let mut naive_seen: HashSet<&str> = HashSet::new();
                    for cf in [large_f, hot_b, third_f]
                        .into_iter()
                        .chain(p_files.iter().copied())
                    {
                        if naive_seen.insert(cf.rel_path.as_str()) {
                            st.naive_bytes = st.naive_bytes.saturating_add(cf.size_bytes as u64);
                        }
                    }

                    sb.wait();

                    // 1. hook_agy SessionStart referencing pack:swarm-scope
                    {
                        let brief = format!(
                            "[swarm] You have just started. Your assignment: audit pack:{PACK_NAME} and {} in worktree.",
                            large_f.rel_path
                        );
                        let hook_payload = Json::obj(vec![
                            ("hookEventName", Json::Str("SessionStart".to_string())),
                            ("conversationId", Json::Str(conv_id.clone())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            (
                                "workspaceRoots",
                                Json::Arr(vec![Json::Str(wt_str.to_string())]),
                            ),
                            ("lastUserInput", Json::Str(brief)),
                        ]);
                        let req = Json::obj(vec![
                            ("op", Json::Str("hook".to_string())),
                            ("flavor", Json::Str("agy".to_string())),
                            ("payload", Json::Str(hook_payload.to_json_string())),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &req) {
                            Ok(rep) => {
                                if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let b = reply_payload_bytes(&rep) as u64;
                                    st.multiagent_bytes += b;
                                    st.v252_est_bytes += b;
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }

                    // 2. Concurrent 4-query batch search (coalescing + 2s micro-cache + fair-share)
                    srb.wait();
                    {
                        let q3 = format!("{}:{}", third_f.rel_path, third_f.search_token);
                        let req = Json::obj(vec![
                            ("op", Json::Str("search".to_string())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            ("session", Json::Str(session.clone())),
                            (
                                "q",
                                Json::Arr(vec![
                                    Json::Str(hq0.to_string()),
                                    Json::Str(hq1.to_string()),
                                    Json::Str(hq2.to_string()),
                                    Json::Str(q3),
                                ]),
                            ),
                            ("max_results", Json::Int(12)),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &req) {
                            Ok(rep) => {
                                if is_busy_reply(&rep) {
                                    st.search_busy += 1;
                                } else if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let b = reply_payload_bytes(&rep) as u64;
                                    st.multiagent_bytes += b;
                                    st.v252_est_bytes += b;
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }

                    // 3. hook_agy PreToolUse read_file on large >=350L code file (Large-Read Gate Strike 1)
                    {
                        let target_abs = Path::new(wt_str)
                            .join(&large_f.rel_path)
                            .to_string_lossy()
                            .into_owned();
                        let hook_payload = Json::obj(vec![
                            ("hookEventName", Json::Str("PreToolUse".to_string())),
                            ("conversationId", Json::Str(conv_id.clone())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            (
                                "workspaceRoots",
                                Json::Arr(vec![Json::Str(wt_str.to_string())]),
                            ),
                            (
                                "toolCall",
                                Json::obj(vec![
                                    ("id", Json::Str("call-large-read-1".to_string())),
                                    ("name", Json::Str("read_file".to_string())),
                                    ("args", Json::obj(vec![("Path", Json::Str(target_abs))])),
                                ]),
                            ),
                        ]);
                        let req = Json::obj(vec![
                            ("op", Json::Str("hook".to_string())),
                            ("flavor", Json::Str("agy".to_string())),
                            ("payload", Json::Str(hook_payload.to_json_string())),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &req) {
                            Ok(rep) => {
                                if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let denied = rep
                                        .get("hook_reply")
                                        .and_then(|hr| hr.get_str("decision"))
                                        == Some("deny");
                                    if denied {
                                        st.large_read_redirects += 1;
                                        let redir_b = reply_payload_bytes(&rep) as u64;
                                        st.multiagent_bytes += redir_b;
                                        // Without Large-Read Gate, v2.5.2 would deliver full file bytes
                                        st.v252_est_bytes += large_f.size_bytes as u64;
                                    } else {
                                        let full_b = large_f.size_bytes as u64;
                                        st.multiagent_bytes += full_b;
                                        st.v252_est_bytes += full_b;
                                    }
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }

                    // 4. symbols on hot + third files (ParsedBody cross-worktree RAM dedup)
                    {
                        let req = Json::obj(vec![
                            ("op", Json::Str("symbols".to_string())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            ("session", Json::Str(session.clone())),
                            ("compact", Json::Bool(true)),
                            (
                                "requests",
                                Json::Arr(vec![
                                    Json::Str(format!(
                                        "{}#{}",
                                        large_f.rel_path, large_f.primary_symbol
                                    )),
                                    Json::Str(format!(
                                        "{}#{}",
                                        third_f.rel_path, third_f.primary_symbol
                                    )),
                                ]),
                            ),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &req) {
                            Ok(rep) => {
                                if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let b = reply_payload_bytes(&rep) as u64;
                                    st.multiagent_bytes += b;
                                    st.v252_est_bytes += b;
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }

                    // 5a. memo pack_get + repeat pack_get (pack_dedup_hits + cross-worktree visibility)
                    let mut first_pack_bytes = 0u64;
                    for pass in 0..2u8 {
                        let req = Json::obj(vec![
                            ("op", Json::Str("memo".to_string())),
                            ("action", Json::Str("pack_get".to_string())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            ("session", Json::Str(session.clone())),
                            ("topic", Json::Str(PACK_NAME.to_string())),
                            ("max_bytes", Json::Int(8192)),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &req) {
                            Ok(rep) => {
                                if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let txt = rep.get_str("text").unwrap_or("");
                                    let b = txt.len() as u64;
                                    st.multiagent_bytes += b;
                                    if txt.starts_with("[UNCHANGED pack:") {
                                        st.pack_dedup_hits += 1;
                                        // Without pack dedup, full pack body would be resent
                                        st.v252_est_bytes += first_pack_bytes.max(b);
                                    } else {
                                        if pass == 0 {
                                            first_pack_bytes = b;
                                        }
                                        st.v252_est_bytes += b;
                                    }
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }

                    // 5b. memo list from linked worktree wt-k (cross-worktree memo visibility)
                    {
                        let req = Json::obj(vec![
                            ("op", Json::Str("memo".to_string())),
                            ("action", Json::Str("list".to_string())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            ("session", Json::Str(session.clone())),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &req) {
                            Ok(rep) => {
                                if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let b = reply_payload_bytes(&rep) as u64;
                                    st.multiagent_bytes += b;
                                    let found_fresh = rep
                                        .get("memos")
                                        .and_then(Json::as_arr)
                                        .is_some_and(|arr| {
                                            arr.iter().any(|m| {
                                                m.get_str("topic") == Some(MEMO_HOT_TOPIC)
                                                    && m.get_str("status") == Some("fresh")
                                            })
                                        });
                                    if found_fresh {
                                        st.cross_worktree_memo_ok += 1;
                                        // v2.5.2 isolated worktrees missed memos and re-read hot0
                                        st.v252_est_bytes += hot_zero_bytes.max(b);
                                    } else {
                                        st.v252_est_bytes += b;
                                    }
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }

                    // 6a. impact
                    {
                        let req = Json::obj(vec![
                            ("op", Json::Str("impact".to_string())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            ("session", Json::Str(session.clone())),
                            (
                                "targets",
                                Json::Arr(vec![Json::Str(format!(
                                    "{}#{}",
                                    hot_b.rel_path, hot_b.primary_symbol
                                ))]),
                            ),
                            ("max_callers", Json::Int(8)),
                            ("include_tests", Json::Bool(false)),
                            ("include_git_status", Json::Bool(false)),
                            ("max_bytes", Json::Int(4096)),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &req) {
                            Ok(rep) => {
                                if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let b = reply_payload_bytes(&rep) as u64;
                                    st.multiagent_bytes += b;
                                    st.v252_est_bytes += b;
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }

                    // 6b. git status / diff --stat
                    {
                        let req = if (worker_id & 1) == 0 {
                            Json::obj(vec![
                                ("op", Json::Str("git".to_string())),
                                ("action", Json::Str("status".to_string())),
                                ("cwd", Json::Str(wt_str.to_string())),
                            ])
                        } else {
                            Json::obj(vec![
                                ("op", Json::Str("git".to_string())),
                                ("action", Json::Str("diff".to_string())),
                                ("stat", Json::Bool(true)),
                                ("cwd", Json::Str(wt_str.to_string())),
                            ])
                        };
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &req) {
                            Ok(rep) => {
                                if is_busy_reply(&rep) {
                                    st.search_busy += 1;
                                } else if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let b = reply_payload_bytes(&rep) as u64;
                                    st.multiagent_bytes += b;
                                    st.v252_est_bytes += b;
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }

                    // 7. Controlled edit by worker 0 in wt-0 + ChangeFeed / [STALE] verification across worktrees
                    eb.wait();
                    if worker_id == 0 {
                        let edit_req = Json::obj(vec![
                            ("op", Json::Str("edit".to_string())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            ("session", Json::Str(session.clone())),
                            ("dry_run", Json::Bool(false)),
                            (
                                "edits",
                                Json::Arr(vec![Json::obj(vec![
                                    ("path", Json::Str(EDIT_TARGET_REL.to_string())),
                                    (
                                        "ops",
                                        Json::Arr(vec![Json::obj(vec![
                                            ("op", Json::Str("replace_lines".to_string())),
                                            ("start", Json::Str(ea.to_string())),
                                            ("end", Json::Str(ea.to_string())),
                                            ("content", Json::Str(el3.to_string())),
                                        ])]),
                                    ),
                                ])]),
                            ),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &edit_req) {
                            Ok(rep) => {
                                if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let b = reply_payload_bytes(&rep) as u64;
                                    st.multiagent_bytes += b;
                                    st.v252_est_bytes += b;
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }
                    peb.wait();

                    if worker_id == 0 {
                        // Verify [STALE] memo detection in the edited worktree
                        let get_req = Json::obj(vec![
                            ("op", Json::Str("memo".to_string())),
                            ("action", Json::Str("get".to_string())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            ("session", Json::Str(session)),
                            ("topic", Json::Str(MEMO_EDIT_TOPIC.to_string())),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &get_req) {
                            Ok(rep) => {
                                if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let b = reply_payload_bytes(&rep) as u64;
                                    st.multiagent_bytes += b;
                                    st.v252_est_bytes += b;
                                    st.stale_detected = rep
                                        .get("memo")
                                        .and_then(|m| m.get_str("status"))
                                        == Some("stale");
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    } else {
                        // Verify ChangeFeed visibility from other workers across linked worktrees
                        let ch_req = Json::obj(vec![
                            ("op", Json::Str("memo".to_string())),
                            ("action", Json::Str("changes".to_string())),
                            ("cwd", Json::Str(wt_str.to_string())),
                            ("session", Json::Str(session)),
                            ("since_seq", Json::Int(baseline_change_seq)),
                        ]);
                        let t0 = Instant::now();
                        match send_swarm_rpc(port, tok, &ch_req) {
                            Ok(rep) => {
                                if rep.get_bool("ok") != Some(true) {
                                    st.errors += 1;
                                } else {
                                    let b = reply_payload_bytes(&rep) as u64;
                                    st.multiagent_bytes += b;
                                    st.v252_est_bytes += b;
                                    st.change_feed_visible = rep
                                        .get("changes")
                                        .and_then(|c| c.get("events"))
                                        .and_then(Json::as_arr)
                                        .is_some_and(|evs| {
                                            evs.iter().any(|ev| {
                                                ev.get_str("rel_path") == Some(EDIT_TARGET_REL)
                                            })
                                        });
                                }
                            }
                            Err(_) => st.errors += 1,
                        }
                        st.lats_us.push(t0.elapsed().as_micros() as u64);
                    }

                    st
                }));
            }

            let mut out = Vec::with_capacity(n_agents);
            for h in handles {
                match h.join() {
                    Ok(stats) => out.push(stats),
                    Err(_) => out.push(WorkerStats {
                        errors: 1,
                        ..WorkerStats::default()
                    }),
                }
            }
            out
        });

        let elapsed_ns = wave_start.elapsed().as_nanos().max(1);
        let mut all_lats_us: Vec<u64> = Vec::with_capacity(n_agents * 11);
        let mut wave_errors = wave_setup_errors;
        let mut wave_search_busy = 0usize;
        let mut large_read_redirects = 0usize;
        let mut pack_dedup_hits = 0usize;
        let mut cross_worktree_memo_ok = 0usize;
        let mut change_feed_visible = 0usize;
        let mut stale_detected = false;
        let mut naive_read_file_bytes = 0u64;
        let mut ctx_v252_est_bytes = 0u64;
        let mut ctx_multiagent_bytes = 0u64;

        for mut r in worker_results {
            all_lats_us.append(&mut r.lats_us);
            wave_errors += r.errors;
            wave_search_busy += r.search_busy;
            large_read_redirects += r.large_read_redirects;
            pack_dedup_hits += r.pack_dedup_hits;
            cross_worktree_memo_ok += r.cross_worktree_memo_ok;
            if r.change_feed_visible {
                change_feed_visible += 1;
            }
            stale_detected |= r.stale_detected;
            naive_read_file_bytes = naive_read_file_bytes.saturating_add(r.naive_bytes);
            ctx_v252_est_bytes = ctx_v252_est_bytes.saturating_add(r.v252_est_bytes);
            ctx_multiagent_bytes = ctx_multiagent_bytes.saturating_add(r.multiagent_bytes);
        }

        all_lats_us.sort_unstable();
        let total_ops = all_lats_us.len();
        let p50_us = percentile(&all_lats_us, 50);
        let p95_us = percentile(&all_lats_us, 95);
        let p99_us = percentile(&all_lats_us, 99);
        // Necessary reporting quotient over runtime wall-clock ns (zero-guarded above).
        let ops_per_sec = ((total_ops as u128 * 1_000_000_000u128) / elapsed_ns) as u64;

        let st = send_swarm_rpc(
            port,
            &token,
            &Json::obj(vec![("op", Json::Str("status".to_string()))]),
        )
        .ok()
        .and_then(|r| r.get("status").cloned())
        .unwrap_or(Json::Null);

        let used_ram_bytes = st.get_i64("used_ram_bytes").unwrap_or(0).max(0) as u64;
        let cached_files = st.get_i64("cached_files").unwrap_or(0).max(0) as u64;
        let peak_subprocs = st.get_i64("peak_subprocs").unwrap_or(0).max(0) as u64;
        let cache_hits = st.get_i64("cache_hits").unwrap_or(0).max(0) as u64;
        let cache_misses = st.get_i64("cache_misses").unwrap_or(0).max(0) as u64;
        let memo_entries = st.get_i64("memo_entries").unwrap_or(0).max(0) as u64;

        // Necessary reporting ratios over runtime byte totals (zero-guarded).
        let payload_savings_tenths: u64 = if naive_read_file_bytes > 0 {
            let saved = naive_read_file_bytes.saturating_sub(ctx_multiagent_bytes);
            ((saved as u128 * 1_000u128) / naive_read_file_bytes as u128) as u64
        } else {
            0
        };
        let vs_v252_tenths: u64 = if ctx_v252_est_bytes > 0 {
            let saved = ctx_v252_est_bytes.saturating_sub(ctx_multiagent_bytes);
            ((saved as u128 * 1_000u128) / ctx_v252_est_bytes as u128) as u64
        } else {
            0
        };

        total_errors += wave_errors;

        if !as_json {
            let p50_str = format!("{}.{:02}", p50_us / 1_000, (p50_us % 1_000) / 10);
            let p95_str = format!("{}.{:02}", p95_us / 1_000, (p95_us % 1_000) / 10);
            let p99_str = format!("{}.{:02}", p99_us / 1_000, (p99_us % 1_000) / 10);
            let sav_str = format!(
                "{}.{}%",
                payload_savings_tenths / 10,
                payload_savings_tenths % 10
            );
            println!(
                "{:>6} | {:>9} | {:>7} | {:>7} | {:>7} | {:>6} | {:>6} | {:>6} | {:>6} | {:>8} | {:>7} | {:>7}",
                n_agents,
                ops_per_sec,
                p50_str,
                p95_str,
                p99_str,
                wave_errors,
                large_read_redirects,
                pack_dedup_hits,
                cross_worktree_memo_ok,
                used_ram_bytes >> 10,
                peak_subprocs,
                sav_str
            );
        }

        wave_json_rows.push(Json::obj(vec![
            ("agents", Json::Int(n_agents as i64)),
            ("worktrees", Json::Int(worktree_count as i64)),
            ("total_ops", Json::Int(total_ops as i64)),
            ("ops_per_sec", Json::Int(ops_per_sec as i64)),
            ("p50_ms", us_to_ms_token(p50_us)),
            ("p95_ms", us_to_ms_token(p95_us)),
            ("p99_ms", us_to_ms_token(p99_us)),
            ("p50_us", Json::Int(p50_us as i64)),
            ("p95_us", Json::Int(p95_us as i64)),
            ("p99_us", Json::Int(p99_us as i64)),
            ("errors", Json::Int(wave_errors as i64)),
            ("search_busy", Json::Int(wave_search_busy as i64)),
            (
                "large_read_redirects",
                Json::Int(large_read_redirects as i64),
            ),
            ("pack_dedup_hits", Json::Int(pack_dedup_hits as i64)),
            (
                "cross_worktree_memo_ok",
                Json::Int(cross_worktree_memo_ok as i64),
            ),
            (
                "change_feed_visible",
                Json::Int(change_feed_visible as i64),
            ),
            ("stale_detected", Json::Bool(stale_detected)),
            ("used_ram_bytes", Json::Int(used_ram_bytes as i64)),
            ("cached_files", Json::Int(cached_files as i64)),
            ("peak_subprocs", Json::Int(peak_subprocs as i64)),
            ("cache_hits", Json::Int(cache_hits as i64)),
            ("cache_misses", Json::Int(cache_misses as i64)),
            ("memo_entries", Json::Int(memo_entries as i64)),
            (
                "naive_read_file_bytes",
                Json::Int(naive_read_file_bytes as i64),
            ),
            ("ctx_v252_est_bytes", Json::Int(ctx_v252_est_bytes as i64)),
            (
                "ctx_multiagent_bytes",
                Json::Int(ctx_multiagent_bytes as i64),
            ),
            (
                "payload_savings_pct",
                tenths_pct_token(payload_savings_tenths),
            ),
            ("vs_v252_savings_pct", tenths_pct_token(vs_v252_tenths)),
        ]));
    }

    if as_json {
        println!(
            "{}",
            Json::obj(vec![
                ("ok", Json::Bool(total_errors == 0)),
                ("repo", Json::Str(repo_dir.to_string_lossy().into_owned())),
                ("worktrees", Json::Int(worktree_count as i64)),
                ("corpus_files", Json::Int(ws.corpus_count as i64)),
                ("large_files", Json::Int(ws.large_count as i64)),
                ("waves", Json::Arr(wave_json_rows)),
            ])
            .to_json_string()
        );
    }

    if total_errors == 0 {
        0
    } else {
        1
    }
}
