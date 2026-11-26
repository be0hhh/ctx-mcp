//! Direct in-process hot-kernel microbenchmarks (`ctx-bench micro`).
//! Calls only production public `ctx::` APIs (zero test-only hooks in `src/`).

use ctx::base::json::{self, Json};
use ctx::base::security::WorkspaceAllowlist;
use ctx::base::simd::fmt::push_u64;
use ctx::base::simd::{
    decimal_digits, fast_hash64, line_hash3, scan_source_bytes, search_lines_literals,
    trigram_bloom128_ascii_lower, trigram_bloom64_ascii_lower,
};
use ctx::cli::diag::compress_diagnostics;
use ctx::engine::compact::compact_text_for_ext;
use ctx::engine::{op_search, SearchOptions, SEARCH_RESPONSE_BYTES};
use ctx::install::update::sha256_hex;
use ctx::parser::{build_cleaned_code_buffer_for_ext, extract_symbols};
use ctx::rpc::BrokerService;
use ctx::store::RamStore;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

struct MicroRow {
    name: &'static str,
    iters: usize,
    bytes_per_iter: usize,
    total_ns: u128,
}

impl MicroRow {
    fn ns_per_op(&self) -> u64 {
        let iters = self.iters.max(1) as u128;
        (self.total_ns / iters) as u64
    }

    fn mb_per_sec(&self) -> u64 {
        if self.bytes_per_iter == 0 {
            return 0;
        }
        let total_bytes = (self.bytes_per_iter as u128) * (self.iters as u128);
        let ns = self.total_ns.max(1);
        // bytes/ns == GB/s; * 1000 => MB/s (SI 10^6 B/s)
        ((total_bytes * 1_000) / ns) as u64
    }
}

fn build_synthetic_cpp(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 4096);
    s.push_str("#pragma once\n#include <cstdint>\nnamespace bench::hot {\n");
    let mut i = 0usize;
    while s.len() < target_bytes {
        s.push_str("struct EngineSlot_");
        push_u64(&mut s, i as u64);
        s.push_str(" {\n  std::int64_t bidPxE8 = 100000000;\n  std::int64_t askPxE8 = 100000100;\n");
        s.push_str("  // synthetic comment line with \"quoted \\\"text\\\"\" and unicode: цена\n");
        if (i & 31) == 17 {
            s.push_str("  bool applyFillHot(std::int64_t deltaQty) noexcept { return deltaQty > 0; }\n");
        } else {
            s.push_str("  bool onTickUpdate(std::int64_t seq) noexcept { return seq != 0; }\n");
        }
        s.push_str("};\n");
        i += 1;
    }
    s.push_str("} // namespace bench::hot\n");
    s
}

fn build_synthetic_4k_lines() -> Vec<String> {
    let mut lines = Vec::with_capacity(4096);
    for i in 0..4096usize {
        let mut line = String::with_capacity(72);
        match i & 3 {
            0 => {
                line.push_str("  const std::int64_t nextQty_");
                push_u64(&mut line, i as u64);
                line.push_str(" = states_[instId].netQtyE8 + deltaE8;");
            }
            1 => {
                line.push_str("  if (bytescan::hftUnlikely(instId >= kMaxInst)) return false; // #");
                push_u64(&mut line, i as u64);
            }
            2 => {
                line.push_str("  coldMirrors_[");
                push_u64(&mut line, (i & 63) as u64);
                line.push_str("].storeHot(nextNetQtyE8);");
            }
            _ => {
                line.push_str("  [[nodiscard]] bool canApplyFillHot_");
                push_u64(&mut line, i as u64);
                line.push_str("(Side side, std::int64_t qty) const noexcept;");
            }
        }
        lines.push(line);
    }
    lines
}

fn build_synthetic_clean_cpp(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 4096);
    s.push_str("#pragma once\n#include <cstdint>\nnamespace bench::clean {\n");
    let mut i = 0usize;
    while s.len() < target_bytes {
        s.push_str("struct RuleUnit_");
        push_u64(&mut s, i as u64);
        s.push_str(" {\n");
        s.push_str("  static constexpr std::uint64_t kScale = 1'000'000'000ULL;\n");
        s.push_str("  static constexpr std::uint32_t kMask = 0xFF'AA'10u;\n");
        s.push_str("  // line comment with 'quote' and \"string\" and struct Ignored {}\n");
        s.push_str("  /* block comment with 1'000 and { fake_scope(); } */\n");
        s.push_str("  static constexpr const char* kRaw = R\"raw(payload { 1'000 } \"x\")raw\";\n");
        s.push_str("  static constexpr char kTag = 'x';\n");
        s.push_str("  bool check(std::int64_t v) const noexcept { return v != 1'000 && kTag != '\\n'; }\n");
        s.push_str("};\n");
        i += 1;
    }
    s.push_str("} // namespace bench::clean\n");
    s
}

fn build_synthetic_clean_rs(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 4096);
    s.push_str("pub mod clean_bench {\n");
    let mut i = 0usize;
    while s.len() < target_bytes {
        s.push_str("pub fn borrow_slot_");
        push_u64(&mut s, i as u64);
        s.push_str("<'a, 'b>(head: &'a str, fallback: &'static str) -> &'a str {\n");
        s.push_str("    // rust comment with 'a and \"ignored\"\n");
        s.push_str("    /* outer /* nested { fn fake<'c>() {} } */ comment */\n");
        s.push_str("    let raw = r#\"raw \"quoted\" { lifetime 'a }\"#;\n");
        s.push_str("    let sep: u64 = 1_000_000;\n");
        s.push_str("    if head.is_empty() && raw.len() == sep as usize && '\\n' != 'x' {\n");
        s.push_str("        let _ = fallback;\n");
        s.push_str("    }\n");
        s.push_str("    head\n");
        s.push_str("}\n");
        i += 1;
    }
    s.push_str("}\n");
    s
}

fn build_synthetic_rank_cpp() -> String {
    let mut s = String::with_capacity(32 * 1024);
    s.push_str("#pragma once\n#include <cstdint>\nnamespace bench::rank {\n");
    for i in 0..26usize {
        s.push_str("struct ScopeEngine_");
        push_u64(&mut s, i as u64);
        s.push_str(" {\n");
        s.push_str("  // comment mention of applyFillHot before member\n");
        s.push_str("  std::int64_t netQtyE8 = 0;\n");
        s.push_str("  std::uint64_t openCostE8 = 0;\n");
        s.push_str("  bool applyFillHot(std::int64_t deltaQty, std::int64_t fillPx) noexcept {\n");
        s.push_str("    if (deltaQty == 0 || fillPx <= 0) return false;\n");
        s.push_str("    netQtyE8 += deltaQty;\n");
        s.push_str("    openCostE8 += static_cast<std::uint64_t>(fillPx);\n");
        s.push_str("    return true;\n");
        s.push_str("  }\n");
        s.push_str("  bool dispatchOrderHot(std::int64_t qty, std::int64_t px) noexcept {\n");
        s.push_str("    // call site note for applyFillHot\n");
        s.push_str("    const bool ok = applyFillHot(qty, px);\n");
        s.push_str("    if (!ok) return false;\n");
        s.push_str("    return applyFillHot(qty, px);\n");
        s.push_str("  }\n");
        s.push_str("  std::int64_t loadHot() const noexcept { return netQtyE8; }\n");
        s.push_str("};\n");
    }
    s.push_str("} // namespace bench::rank\n");
    s
}

fn build_synthetic_syslog_256k(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 4096);
    let mut i = 0u64;
    while s.len() < target_bytes {
        let sec = i & 31;
        if (i & 255) == 127 {
            s.push_str("\x1b[31m2026-11-26T21:10:");
            push_u64(&mut s, sec);
            s.push_str("Z node-1 svc[4123]: FATAL: wal checksum mismatch at 0xdeadbeef\x1b[0m\n");
        } else if (i & 63) == 17 {
            s.push_str("[");
            push_u64(&mut s, i);
            s.push_str("/4096] syncing...\r[");
            push_u64(&mut s, i + 1);
            s.push_str("/4096] syncing...\r2026-11-26T21:10:");
            push_u64(&mut s, sec);
            s.push_str("Z node-1 svc[4123]: WARN: queue depth ");
            push_u64(&mut s, 500 + (i & 31));
            s.push_str(" peer=10.20.30.40:8443\n");
        } else {
            s.push_str("\x1b[32m2026-11-26T21:10:");
            push_u64(&mut s, sec);
            s.push_str("Z\x1b[0m node-1 svc[");
            push_u64(&mut s, 4100 + (i & 31));
            s.push_str("]: INFO healthcheck ok req=550e8400-e29b-41d4-a716-446655440000 ptr=0x7f00");
            push_u64(&mut s, i & 255);
            s.push('\n');
        }
        i += 1;
    }
    s
}

fn build_synthetic_json_array_256k(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 4096);
    s.push_str("[\n");
    let mut i = 0u64;
    while s.len() + 180 < target_bytes {
        if i > 0 {
            s.push_str(",\n");
        }
        if (i & 127) == 77 {
            s.push_str("  {\"id\":");
            push_u64(&mut s, i);
            s.push_str(",\"status\":\"failed\",\"error\":\"RATE_LIMIT_EXCEEDED\",\"message\":\"quota exhausted on shard eu-central-1\"}");
        } else {
            s.push_str("  {\"id\":");
            push_u64(&mut s, i);
            s.push_str(",\"service\":\"gateway\",\"region\":\"eu-central-1\",\"status\":\"ok\",\"latency_ms\":");
            push_u64(&mut s, 10 + (i & 31));
            s.push_str(",\"checksum\":\"xxh3_0000aabbccdd\"}");
        }
        i += 1;
    }
    s.push_str("\n]\n");
    s
}

fn build_synthetic_md_32k(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 2048);
    s.push_str("---\ntitle: Bench Spec\nversion: 2.5\n---\n\n# Overview\n\n");
    let mut i = 0u64;
    while s.len() < target_bytes {
        s.push_str("## Section ");
        push_u64(&mut s, i);
        s.push_str("\n\n<!-- verbose review note to strip -->\n\n\n");
        s.push_str("| Parameter      | Config Key            | Active Value  |\n");
        s.push_str("| -------------- | --------------------- | ------------- |\n");
        s.push_str("| Max Batch      | `limits.max_batch`    | `6`           |\n\n");
        s.push_str("```rust\nlet keep_blank = true;\n\nlet kept = \"<!-- inside fence -->\";\n```\n\n");
        i += 1;
    }
    s
}

fn build_synthetic_compact_json_32k(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 2048);
    s.push_str("{\n  \"routes\": {\n");
    let mut i = 0u64;
    while s.len() + 200 < target_bytes {
        if i > 0 {
            s.push_str(",\n");
        }
        s.push_str("    \"route_");
        push_u64(&mut s, i);
        s.push_str("\": {\n      \"model\": \"neon\",\n      \"effort\": \"xhigh\",\n      \"url\": \"https://example.local/api/v1\"\n    }");
        i += 1;
    }
    s.push_str("\n  }\n}\n");
    s
}

fn bench_kernel<F: FnMut()>(
    name: &'static str,
    iters: usize,
    bytes_per_iter: usize,
    mut f: F,
) -> MicroRow {
    // Warmup
    let warm = (iters / 10).clamp(2, 16);
    for _ in 0..warm {
        f();
    }
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    MicroRow {
        name,
        iters,
        bytes_per_iter,
        total_ns: t0.elapsed().as_nanos().max(1),
    }
}

pub fn run_micro_cli(args: &[String]) -> i32 {
    let mut iters: usize = 200;
    let mut as_json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => as_json = true,
            "--iters" if i + 1 < args.len() => {
                i += 1;
                if let Ok(v) = args[i].parse::<usize>() {
                    iters = v.clamp(1, 100_000);
                }
            }
            _ => {}
        }
        i += 1;
    }

    let cpp_256k = build_synthetic_cpp(256 * 1024);
    let scanned = match scan_source_bytes(cpp_256k.as_bytes().to_vec()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ctx-bench micro scan error: {e:?}");
            return 1;
        }
    };
    let cpp_64k = build_synthetic_cpp(64 * 1024);
    let scanned_64k = match scan_source_bytes(cpp_64k.as_bytes().to_vec()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ctx-bench micro scan error: {e:?}");
            return 1;
        }
    };

    let json_payload = Json::obj(vec![
        ("op", Json::Str("read".to_string())),
        ("ok", Json::Bool(true)),
        ("text", Json::Str(cpp_64k.clone())),
        ("lines", Json::Int(2048)),
    ])
    .to_json_string();

    let paths_batch: Vec<&[u8]> = vec![
        b"src/src/Exchanges/Binance/Spot/Market/v1_ws/Bbo.hpp",
        b"src/src/Runtime/Hot/Position/PositionTable.hpp",
        b"src/src/Runtime/Cold/Startup/StartupStreamBoundary.cpp",
        b"src/src/Core/Math/FastDivisor.hpp",
        b"src/src/Trading/Capital/AccountWalletLedger.hpp",
        b"agents/ctx/src/base/simd/search.rs",
    ];
    let paths_total_bytes: usize = paths_batch.iter().map(|p| p.len()).sum();

    let tmp_root = std::env::temp_dir().join(format!("ctx-micro-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_root);
    let _ = fs::create_dir_all(tmp_root.join(".git"));
    let sample_file = tmp_root.join("OrderEngine.hpp");
    let _ = fs::write(&sample_file, &cpp_64k);
    let allowlist = WorkspaceAllowlist::new();
    let _ = allowlist.register_hint(&tmp_root, true);
    let store = RamStore::new(tmp_root.join("snapshot.bin"));
    let canon_sample = allowlist.admit_file(&sample_file, Some(&tmp_root)).ok();
    if let Some((ref cp, ref wr)) = canon_sample {
        let _ = store.get_full_entry(cp, Some(wr));
    }

    let mut rows = Vec::new();

    rows.push(bench_kernel(
        "search_exact_256k",
        iters,
        scanned.text.len(),
        || {
            let hits = search_lines_literals(
                black_box(&scanned.text),
                black_box(&scanned.line_offsets),
                black_box(&["applyFillHot"]),
                true,
                256,
            );
            black_box(hits);
        },
    ));

    rows.push(bench_kernel(
        "search_ascii_ci_256k",
        iters,
        scanned.text.len(),
        || {
            let hits = search_lines_literals(
                black_box(&scanned.text),
                black_box(&scanned.line_offsets),
                black_box(&["applyfillhot"]),
                false,
                256,
            );
            black_box(hits);
        },
    ));

    rows.push(bench_kernel(
        "scan_source_256k",
        iters,
        cpp_256k.len(),
        || {
            let res = scan_source_bytes(black_box(cpp_256k.as_bytes().to_vec()));
            let _ = black_box(res);
        },
    ));

    rows.push(bench_kernel(
        "fast_hash64_256k",
        iters * 4,
        cpp_256k.len(),
        || {
            let h = fast_hash64(black_box(cpp_256k.as_bytes()));
            black_box(h);
        },
    ));

    rows.push(bench_kernel(
        "trigram_bloom_6paths",
        iters * 64,
        paths_total_bytes,
        || {
            let mut acc = 0u64;
            for &p in &paths_batch {
                acc ^= trigram_bloom64_ascii_lower(black_box(p));
            }
            black_box(acc);
        },
    ));

    rows.push(bench_kernel("push_u64_x1000", iters * 8, 0, || {
        let mut buf = String::with_capacity(8192);
        let mut dsum = 0usize;
        for n in 0..1000u64 {
            let v = n.wrapping_mul(1_234_567);
            dsum += decimal_digits(black_box(v as usize));
            push_u64(&mut buf, black_box(v));
        }
        black_box((buf.len(), dsum));
    }));

    rows.push(bench_kernel(
        "json_parse_64k",
        iters,
        json_payload.len(),
        || {
            let parsed = json::parse(black_box(&json_payload));
            let _ = black_box(parsed);
        },
    ));

    let parsed_doc = json::parse(&json_payload).unwrap_or(Json::Null);
    rows.push(bench_kernel(
        "json_encode_64k",
        iters,
        json_payload.len(),
        || {
            let encoded = black_box(&parsed_doc).to_json_string();
            black_box(encoded);
        },
    ));

    rows.push(bench_kernel(
        "cpp_parse_64k",
        iters.min(200),
        scanned_64k.text.len(),
        || {
            let syms = extract_symbols(
                Path::new("OrderEngine.hpp"),
                black_box(&scanned_64k.text),
                black_box(&scanned_64k.line_offsets),
            );
            black_box(syms);
        },
    ));

    if let Some((ref cp, ref wr)) = canon_sample {
        rows.push(bench_kernel("store_cache_hit", iters * 64, 0, || {
            let entry = store.get_full_entry(black_box(cp), Some(black_box(wr)));
            let _ = black_box(entry);
        }));
        rows.push(bench_kernel("allowlist_admit_file", iters * 8, 0, || {
            let admitted = allowlist.admit_file(black_box(&sample_file), Some(black_box(&tmp_root)));
            let _ = black_box(admitted);
        }));
    }

    let lines_4k = build_synthetic_4k_lines();
    let lines_4k_bytes: usize = lines_4k.iter().map(String::len).sum();
    rows.push(bench_kernel(
        "line_hash3_4k_lines",
        iters,
        lines_4k_bytes,
        || {
            let mut acc = 0u32;
            for line in &lines_4k {
                let h = line_hash3(black_box(line.as_str()));
                acc ^= (h[0] as u32) | ((h[1] as u32) << 8) | ((h[2] as u32) << 16);
            }
            black_box(acc);
        },
    ));

    let sha_buf_256k = &cpp_256k.as_bytes()[..256 * 1024];
    rows.push(bench_kernel(
        "sha256_hex_256k",
        iters.min(200),
        sha_buf_256k.len(),
        || {
            let hex = sha256_hex(black_box(sha_buf_256k));
            black_box(hex);
        },
    ));

    let clean_cpp_128k = build_synthetic_clean_cpp(128 * 1024);
    let clean_rs_128k = build_synthetic_clean_rs(128 * 1024);
    rows.push(bench_kernel(
        "clean_code_buf_256k",
        iters.min(200),
        clean_cpp_128k.len() + clean_rs_128k.len(),
        || {
            let cleaned_cpp = build_cleaned_code_buffer_for_ext(black_box(&clean_cpp_128k), "cpp");
            let cleaned_rs = build_cleaned_code_buffer_for_ext(black_box(&clean_rs_128k), "rs");
            black_box((cleaned_cpp.len(), cleaned_rs.len()));
        },
    ));

    let rank_cpp = build_synthetic_rank_cpp();
    let rank_file = tmp_root.join("MultiScopeRank.hpp");
    let _ = fs::write(&rank_file, &rank_cpp);
    let rank_svc = BrokerService::new_ephemeral_inproc(tmp_root.join("rank-snapshot.bin"));
    let _ = rank_svc.allowlist.register_hint(&tmp_root, true);
    if let Ok((cp, wr)) = rank_svc.allowlist.admit_file(&rank_file, Some(&tmp_root)) {
        let _ = rank_svc.store.get_full_entry(&cp, Some(&wr));
    }
    let rank_roots = vec!["MultiScopeRank.hpp".to_string()];
    let rank_opts = SearchOptions {
        max_results: 24,
        with_scopes: false,
        context_lines: 0,
        max_bytes: SEARCH_RESPONSE_BYTES,
        code_only: false,
    };
    rows.push(bench_kernel(
        "search_rank_spread",
        iters.min(200),
        rank_cpp.len(),
        || {
            let res = op_search(
                &rank_svc,
                black_box("applyFillHot"),
                black_box(&rank_roots),
                rank_opts,
                Some(&tmp_root),
            );
            let _ = black_box(res);
        },
    ));

    let bloom_buf_256k = &cpp_256k.as_bytes()[..256 * 1024];
    rows.push(bench_kernel(
        "content_bloom128_256k",
        iters * 2,
        bloom_buf_256k.len(),
        || {
            let b = trigram_bloom128_ascii_lower(black_box(bloom_buf_256k));
            black_box(b);
        },
    ));

    let syslog_256k = build_synthetic_syslog_256k(256 * 1024);
    rows.push(bench_kernel(
        "diag_log_compress_256k",
        iters.min(100),
        syslog_256k.len(),
        || {
            let out = compress_diagnostics(black_box(&syslog_256k), Path::new("."), 15, 2, false);
            black_box(out.len());
        },
    ));

    let diag_json_256k = build_synthetic_json_array_256k(256 * 1024);
    rows.push(bench_kernel(
        "diag_json_compact_256k",
        iters.min(100),
        diag_json_256k.len(),
        || {
            let out =
                compress_diagnostics(black_box(&diag_json_256k), Path::new("."), 15, 2, false);
            black_box(out.len());
        },
    ));

    let md_32k = build_synthetic_md_32k(32 * 1024);
    let compact_json_32k = build_synthetic_compact_json_32k(32 * 1024);
    rows.push(bench_kernel(
        "compact_md_json_64k",
        iters.min(200),
        md_32k.len() + compact_json_32k.len(),
        || {
            let c_md = compact_text_for_ext("md", black_box(&md_32k), false);
            let c_json = compact_text_for_ext("json", black_box(&compact_json_32k), true);
            black_box((c_md.len(), c_json.len()));
        },
    ));

    let _ = fs::remove_dir_all(&tmp_root);

    if as_json {
        let items: Vec<Json> = rows
            .iter()
            .map(|r| {
                Json::obj(vec![
                    ("name", Json::Str(r.name.to_string())),
                    ("iters", Json::Int(r.iters as i64)),
                    ("bytes_per_iter", Json::Int(r.bytes_per_iter as i64)),
                    ("ns_per_op", Json::Int(r.ns_per_op() as i64)),
                    ("mb_per_sec", Json::Int(r.mb_per_sec() as i64)),
                ])
            })
            .collect();
        println!(
            "{}",
            Json::obj(vec![("ok", Json::Bool(true)), ("kernels", Json::Arr(items))])
                .to_json_string()
        );
    } else {
        println!(
            "{:<24} | {:>8} | {:>10} | {:>10}",
            "kernel", "iters", "ns/op", "MB/s"
        );
        println!("{}", "-".repeat(62));
        for r in &rows {
            let mb = if r.bytes_per_iter > 0 {
                r.mb_per_sec().to_string()
            } else {
                "-".to_string()
            };
            println!(
                "{:<24} | {:>8} | {:>10} | {:>10}",
                r.name,
                r.iters,
                r.ns_per_op(),
                mb
            );
        }
    }

    0
}
