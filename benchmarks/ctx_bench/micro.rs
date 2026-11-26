//! Direct in-process hot-kernel microbenchmarks (`ctx-bench micro`).
//! Calls only production public `ctx::` APIs (zero test-only hooks in `src/`).

use ctx::base::json::{self, Json};
use ctx::base::security::WorkspaceAllowlist;
use ctx::base::simd::fmt::push_u64;
use ctx::base::simd::{
    decimal_digits, fast_hash64, scan_source_bytes, search_lines_literals,
    trigram_bloom64_ascii_lower,
};
use ctx::parser::extract_symbols;
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
