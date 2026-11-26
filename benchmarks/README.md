# CTX benchmarks

Live Native vs CTX agent results are in the [main README](../README.md#benchmark-highlights).

## Load & Hot-Kernel Results (`v2.4.0`)

Measured on Linux x86-64 (AMD Ryzen 5 5600X, AVX2 + BMI1, `rustc 1.100.0`, release full LTO, `0` hardware `div`/`idiv` in `ctx::`).

### 1. In-process hot kernels (`ctx-bench micro --iters 200`)

| Kernel | Iterations | ns/op | Throughput |
|---|---:|---:|---:|
| `search_exact_256k` (AVX2+BMI1 zero-spill) | 200 | 7,012 | **37,391 MB/s** |
| `search_ascii_ci_256k` (AVX2+BMI1 inline fold) | 200 | 6,599 | **39,729 MB/s** |
| `scan_source_256k` (2-phase AVX2+BMI1) | 200 | 23,532 | **11,142 MB/s** |
| `fast_hash64_256k` (2-way ILP 32B fold) | 800 | 15,888 | **16,503 MB/s** |
| `json_encode_64k` (single-pass AVX2 stream) | 200 | 14,879 | **4,629 MB/s** |
| `json_parse_64k` (SIMD escape-free slice) | 200 | 23,748 | **2,900 MB/s** |
| `trigram_bloom_6paths` (256B LUT) | 12,800 | 262 | **1,009 MB/s** |
| `cpp_parse_64k` (symbol extractor) | 200 | 190,045 | 344 MB/s |
| `push_u64_x1000` (2-digit LUT + branchless len) | 1,600 | 6,526 | 6.5 ns/int |
| `store_cache_hit` (64-shard `FastHashMap` + stat) | 12,800 | 1,320 | 1.32 µs/hit |
| `allowlist_admit_file` (lexical + canonicalize) | 1,600 | 7,601 | 7.60 µs/admit |

### 2. Concurrent TCP daemon waves (`ctx-bench waves --agents 1,10,50,100,200 --ops 25`)

32 worker threads, 64 cache shards, keep-alive RPC, competing same-role capsules:

| Agents | Total ops | ops/sec | p50 (µs) | p95 (µs) | p99 (µs) | Cache hit | Iso errs | Capsules OK | Misdelivery / Miss / Busy |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 25 | 1,948 | 449 | 500 | 677 | 72.8% | 0 | 1 | 0 / 0 / 0 |
| 10 | 250 | 8,697 | 888 | 2,416 | 4,014 | 96.7% | 0 | 10 | 0 / 0 / 0 |
| 50 | 1,250 | **11,649** | 2,690 | 10,550 | 14,222 | 99.3% | 0 | 50 | 0 / 0 / 0 |
| 100 | 2,500 | **11,207** | 4,889 | 22,602 | 30,947 | 99.7% | 0 | 100 | 0 / 0 / 0 |
| 200 | 5,000 | 7,416 | 7,589 | 77,683 | 292,159 | 99.8% | 0 | 200 | 0 / 0 / 0 |

### 3. 100-client concurrent 4-query search stress (400-file fixture)

| Scenario | Requests | Queries/req | OK | p50 (ms) | p95 (ms) | max (ms) | Peak subprocs |
|---|---:|---:|---:|---:|---:|---:|---:|
| `single-literal` | 30 | 4 | 30/30 | **0.620** | 0.733 | 0.778 | 0 |
| `single-regex` | 30 | 4 | 30/30 | 2.805 | 4.576 | 6.642 | 4 |
| `single-broad-regex` | 20 | 1 | 20/20 | 3.163 | 3.358 | 3.478 | 4 |
| `100-literal` | 100 | 4 | **100/100** | **17.648** | 30.351 | 33.309 | 4 |
| `100-regex` | 100 | 4 | **100/100** | 157.381 | 231.100 | 237.065 | 16 |

## Reproduce

From the CTX root, run the separated `ctx-bench` binary directly or through the Python runner (zero model calls):

```bash
# Build both `ctx` and `ctx-bench`
cargo build --release --bins

# 1–200 concurrent agent TCP daemon waves
./target/release/ctx-bench waves --ctx-bin ./target/release/ctx --agents 1,10,50,100,200 --ops 25

# In-process hot-kernel microbenchmarks (AVX2 search/scan, hashing, JSON, C++ parser, RAM store)
./target/release/ctx-bench micro --iters 200

# Unified runner (auto-falls back to 2-step bare `rustc` when Cargo is unavailable)
python3 -B benchmarks/run_benchmark.py --synthetic-only --micro
```

The same runner accepts a list of live Antigravity tasks through
`--tasks-json`. Each entry specifies a question and the expected source
anchors:

```json
[
  {
    "id": "method_definition",
    "question": "Find the exact file and line that defines targetMethod.",
    "anchors": [["MyModule.cpp", ["MyModule::targetMethod("]]]
  }
]
```

```bash
python3 -B benchmarks/run_benchmark.py --workspace /path/to/repo \
  --tasks-json tasks.json --agy-model gemini-4-neon-xhigh
```
