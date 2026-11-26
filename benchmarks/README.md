# CTX Benchmarks

Headline savings and full-session Native vs CTX totals are in the
[main README](../README.md#savings-at-a-glance-native-vs-ctx-v240).

## Cold (Turn 1) vs Warm (Turn 2) Breakdown (`v2.4.0`)

Two-turn real-session navigation on an isolated 850-file tracked snapshot:
- **Cold (Turn 1):** 4-anchor cross-module task on a fresh conversation and fresh cold `ctx daemon` (0 cached files).
- **Warm (Turn 2):** 2-anchor follow-up in the exact same conversation (`agy --resume` / `codex exec resume`) on the warmed LLM prompt cache and warmed `ctx` RAM daemon.

### Antigravity (`agy --sandbox --mode plan`, 4 core eager tools)

| Model | Phase | Route | Wall time | Input (Δ vs Native) | Uncached (Δ vs Native) | LLM cache hit | CTX RAM cache hit | Tool calls | MCP ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Neon High** | Cold | Native | 39.9 s | 98,444 | 39,081 | 60.3% | — | 7 | — |
| **Neon High** | Cold | **CTX** | 51.3 s (+28.6%) | **84,236 (−14.4%)** | **25,076 (−35.8%)** | **70.2%** | 78.6% (22/28) | **5** | 33.5 |
| **Neon High** | Warm | Native | 41.7 s | 149,529 | 27,222 | 81.8% | — | 3 | — |
| **Neon High** | Warm | **CTX** | **13.4 s (−67.9%)** | **46,413 (−69.0%)** | **6,525 (−76.0%)** | **85.9%** | 62.7% (37/59) | **1** | **8.5** |
| **Neon XHigh** | Cold | Native | 132.6 s | 154,780 | 46,879 | 69.7% | — | 9 | — |
| **Neon XHigh** | Cold | **CTX** | **103.2 s (−22.2%)** | **75,673 (−51.1%)** | **23,498 (−49.9%)** | 68.9% | 72.7% (16/22) | **3** | **21.3** |
| **Neon XHigh** | Warm | Native | 31.1 s | 259,089 | 31,048 | 88.0% | — | 5 | — |
| **Neon XHigh** | Warm | **CTX** | 57.4 s (+84.9%) | **56,480 (−78.2%)** | **7,072 (−77.2%)** | 87.5% | 74.1% (63/85) | **1** | **8.5** |
| **Carbon High** | Cold | Native | 158.5 s | 111,026 | 43,095 | 61.2% | — | 8 | — |
| **Carbon High** | Cold | **CTX** | 225.5 s (+42.2%) | 127,969 (+15.3%) | **33,827 (−21.5%)** | **73.6%** | 84.2% (32/38) | **5** | **31.3** |
| **Carbon High** | Warm | Native | 107.6 s | 244,993 | 74,807 | 69.5% | — | 5 | — |
| **Carbon High** | Warm | **CTX** | **26.9 s (−75.0%)** | **80,349 (−67.2%)** | **10,388 (−86.1%)** | **87.1%** | 62.7% (37/59) | **1** | **8.3** |

### Codex (`codex-cli 0.172.0`, `exec` → `exec resume`, direct MCP)

| Model | Phase | Route | Wall time | Input (Δ vs Native) | Uncached | Output | Tool calls | Tool bytes | CTX RAM hit | MCP ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Astra XHigh** | Cold | Native | 27.6 s | 81,451 | 8,747 | 477 | 5 | 20,723 B | — | — |
| **Astra XHigh** | Cold | **CTX** | **18.7 s (−32.2%)** | **76,332 (−6.3%)** | 11,180 | **321** | **3** | **2,833 B** | 77.8% (21/27) | **18.8** |
| **Astra XHigh** | Warm | Native | 18.0 s | 151,710 | 10,142 | 782 | 4 | 3,259 B | — | — |
| **Astra XHigh** | Warm | **CTX** | **13.4 s (−25.3%)** | **136,489 (−10.0%)** | 11,945 | **495** | **2** | **1,396 B** | 65.1% (41/63) | **15.5** |
| **Astra Max** | Cold | Native | 36.4 s | 65,088 | 14,400 | 1,377 | 4 | 44,643 B | — | — |
| **Astra Max** | Cold | **CTX** | **31.8 s (−12.7%)** | 76,798 (+18.0%) | **12,286** | **1,090** | **3** | **2,307 B** | 70.0% (14/20) | **17.8** |
| **Astra Max** | Warm | Native | 25.9 s | 155,723 | 16,075 | 2,012 | 4 | 4,150 B | — | — |
| **Astra Max** | Warm | **CTX** | **22.1 s (−14.5%)** | **138,827 (−10.9%)** | **12,875** | **1,660** | **2** | **1,001 B** | 40.5% (15/37) | **22.3** |

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
