# CTX Benchmarks (`v2.5.0` – `v2.5.5`)

Headline positioning, quota-drain summary, and full-session Native vs CTX totals are in the
[main README](../README.md#savings-at-a-glance-native-vs-ctx-v250).
Sections 1–4 report verified `v2.5.0` single-agent baselines; Sections 5–6 report verified **`v2.5.3` – `v2.5.5`** Fat-LTO load, hot-kernel, `10–100` agent multi-worktree swarm, live 8-agent 3-level hierarchical MCP+CLI A/B, and live 10-agent parallel MCP A/B runs (`0` `.unwrap()`/`.expect()` in production, `0` `div`/`idiv`, `0` failed edits).

## 1. Cold (Turn 1) vs Warm (Turn 2) Navigation (`30/30` exact `file:line`)

Two-turn real-session navigation on an isolated 850-file tracked snapshot:
- **Cold (Turn 1):** 4-anchor cross-module task on a fresh conversation and fresh cold `ctx daemon` (0 cached files).
- **Warm (Turn 2):** 2-anchor follow-up in the exact same conversation (`agy --resume` / `codex exec resume`) on the warmed LLM prompt cache and warmed `ctx` RAM daemon.

### Antigravity (`agy --sandbox --mode plan`, 4 core eager tools)

| Model | Phase | Route | Wall time | Input (Δ vs Native) | Uncached (Δ vs Native) | LLM cache hit | CTX RAM hit | Tool calls | MCP ms | RSS |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Neon High** | Cold | Native | 55.1 s | 60,789 | 31,137 | 48.8% | — | 6 | — | — |
| **Neon High** | Cold | **CTX** | **49.7 s (−9.9%)** | **31,262 (−48.6%)** | **16,685 (−46.4%)** | 46.6% | **71.4% (15/21)** | **1** | **9.2** | 6.4 MiB |
| **Neon High** | Warm | Native | 18.9 s | 112,704 | 8,758 | 92.2% | — | 3 | — | — |
| **Neon High** | Warm | **CTX** | 25.2 s (+33.6%) | **71,120 (−36.9%)** | 10,798 (+23.3%) | 84.8% | **82.7% (105/127)** | **2** | **11.5** | 6.9 MiB |
| **Neon XHigh** | Cold | Native | 124.6 s | 114,986 | 48,491 | 57.8% | — | 8 | — | — |
| **Neon XHigh** | Cold | **CTX** | **105.3 s (−15.5%)** | **54,460 (−52.6%)** | **14,848 (−69.4%)** | **72.7%** | **84.6% (33/39)** | **3** | **16.5** | 6.8 MiB |
| **Neon XHigh** | Warm | Native | 24.3 s | 183,174 | 27,033 | 85.2% | — | 3 | — | — |
| **Neon XHigh** | Warm | **CTX** | 48.5 s (+99.5%) | **104,884 (−42.7%)** | **15,963 (−40.9%)** | 84.8% | **87.1% (148/170)** | 3 | **25.6** | 7.4 MiB |
| **Carbon High** | Cold | Native | 188.7 s | 109,660 | 52,526 | 52.1% | — | 8 | — | — |
| **Carbon High** | Cold | **CTX** | 326.8 s (+73.2%) | **55,035 (−49.8%)** | **22,347 (−57.5%)** | **59.4%** | **78.6% (22/28)** | **3** | **16.8** | 6.9 MiB |
| **Carbon High** | Warm | Native | 27.5 s | 215,380 | 24,264 | 88.7% | — | 4 | — | — |
| **Carbon High** | Warm | **CTX** | 102.5 s (+272.7%) | **140,657 (−34.7%)** | 50,969 (+110.1%) | 63.8% | **84.3% (118/140)** | **2** | **17.9** | 7.7 MiB |

### Codex (`codex-cli`, `exec` → `exec resume`, direct MCP)

| Model | Phase | Route | Wall time | Input (Δ vs Native) | Uncached | LLM cache hit | Output | Tool calls | Tool bytes | CTX RAM hit | MCP ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Astra XHigh** | Cold | Native | 13.2 s | 42,868 | 11,252 | 73.8% | 476 | 1 | 25,384 B | — | — |
| **Astra XHigh** | Cold | **CTX** | 19.0 s (+44.1%) | 58,038 (+35.4%) | 11,574 | **80.1%** | 540 | 2 | **2,976 B (−88.3%)** | **82.4% (28/34)** | **14.5** |
| **Astra XHigh** | Warm | Native | 14.8 s | 121,227 | 13,707 | 88.7% | 268 | 3 | 8,109 B | — | — |
| **Astra XHigh** | Warm | **CTX** | 19.0 s (+28.8%) | **119,250 (−1.6%)** | **12,754** | **89.3%** | 384 | **2** | **1,617 B (−80.1%)** | **77.5% (31/40)** | **16.6** |
| **Astra Max** | Cold | Native | 27.5 s | 61,196 | 15,116 | 75.3% | 1,197 | 4 | 38,849 B | — | — |
| **Astra Max** | Cold | **CTX** | **24.7 s (−10.3%)** | 77,822 (+27.2%) | **11,646** | **85.0%** | **1,054** | **3** | **3,299 B (−91.5%)** | **82.4% (28/34)** | **11.1** |
| **Astra Max** | Warm | Native | 29.4 s | 166,762 | 17,130 | 89.7% | 1,474 | 6 | 5,451 B | — | — |
| **Astra Max** | Warm | **CTX** | **16.6 s (−43.4%)** | **140,371 (−15.8%)** | **13,139** | **90.6%** | **798** | **2** | **1,825 B (−66.5%)** | **66.2% (43/65)** | **16.1** |

- **Aggregate (all 5 models, `30/30` exact `file:line`):** Tool calls **`46 → 23` (−50.0%)**, Full input **`−28.3%`** (**−42.6%** AGY), Uncached **`−27.5%`** (**−51.4%** Cold), LLM cache hit **59.3% → 72.1%** Cold (**85.4% → 87.6%** Codex), CTX RAM hit **81.8%** (`571/698`), Codex tool payload **`77,793 B → 9,717 B` (−87.5%, 8.0×)**, Est. input quota drain **−28%** (**−35%…−38%** AGY; **−47%…−48%** Neon).

## 2. Universal `ctx diag` v2 Compression (Deterministic + Blind Live LLM)

### Deterministic 6-payload benchmark (`ctx_diag_bench.py --deterministic`)

| Payload | Raw bytes | Compressed bytes | Saved | Est. tokens saved | Time | Result |
|---|---:|---:|---:|---:|---:|---:|
| `clang_template_cascade` | 40,996 | 464 | **98.9%** | 10,133 | 1.27 ms | PASS |
| `cargo_test_failure` | 26,460 | 496 | **98.1%** | 6,491 | 6.72 ms | PASS |
| `pytest_deep_frames` | 20,623 | 410 | **98.0%** | 5,053 | 6.21 ms | PASS |
| `journalctl_syslog_burst` | 182,947 | 850 | **99.5%** | 45,524 | 8.46 ms | PASS |
| `json_api_buried_error` | 64,488 | 465 | **99.3%** | 16,006 | 6.93 ms | PASS |
| `cmake_ninja_ok_build` | 40,120 | 252 | **99.4%** | 9,967 | 5.86 ms | PASS |
| **TOTAL (6/6)** | **375,634** | **2,937** | **99.2% (128×)** | **~93,174** | **35.45 ms** | **PASS** |

### Blind Live LLM diagnosis (`raw_bash` vs `ctx diag -- ./run_checks.sh`)

| Client & Model | Route | Verified | Calls | Full input | Uncached input | Output | Wall time | Est. quota drain |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **AGY · Neon XHigh** | `raw_bash` | PASS | 7 | 110,128 | 29,277 | 2,340 | 33.6 s | baseline |
| **AGY · Neon XHigh** | **`ctx diag`** | **PASS** | **1 (−85.7%)** | **27,134 (−75.4%)** | **16,009 (−45.3%)** | **1,473 (−37.1%)** | **18.5 s (−45.0%)** | **−51%…−57%** |
| **Codex · Astra XHigh** | `raw_bash` | PASS | 2 | 67,640 | 12,216 | 196 | 14.2 s | baseline |
| **Codex · Astra XHigh** | **`ctx diag`** | **PASS** | **1 (−50.0%)** | **32,502 (−52.0%)** | **2,678 (−78.1%)** | **164 (−16.3%)** | **11.9 s (−16.2%)** | **−60%…−66%** |

## 3. Atomic Multi-File Edit & Refactor (5 models, `20/20` verified, `0` failed edits)

Two multi-file tasks (`cpp_sig_edit` across C++ headers; `py_refactor` lexical rename + strict check + `__all__` re-export across Python modules):

| Client & Model | Task | Route | Verified | Calls | Full input | Uncached | Output | Wall time | Payload B | MCP ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Codex · Astra XHigh** | `cpp_sig_edit` | Native | PASS | 10 | 108,042 | 22,410 | 1,075 | 35.3 s | 28,811 | — |
| **Codex · Astra XHigh** | `cpp_sig_edit` | **CTX** | **PASS** | **3 (−70.0%)** | **82,221 (−23.9%)** | **22,317** | **978** | **31.5 s** | **12,759 (−55.7%)** | **80.0** |
| **Codex · Astra XHigh** | `py_refactor` | Native | PASS | 10 | 113,815 | 26,135 | 1,031 | 34.8 s | 35,547 | — |
| **Codex · Astra XHigh** | `py_refactor` | **CTX** | **PASS** | **6 (−40.0%)** | 136,273 | **13,009 (−50.2%)** | **936** | 39.8 s | **11,864 (−66.6%)** | **92.8** |
| **Codex · Astra Max** | `cpp_sig_edit` | Native | PASS | 11 | 119,474 | 12,594 | 2,281 | 60.0 s | 29,135 | — |
| **Codex · Astra Max** | `cpp_sig_edit` | **CTX** | **PASS** | **4 (−63.6%)** | **118,454** | 26,678 | 3,047 | 70.4 s | **26,984** | **79.8** |
| **Codex · Astra Max** | `py_refactor` | Native | PASS | 12 | 123,346 | 15,314 | 3,478 | 77.4 s | 44,666 | — |
| **Codex · Astra Max** | `py_refactor` | **CTX** | **PASS** | **5 (−58.3%)** | 135,827 | 16,403 | **3,450** | 80.1 s | **23,808 (−46.7%)** | **88.4** |
| **AGY · Neon High** | `cpp_sig_edit` | Native | PASS | 7 | 127,289 | 36,060 | 8,688 | 71.3 s | — | — |
| **AGY · Neon High** | `cpp_sig_edit` | **CTX** | **PASS** | 7 | 179,008 | 42,606 | 9,135 | 83.7 s | 37,520 | **88.5** |
| **AGY · Neon High** | `py_refactor` | Native | PASS | 12 | 194,654 | 31,389 | 9,848 | 98.7 s | — | — |
| **AGY · Neon High** | `py_refactor` | **CTX** | **PASS** | **8 (−33.3%)** | **112,927 (−42.0%)** | **30,192** | **7,320** | **67.2 s (−31.9%)** | 15,543 | **89.9** |
| **AGY · Neon XHigh** | `cpp_sig_edit` | Native | PASS | 8 | 140,440 | 30,849 | 14,582 | 121.3 s | — | — |
| **AGY · Neon XHigh** | `cpp_sig_edit` | **CTX** | **PASS** | 9 | 197,110 | 34,756 | 15,541 | 129.0 s | 35,739 | **122.8** |
| **AGY · Neon XHigh** | `py_refactor` | Native | PASS | 13 | 209,285 | 49,116 | 15,275 | 135.0 s | — | — |
| **AGY · Neon XHigh** | `py_refactor` | **CTX** | **PASS** | **10 (−23.1%)** | 213,758 | **33,905 (−31.0%)** | 18,041 | 167.7 s | 31,139 | **138.4** |
| **AGY · Carbon High** | `cpp_sig_edit` | Native | PASS | 10 | 195,715 | 42,161 | 17,187 | 180.4 s | — | — |
| **AGY · Carbon High** | `cpp_sig_edit` | **CTX** | **PASS** | **9 (−10.0%)** | 280,539 | 78,637 | **16,440** | 186.5 s | 52,969 | **116.9** |
| **AGY · Carbon High** | `py_refactor` | Native | PASS | 20 | 496,214 | 70,619 | 29,050 | 347.3 s | — | — |
| **AGY · Carbon High** | `py_refactor` | **CTX** | **PASS** | **17 (−15.0%)** | **431,589 (−13.0%)** | 78,224 | 38,358 | 524.6 s | 39,076 | **208.5** |

- **Totals (`20/20` verified, `0` failed edits):** Tool calls **`113 → 78` (−31.0%)** (`43 → 18` = **−58.1%** on Codex; `70 → 60` = **−14.3%** on AGY); Codex payload **`138.2 KB → 75.4 KB` (−45.4%)**; average MCP latency **`14.2 ms/call`**.

## 4. Polyglot 6-Task Suite (`24/24` verified, `0` failed edits)

| Model | Task | Route | Calls | Full input | Uncached | Output | Wall time | MCP ms |
|---|---|---|---:|---:|---:|---:|---:|---:|
| **Codex · Astra XHigh** | `rust_edit` | Native → **CTX** | 12 → **6 (−50%)** | 138.0k → 193.8k | 27.4k → 32.9k | 1,527 → **888 (−41.8%)** | 44.0 → 45.1 s | 15.6 |
| **Codex · Astra XHigh** | `go_edit` | Native → **CTX** | 9 → **8** | 140.8k → 292.5k | 26.9k → 33.1k | 1,632 → 2,465 | 50.1 → 66.7 s | 14.4 |
| **Codex · Astra XHigh** | `docs_json_nav` | Native → **CTX** | 5 → **3 (−40%)** | 43.0k → 90.8k | 8.1k → 15.9k | 518 → **494** | 18.0 → 20.2 s | 9.0 |
| **Codex · Astra XHigh** | `config_docs_edit` | Native → **CTX** | 6 → **4 (−33%)** | 98.8k → 127.7k | 12.4k → 20.3k | 755 → **616 (−18.4%)** | 25.2 → **24.5 s** | 7.8 |
| **Codex · Astra XHigh** | `script_create_edit` | Native → **CTX** | 12 → **4 (−67%)** | 184.6k → **120.2k (−34.9%)** | 15.0k → 18.3k | 623 → **417 (−33.1%)** | 29.9 → **20.5 s (−31.5%)** | 11.2 |
| **Codex · Astra XHigh** | `shared_pack_rules` | Native → **CTX** | 10 → **3 (−70%)** | 68.9k → 97.4k | 11.5k → 19.9k | 747 → **640 (−14.3%)** | 23.2 → 23.6 s | 8.2 |
| **AGY · Neon XHigh** | `rust_edit` | Native → **CTX** | 11 → **8 (−27%)** | 322.6k → **167.2k (−48.2%)** | 49.2k → **44.4k** | 12,129 → **12,124** | 115.8 → **109.9 s** | 19.0 |
| **AGY · Neon XHigh** | `go_edit` | Native → **CTX** | 10 → 12 | 130.7k → 244.8k | 33.0k → 57.5k | 12,513 → 16,543 | 94.2 → 131.1 s | 21.1 |
| **AGY · Neon XHigh** | `docs_json_nav` | Native → **CTX** | 5 → **1 (−80%)** | 48.0k → **42.7k (−11.0%)** | 19.1k → 22.4k | 3,000 → 3,262 | 32.6 → **29.5 s** | **1.1** |
| **AGY · Neon XHigh** | `config_docs_edit` | Native → **CTX** | 7 → **5 (−29%)** | 105.3k → 141.0k | 22.3k → 35.1k | 7,785 → **5,261 (−32.4%)** | 67.8 → **50.4 s (−25.6%)** | 10.3 |
| **AGY · Neon XHigh** | `script_create_edit` | Native → **CTX** | 5 → **2 (−60%)** | 84.4k → **69.9k (−17.2%)** | 16.6k → 25.9k | 3,182 → 3,846 | 38.3 → **35.0 s** | **2.4** |
| **AGY · Neon XHigh** | `shared_pack_rules` | Native → **CTX** | 4 → 4 | 60.5k → 96.9k | 31.6k → **30.4k** | 3,155 → 4,756 | 26.9 → 46.9 s | 3.8 |

- **Totals (`24/24` verified, `0` failed edits):** Codex tool calls **`54 → 28` (−48.1%)** (`2.36 ms/call` MCP); AGY tool calls **`42 → 32` (−23.8%)** (`1.80 ms/call` MCP).

## 5. Load & Hot-Kernel Results (`v2.5.5`)

Measured on Linux x86-64 (AMD Ryzen 5 5600X, AVX2 + BMI1, `RUSTFLAGS="-C target-cpu=native"`, release Fat-LTO, `0` hardware `div`/`idiv`, `0` `.unwrap()`/`.expect()` in production).

### In-process hot kernels (`ctx-bench micro --iters 200`, 19 kernels)

| Kernel | Iterations | ns/op | Throughput |
|---|---:|---:|---:|
| `search_ascii_ci_256k` (AVX2+BMI1 inline fold) | 200 | 7,553 | **34,711 MB/s** |
| `search_exact_256k` (AVX2+BMI1 zero-spill) | 200 | 8,259 | **31,746 MB/s** |
| `fast_hash64_256k` (2-way ILP 32B fold) | 800 | 18,097 | **14,488 MB/s** |
| `scan_source_256k` (2-phase AVX2+BMI1) | 200 | 25,110 | **10,442 MB/s** |
| `line_hash3_4k_lines` (3-hex content anchors) | 200 | 35,118 | **7,845 MB/s** |
| `json_encode_64k` (single-pass AVX2 stream) | 200 | 15,385 | **4,477 MB/s** |
| `json_parse_64k` (SIMD escape-free slice) | 200 | 22,113 | **3,115 MB/s** |
| `trigram_bloom_6paths` (256B LUT) | 12,800 | 141 | **1,878 MB/s** |
| `clean_code_buf_256k` (AVX2+SSE2 delimiter scrubber) | 200 | 187,346 | **1,400 MB/s** |
| `search_rank_spread` (multi-file scoring & selection) | 200 | 26,818 | **628 MB/s** |
| `content_bloom128_256k` (in-RAM 128-bit ASCII-lower bloom) | 400 | 447,960 | **585 MB/s** |
| `cpp_parse_64k` (symbol extractor) | 200 | 161,737 | **405 MB/s** |
| `sha256_hex_256k` (pure-Rust SHA-256) | 200 | 712,117 | 368 MB/s |
| `diag_json_compact_256k` (large JSON/NDJSON schema + error compactor) | 100 | 1,072,920 | 244 MB/s |
| `compact_md_json_64k` (lossless Markdown/JSON/YAML compactor) | 200 | 328,727 | 198 MB/s |
| `diag_log_compress_256k` (SIMD ANSI/CR + template dedup) | 100 | 2,302,263 | 113 MB/s |
| `push_u64_x1000` (2-digit LUT + branchless len) | 1,600 | 7,185 | 7.2 ns/int |
| `store_cache_hit` (64-shard `FastHashMap` + stat) | 12,800 | 3,949 | 3.95 µs/hit |
| `allowlist_admit_file` (lexical + canonicalize) | 1,600 | 8,246 | 8.25 µs/admit |

### Concurrent TCP daemon waves (`ctx-bench waves --agents 1,10,50,100,200 --ops 20`)

64 worker threads, 1024 accept queue, 64 cache shards, keep-alive RPC (`BenchConn`), competing same-role capsules:

| Agents | Total ops | ops/sec | p50 (µs) | p95 (µs) | p99 (µs) | Cache hit | RPC / Iso errs | Capsules OK | Misdelivery / Miss / Busy |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 20 | 2,424 | **256** | 1,164 | 1,164 | 78.6% | 0 / 0 | 1 | 0 / 0 / 0 |
| 10 | 200 | **13,443** | **435** | 1,456 | 4,126 | 95.3% | 0 / 0 | 10 | 0 / 0 / 0 |
| 50 | 1,000 | 11,232 | 1,840 | 18,117 | 22,985 | 99.0% | 0 / 0 | 50 | 0 / 0 / 0 |
| 100 | 2,000 | **11,851** | 2,976 | 25,549 | 40,336 | 99.6% | 0 / 0 | 100 | 0 / 0 / 0 |
| 200 | 4,000 | **11,444** | 7,876 | **50,100** | **71,441** | **99.8%** | **0 / 0** | **200** | **0 / 0 / 0** |

## 6. Multi-Agent Swarm Scaling & Live Hierarchical A/B (`v2.5.3` – `v2.5.5`)

### Tier 1A — Isolated Daemon Swarm Replay (`ctx-bench swarm --agents 10,50,100 --worktrees 8`, 0 LLM tokens, `v2.5.5`)

Measured on an isolated 201-file C++/Rust corpus (`32` files `>=350L`) cloned into a temporary Git repository with **`8` real linked `git worktree`s** sharing one `ctx` daemon (scout publishes Shared Context Pack + memos → `N` concurrent workers run `SessionStart` pack auto-materialization, 4-query batch `search` coalescing, `PreToolUse read_file` Large-Read Gate, cross-worktree `symbols`, `pack_get` dedup, `memo list`, `impact`, `git`, and concurrent edit `ChangeFeed` + `[STALE]` verification):

| Agents | ops/sec | p50 ms | p95 ms | p99 ms | Errors | Large-Read redirects | Pack dedup hits | Cross-WT memos | ChangeFeed visible | Stale detected | **RAM (8 worktrees)** | Peak subprocs | **Payload saved** |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|---:|---:|---:|
| **10** | 1,523 | 3.66 | 19.00 | 23.57 | **0** | 10/10 | 10/10 | 10/10 | 9/9 | Yes | **2,880 KiB** | 8 | **93.8%** |
| **50** | 1,973 | 8.68 | 53.46 | 72.06 | **0** | 50/50 | 50/50 | 50/50 | 49/49 | Yes | **2,880 KiB** | 16 | **93.7%** |
| **100** | **2,210** | **14.29** | 118.75 | 242.92 | **0** | 100/100 | 100/100 | 100/100 | 99/99 | Yes | **2,880 KiB** | 16 | **93.6%** |

- **Flat RAM across 8 linked worktrees:** `ParsedBody` content-addressed deduplication keeps total daemon RAM identical (`2,880 KiB`) across `10`, `50`, and `100` agents spanning all `8` worktrees (`1×` storage instead of `8×`).

### Tier 1B — Offline Multi-Agent Context Replay (`160` source files, `23 >= 350L`, 71.8% inter-agent file overlap)

| Agents | Naive `read_file` | CTX `v2.5.2` | **CTX `v2.5.5`** | Saved vs Naive | Saved vs `v2.5.2` |
|---:|---:|---:|---:|---:|---:|
| **10** | 805.1 KB (~206k tok) | 650.0 KB | **122.2 KB (~31k tok)** | **84.8%** | **81.2%** |
| **50** | 4,071.3 KB (~1.04M tok) | 3,241.8 KB | **601.9 KB (~154k tok)** | **85.2%** | **81.4%** |
| **100** | 8,138.2 KB (~2.08M tok) | 6,470.6 KB | **1,201.5 KB (~308k tok)** | **85.2%** | **81.4%** |

### Tier 2A — Live 8-Agent 3-Level Hierarchical Swarm A/B (`Gemini 4 Neon XHigh`, `16/16` sessions, `100.0%` exact `file:line`, `v2.5.5`)

Four-wave hierarchical benchmark over an isolated 75-file C++ multi-subsystem corpus (`1` Root Orchestrator → `2` parallel Squad Leads → `4` parallel Executors locating `12` exact anchors → `1` Final Cross-Boundary Reviewer verifying `4` cross-subsystem anchors = **`16` exact verifiable `file:line` targets per arm**):
- **`baseline_nomcp`:** all 8 `Neon XHigh` agents use native `read_file` (zero MCP, zero `ctx` hooks).
- **`multiagent` (`v2.5.5`):** models real Antigravity swarm topology 1:1 — **Wave 1 Root** uses 8 eager MCP tools + hooks and publishes `pack:hier-root` (`16` selectors); **Waves 2–4** (2 Squad Leads, 4 Executors, 1 Final Reviewer) run as **CLI-only workers** (empty MCP, `PreToolUse` `AGENT_CTX_CLI_TOKEN` + `9.2 KiB` AGY CLI inline cap + squad Shared Context Packs `squad-runtime` & `squad-exchange`) sharing one isolated `ctx v2.5.5` daemon.

| Wave (`Gemini 4 Neon XHigh`) | Native uncached | **CTX `v2.5.5` uncached** | Uncached delta | Native `read_file` | **CTX `read_file`** | CTX calls | Exact `file:line` |
|---|---:|---:|---:|---:|---:|---:|---:|
| **W1 Root (`1` MCP)** | 131,734 | **61,288** | **−53.5%** | 14 | **1** | 12 MCP | — |
| **W2 Squad Leads (`2` CLI)** | 144,459 | **87,083** | **−39.7%** | 14 | **1** | 32 CLI | — |
| **W3 Executors (`4` CLI)** | 200,295 | **132,450** | **−33.9%** | 17 | **0 (−100%)** | 63 CLI | **12/12 (100%)** |
| **W4 Cross-Boundary Review (`1` CLI)** | 92,994 | **49,057** | **−47.2%** | 12 | **0 (−100%)** | 30 CLI | **4/4 (100%)** |
| **Total (`8` agents / arm)** | **569,482** | **329,878** | **−42.1%** | **57** | **2 (−96.5%)** | **137** (12+125) | **16/16 (100%)** |

| Arm (`8` `Neon XHigh` agents) | Wall time | Full input | **Uncached input** | Cached input | Weighted input\* | Output (thinking) | **`read_file`** | `ALREADY IN CONTEXT` | `read`/`inspect`/`sym`/`search` truncations | Exact `file:line` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **`baseline_nomcp`** | 304.7 s | 1,005,309 | 569,482 | 435,827 | 613,065 | 60,887 (48,736) | 57 | 0 | — | 16/16 (100%) |
| **`multiagent` (`v2.5.5`)** | 579.1 s | 1,303,044 | **329,878 (−42.1%)** | 973,166 | **427,195 (−30.3%)** | 84,059 (63,027) | **2 (−96.5%)** | **0** | **0 / 101** | **16/16 (100%)** |

<sub>*Weighted input = `uncached + 0.10× cached`. Excluding ~104k fixed host system prompt tokens across 8 sessions, dynamic code context dropped **~51.5%** (`~465k → ~226k`). Wall time on CLI-only workers reflects host shell/hook PTY overhead (~2–4 s per `run_command` across 125 fine-grained CLI calls); batching multiple symbols per `ctx sym` call or using MCP eliminates this overhead (see Tier 2B).*</sub>

### Tier 2B — Live 10-Agent Parallel MCP Antigravity A/B (`Gemini 4 Neon High`, `20/20` sessions, `100.0%` exact `file:line`, `v2.5.3`)

Ten parallel headless Antigravity (`agy`) sessions solving distinct two-anchor read-only audit tasks over an isolated C++ subsystem (`unshare` bind-mounted isolated `mcp_config.json` and `hooks.json` per arm):
- **`baseline_nomcp`:** native `read_file` without MCP or `ctx` hooks (modeling pre-upgrade swarm workers).
- **`multiagent` (`v2.5.3`):** `8` core eager MCP tools, `AGENT_CTX_LARGE_READ_LINES=350`, shared `ctx` daemon, symbol-first workflow.

| Arm (`10` parallel Neon High agents) | Wall time | Full input | Uncached input | Cached input | Output (thinking) | `read_file` calls | `ctx` calls | Exact `file:line` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **`baseline_nomcp`** | 32.30 s | 363,377 | 233,511 | 129,866 | 19,155 (15,958) | 20 | 0 | 20/20 (100.0%) |
| **`multiagent` (`v2.5.3`)** | **31.15 s (−3.6%)** | **317,487 (−12.6%)** | **182,006 (−22.1%)** | 135,481 (+4.3%) | **17,597 (−8.1%)** (14,761) | **0 (−100.0%)** | **14** | **20/20 (100.0%)** |

<sub>*Across 10 separate sessions, ~130k of uncached input is the fixed host system prompt; dynamic code context ingested into the model dropped by ~50% (`~103k → ~52k` uncached) even on short two-anchor lookups, with zero `read_file` calls and 100% citation accuracy.*</sub>

## Reproduce

From the CTX root, run the separated `ctx-bench` binary directly or through the Python runner (zero model calls):

```bash
# Build both `ctx` and `ctx-bench` (or compile bare `rustc --edition 2021 -D warnings -O src/main.rs`)
cargo build --release --bins

# 1–200 concurrent agent TCP daemon waves
./target/release/ctx-bench waves --ctx-bin ./target/release/ctx --agents 1,10,50,100,200 --ops 20

# 10–100 agent multi-worktree swarm replay (cloned temp repo + 8 linked worktrees, zero live mutations)
./target/release/ctx-bench swarm --ctx-bin ./target/release/ctx --repo . --agents 10,50,100 --worktrees 8

# In-process hot-kernel microbenchmarks (19 kernels)
./target/release/ctx-bench micro --iters 200

# Unified runner (auto-falls back to 2-step bare `rustc` when Cargo is unavailable)
python3 -B benchmarks/run_benchmark.py --synthetic-only --micro
```
