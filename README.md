# CTX

Local zero-dependency Rust MCP server, CLI & in-RAM code index for **Antigravity**,
**Codex**, and **Claude Code**. Cuts token burn, subscription quota drain, tool
calls, noisy command/log output, and navigation latency across C/C++, Rust,
Python, Java, C#, Go, TS/JS, Markdown, JSON, TOML, YAML, Makefile, and
Dockerfile.

## Why CTX Is Different (Data Protocol, Not Output Skin)

CTX is **not** a prompt-style text compressor (like *Caveman*) and **not** just a
terminal stdout wrapper (like *RTK* and similar CLI filters). Instead of changing
how the model talks or only trimming shell output after the fact, **CTX changes
how the AI agent interacts with workspace data itself**:

| Layer | Examples | What it optimizes | What stays untouched |
|---|---|---|---|
| **Output-style compression** | *Caveman* & terse prompts | Shortens the assistant's reply prose | Full-file reads, noisy searches, failed edits, raw logs |
| **CLI stdout wrappers** | *RTK* & terminal filters | Trims stdout of shell commands after execution | Code navigation, multi-file edits, cross-agent re-reads |
| **Data-access & edit protocol** | **CTX** | **Persistent in-RAM symbol/structure index, batched scoped search without full-file dumps, `ctx_impact` + content-hashed atomic `ctx_edit`, Shared Context Packs & per-session dedup across agents, plus built-in `ctx diag` for build/test/log/JSON streams** | Orthogonal to reply style (pairs cleanly with any prompt style) |

- **Zero external crates** (`std`-only; compiles with bare `rustc --edition 2021 -D warnings -O` or Cargo Fat-LTO)
- **Zero-panic production core** (`0` `.unwrap()`, `0` `.expect()`, `0` hardware `div`/`idiv` across `450` Fat-LTO functions)
- **11 write / 10 read-only MCP tools**, cross-platform (Linux, macOS, WSL, Windows), verified self-update (`ctx update`)

## Install

Linux, macOS, or WSL:

```bash
curl -fsSL https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.ps1 | iex
```

Already installed? Upgrade in-place with SHA-256 verification and zero agent restarts:

```bash
ctx update
```

The installer configures Antigravity, Codex, and Claude Code automatically.
For manual configs, flags, and CLI usage, see [setup/README.md](setup/README.md).

## Savings at a Glance (Native vs CTX `v2.5.0`)

Measured across 5 models in two-turn **Cold → Warm** sessions (`30/30` exact `file:line`, `0` errors):

| Metric | Antigravity (`Neon High/XHigh`, `Carbon High`) | Codex (`GPT-6.2 Astra XHigh/Max`) | All 5 models |
|---|---:|---:|---:|
| **Full input tokens** | **−42.6%** (**1.74×** less) | +0.9% (**−9.9%** Warm) | **−28.3%** (**1.39×** less) |
| **Uncached input tokens** | **−31.5%** (**−49.5%** Neon; **−59.2%** Cold / **2.45×**) | **−14.1%** (**−23.1%** on Max) | **−27.5%** (**−51.4%** Cold / **2.06×**) |
| **Warm turn input / uncached** | **−38.1%** (**1.61×**) / **−25.2%** on Neon | **−9.9%** / **−16.0%** | **−27.9%** (**1.39×**) |
| **LLM prompt cache hit** | **71.2%** (**80.7%** Neon XHigh; Cold **53.7% → 61.7%**) | **85.4% → 87.6%** (**88.6%** Max; **90.0%** Warm) | **78.8%** (Cold **59.3% → 72.1%**) |
| **CTX RAM cache hit** | **84.0%** (`441/525`, up to **86.6%**) | **75.1%** (`130/173`, **82.4%** Cold) | **81.8%** (`571/698`) |
| **Tool payload pushed to context** | Hard-capped `<= 9 KB` inline (`0` blind truncation) | **−87.5%** (**8.0×** less; **8.6×** on Max) | **~8×** cleaner context |
| **Tool calls** | **−56.2%** (**2.29×** fewer) | **−35.7%** (**−50.0%** on Max) | **−50.0%** (**2.00×** fewer) |
| **Output tokens** | +33.7% (model thinking variance) | **−18.7%** (**−30.7%** on Max) | — |
| **Est. input quota drain\*** | **−35%…−38%** (**−47%…−48%** Neon · **−56%…−58%** Cold) | **−4%…−8%** (**−11%…−13%** Warm) | **−28%** (**−41%…−47%** Cold) |
| **Est. total quota drain\*** | **−8%…−11%** (**−26%…−27%** on Neon High/XHigh) | **−5%…−9%** (**−13%…−15%** Warm) | **−8%…−10%** (compounds over 10+ turns) |
| **CTX MCP overhead** | **20.7–42.1 ms** total (`6.8–7.7 MiB` RAM) | **27.3–31.0 ms** total (`6.8 MiB` RAM) | **< 43 ms** / session |

<sub>*Weighted token-cost estimate: **input quota** = `1.0× uncached + 0.10–0.25× cached`; **total quota** adds `4.0–5.0× output`. In long multi-turn chats, avoiding full-file dumps compounds savings on every follow-up turn and delays context compaction.*</sub>

### Additional Verified Suites (`v2.5.0`, 100% Pass, `0` Failed Edits)

| Suite | Scope & Verification | Native → CTX (`v2.5.0`) | Quota / Context Highlight |
|---|---|---|---|
| **`ctx diag -- <cmd>` (Deterministic)** | 6 payloads (Clang, cargo, pytest, syslog, JSON, CMake), **6/6** | **`375,634 B → 2,937 B`** (**−99.2%**, **128×**) | **~93,174** tokens saved in **`35.45 ms`** |
| **`ctx diag -- <cmd>` (Blind Live LLM)** | AGY `Neon XHigh` + Codex `Astra XHigh`, **4/4** | AGY: **−75.4%** input, **−45.0%** wall, `7 → 1` calls · Codex: **−52.0%** input, **−78.1%** uncached | **−51%…−57%** total quota (AGY) · **−60%…−66%** total quota (Codex) |
| **Atomic Edit & Refactor** | 5 models (`cpp_sig_edit` + `py_refactor`), **20/20**, **0** failed edits | **−31.0%** calls (**−58.1%** Codex: `43 → 18`) · **−45.4%** Codex payload | Up to **−42.0%** input & **−31.9%** wall (`Neon High` `py_refactor`) |
| **Polyglot 6-Task** | Rust, Go, JSON/TOML/MD, Config+Docs, Script `creates`+`edits`, Shared Pack (**24/24**, **0** failed edits) | Codex: **−48.1%** calls (`54 → 28`) · AGY: **−23.8%** calls (`42 → 32`) | `script_create_edit`: **−67%** calls / **−35%** input / **−32%** wall; `docs_json_nav`: `5 → 1` (`1.1 ms`) |
| **In-RAM Engine & Load** | 19 AVX2 kernels + `1–200` concurrent agents (`ctx-bench`) | **42.8 GB/s** search · **1,455 MB/s** SIMD clean (**3.14×**) · **11,182 ops/s** @ 100 agents | **99.9%** RAM hit rate, **`4.71 ms`** p50, **`0`** iso errs @ 200 agents |

## Native vs CTX — Full Session Totals (Cold + Warm)

Two-turn navigation benchmark on an isolated 850-file repo: **Cold** 4-anchor task (Turn 1) + **Warm** 2-anchor follow-up (Turn 2 via `--resume` / `codex exec resume`), comparing built-in search/reads (**Native**, zero MCP) against **CTX v2.5.0**.

| Client & Model | Route | Exact `file:line` | Wall time | Full input | Uncached input | LLM cache hit | CTX RAM hit | Output (thinking) | Tool calls | CTX MCP time |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **AGY · Gemini 4 Neon (High)** | Native | 6/6 | 74.0 s | 173,493 | 39,895 | 77.0% | — | 5,922 (4,723) | 9 | — |
| **AGY · Gemini 4 Neon (High)** | **CTX** | **6/6** | 74.9 s (+1.2%) | **102,382 (−41.0%)** | **27,483 (−31.1%)** | 73.2% | **81.1% (120/148)** | 7,166 (6,685) | **3 (−66.7%)** | **20.7 ms** |
| **AGY · Gemini 4 Neon (XHigh)** | Native | 6/6 | 148.9 s | 298,160 | 75,524 | 74.7% | — | 17,742 (16,515) | 11 | — |
| **AGY · Gemini 4 Neon (XHigh)** | **CTX** | **6/6** | 153.8 s (+3.3%) | **159,344 (−46.6%)** | **30,811 (−59.2%)** | **80.7%** | **86.6% (181/209)** | 18,408 (17,695) | **6 (−45.5%)** | **42.1 ms** |
| **AGY · Gemini 4 Carbon (High)** | Native | 6/6 | 216.2 s | 325,040 | 76,790 | 76.4% | — | 17,733 (16,595) | 12 | — |
| **AGY · Gemini 4 Carbon (High)** | **CTX** | **6/6** | 429.4 s (+98.6%) | **195,692 (−39.8%)** | **73,316 (−4.5%)** | 62.5% | **83.3% (140/168)** | 29,792 (29,098) | **5 (−58.3%)** | **34.7 ms** |
| **Codex · GPT-6.2 Astra (XHigh)** | Native | 6/6 | 27.9 s | 164,095 | 24,959 | 84.8% | — | 744 (0) | 4 | — |
| **Codex · GPT-6.2 Astra (XHigh)** | **CTX** | **6/6** | 38.0 s (+36.0%) | 177,288 (+8.0%) | **24,328 (−2.5%)** | **86.3%** | **79.7% (59/74)** | 924 (198) | 4 (0.0%) | **31.0 ms** |
| **Codex · GPT-6.2 Astra (Max)** | Native | 6/6 | 56.9 s | 227,958 | 32,246 | 85.9% | — | 2,671 (1,232) | 10 | — |
| **Codex · GPT-6.2 Astra (Max)** | **CTX** | **6/6** | **41.3 s (−27.4%)** | **218,193 (−4.3%)** | **24,785 (−23.1%)** | **88.6%** | **71.7% (71/99)** | **1,852 (−30.7%)** (1,066) | **5 (−50.0%)** | **27.3 ms** |

### Blind Live `ctx diag` v2 (`raw_bash` vs `ctx diag -- ./run_checks.sh`)

| Client & Model | Route | Verified | Tool calls | Full input | Uncached input | Output | Wall time | Est. quota drain\* |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **AGY · Gemini 4 Neon (XHigh)** | `raw_bash` | PASS | 7 | 110,128 | 29,277 | 2,340 | 33.6 s | baseline |
| **AGY · Gemini 4 Neon (XHigh)** | **`ctx diag`** | **PASS** | **1 (−85.7%)** | **27,134 (−75.4%, 4.1×)** | **16,009 (−45.3%)** | **1,473 (−37.1%)** | **18.5 s (−45.0%)** | **−51%…−57%** |
| **Codex · GPT-6.2 Astra (XHigh)** | `raw_bash` | PASS | 2 | 67,640 | 12,216 | 196 | 14.2 s | baseline |
| **Codex · GPT-6.2 Astra (XHigh)** | **`ctx diag`** | **PASS** | **1 (−50.0%)** | **32,502 (−52.0%, 2.1×)** | **2,678 (−78.1%, 4.6×)** | **164 (−16.3%)** | **11.9 s (−16.2%)** | **−60%…−66%** |

## What's New in `v2.5.0`

- **Universal `ctx diag` v2:** Clang/GCC/Rust/Python/TS/Go/MSVC/CMake/ld/lld/test runners + AVX2/SSE2 ANSI/CR scrubbing + template deduplication for Linux/server logs + large JSON/NDJSON schema & error compactor.
- **Atomic `ctx_edit` upgrades & `ctx_git`:** atomic `creates` (with `executable: true`, full `overwrite` rollback, TOCTOU path admission), `verify_absent`, `ctx_git` `stat: true` + automatic conflict-marker scan (`<<<<<<< ` / `>>>>>>> `).
- **Deep Docs/Config/Infra indexing & Shared Context Packs:** hierarchical Markdown `H1..H4`, deep JSON/YAML dotted paths & array-object indexing (`name|id|tool|title`), `Makefile`/`Dockerfile` outlines, lossless compaction, and Shared Context Packs in `ctx_memo` (`pack`/`pack_get`/`packs`) + `ctx_capsule` (`pack_refs`) with per-session `[UNCHANGED]` dedup.
- **SIMD & In-RAM durability:** AVX2+SSE2 code scrubber (`3.14×` faster, `1,455 MB/s`), 128-bit in-RAM trigram bloom prefilter (`610 MB/s`), daemon git-recency background pre-warm, strict memory bounds across all caches/tables, host-aware AGY `<= 9 KB` hard-clamp, and `0` `.unwrap()`/`.expect()`/`div`/`idiv` in production.
- **Verified self-update & cross-platform helpers:** `ctx update [--check|--rebuild|--force]` with pure-Rust FIPS 180-4 SHA-256 verification and custom-flavor protection, `ctx --version`, plus native OS RAM budget detection and hidden Windows subprocess spawning.

[Full Benchmarks, Edit/Polyglot & Load Results](benchmarks/README.md) ·
[Manual Setup & CLI](setup/README.md) ·
[Releases](https://github.com/be0hhh/ctx-mcp/releases)
