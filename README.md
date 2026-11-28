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

### Additional Verified Suites (`v2.5.0` – `v2.5.5`, 100% Pass, `0` Failed Edits)

| Suite | Scope & Verification | Native → CTX | Quota / Context Highlight |
|---|---|---|---|
| **Multi-Agent Swarm (`v2.5.5`)** | `10 / 50 / 100` concurrent agents across `8` linked git worktrees (`ctx-bench swarm`, `201` files, **`0` errors**) | **`2,210 ops/s`** @ 100 agents (`p50 14.3 ms`) · **flat `2,880 KiB` RAM** across all 8 worktrees (`1×` dedup) | **`−93.6%…−93.8%`** swarm payload (`−85.2%` offline vs Naive / `−81.4%` vs `v2.5.2`) |
| **Live 8-Agent 3-Level Hierarchy A/B (`v2.5.5`)** | `1` Root (MCP) → `2` Squad Leads (CLI) → `4` Executors (CLI) → `1` Cross-Boundary Reviewer (CLI), all `Neon XHigh` (`16/16` sessions, `16/16` exact `file:line`) | `read_file`: **`57 → 2` (−96.5%)** (`0` on Executors & Reviewer) · **Uncached input: −42.1%** · **API-weighted input cost: −30.3%** | **`~51.5%`** less dynamic code context · `0/101` CLI truncations on `read`/`inspect`/`sym`/`search` · **`0`** `ALREADY IN CONTEXT` |
| **Live 10-Agent Parallel MCP A/B (`v2.5.3`)** | `10` parallel AGY `Neon High` workers (`20/20` sessions, `100%` exact `file:line`) | `read_file`: **`20 → 0` (−100%)** · Uncached input: **−22.1%** · Full input: **−12.6%** · Output: **−8.1%** | Wall **−3.6%**, `14` `ctx` calls, ~**50%** less dynamic code context per wave |
| **`ctx diag -- <cmd>` (Deterministic)** | 6 payloads (Clang, cargo, pytest, syslog, JSON, CMake), **6/6** | **`375,634 B → 2,937 B`** (**−99.2%**, **128×**) | **~93,174** tokens saved in **`35.45 ms`** |
| **`ctx diag -- <cmd>` (Blind Live LLM)** | AGY `Neon XHigh` + Codex `Astra XHigh`, **4/4** | AGY: **−75.4%** input, **−45.0%** wall, `7 → 1` calls · Codex: **−52.0%** input, **−78.1%** uncached | **−51%…−57%** total quota (AGY) · **−60%…−66%** total quota (Codex) |
| **Atomic Edit & Refactor** | 5 models (`cpp_sig_edit` + `py_refactor`), **20/20**, **0** failed edits | **−31.0%** calls (**−58.1%** Codex: `43 → 18`) · **−45.4%** Codex payload | Up to **−42.0%** input & **−31.9%** wall (`Neon High` `py_refactor`) |
| **Polyglot 6-Task** | Rust, Go, JSON/TOML/MD, Config+Docs, Script `creates`+`edits`, Shared Pack (**24/24**, **0** failed edits) | Codex: **−48.1%** calls (`54 → 28`) · AGY: **−23.8%** calls (`42 → 32`) | `script_create_edit`: **−67%** calls / **−35%** input / **−32%** wall; `docs_json_nav`: `5 → 1` (`1.1 ms`) |
| **In-RAM Engine & Load (`v2.5.5`)** | 19 AVX2 kernels + `1–200` concurrent agents (`ctx-bench`, `64` workers / `1024` queue) | **34.7 GB/s** CI search · **13,443 ops/s** @ 10 · **11,851 ops/s** @ 100 · **11,444 ops/s** @ 200 | **99.8%** RAM hit rate, **`71.4 ms`** p99 @ 200 agents (**3.9×** vs v2.5.0), **`0`** errors |

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

### Live Multi-Agent & Hierarchical Swarm A/B (`v2.5.3` – `v2.5.5`)

- **8-Agent 3-Level Hierarchy (`v2.5.5`, `Gemini 4 Neon XHigh`, `16/16` sessions, `100%` exact `file:line`):** `1` Root Orchestrator (MCP, publishes `pack:hier-root`) → `2` Squad Leads (CLI `ctx`, publish squad packs) → `4` Executors (CLI `ctx`, 12 anchors) → `1` Final Cross-Boundary Reviewer (CLI `ctx`, 4 anchors) sharing one isolated `ctx` daemon across an overlapping 75-file C++ subsystem.
- **10-Agent Parallel MCP (`v2.5.3`, `Gemini 4 Neon High`, `20/20` sessions, `100%` exact `file:line`):** 10 concurrent sessions solving distinct two-anchor lookups over one shared `ctx` daemon.

| Benchmark & Arm | Exact `file:line` | **Uncached input** | Cached input | Weighted input\* | Output (thinking) | **`read_file`** | **`ctx` calls** | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **8-Agent 3-Level (`Neon XHigh`) · Native** | 16/16 | 569,482 | 435,827 | 613,065 | 60,887 (48,736) | 57 | 0 | 304.7 s |
| **8-Agent 3-Level (`Neon XHigh`) · CTX `v2.5.5`** | **16/16** | **329,878 (−42.1%)** | 973,166 | **427,195 (−30.3%)** | 84,059 (63,027) | **2 (−96.5%)** | 137 (12 MCP + 125 CLI) | 579.1 s |
| **10-Agent Parallel (`Neon High`) · Native** | 20/20 | 233,511 | 129,866 | 246,498 | 19,155 (15,958) | 20 | 0 | 32.3 s |
| **10-Agent Parallel (`Neon High`) · CTX `v2.5.3`** | **20/20** | **182,006 (−22.1%)** | 135,481 | **195,554 (−20.7%)** | **17,597 (−8.1%)** (14,761) | **0 (−100.0%)** | **14** (MCP) | **31.2 s (−3.6%)** |

<sub>*Weighted input = `uncached + 0.10× cached`. In the 8-agent hierarchy, uncached input dropped at every level (**W1 Root −53.5%**, **W2 Leads −39.7%**, **W3 Executors −33.9%**, **W4 Reviewer −47.2%**); excluding ~104k fixed host prompt tokens across 8 sessions, dynamic code context fell **~51.5%** (`~465k → ~226k`) with `0` `ALREADY IN CONTEXT` retries and `0/101` truncations on `ctx read`/`inspect`/`sym`/`search`.*</sub>

## Where CTX Wins (and Honest Trade-Offs)

- **Fixed session cost:** loading all 11 MCP tool definitions adds **~6.4 KB** once per conversation (in Antigravity, `--eager=core` loads 8 tools and `--eager=search` loads 1).
- **Vs. an already-targeted native lookup (`git grep` + exact-line `Read`):** per-hit byte size is roughly even (`−20%` to `+5%`). CTX does not magically compress a line you already know the exact start and end of.
- **CLI-only swarm workers vs. MCP wall time:** on hosts where subagent workers lack MCP and invoke `ctx` through a terminal tool (`run_command`), shell/hook spawn overhead (`~2–4 s`/call) adds wall time if workers issue many small single-symbol CLI commands instead of batching (`ctx sym "A#x" "B#y" "C#z"`). Even then, uncached code context drops **−42.1%** (**−30.3%** API-weighted input cost, **−96.5%** `read_file`), while MCP sessions match or beat native wall time (**−3.6%** on 10 parallel agents).
- **Where CTX actually delivers large savings:**
  - **Unknown symbol boundaries & whole-file reads:** agents natively guess line offsets or read whole files; `ctx_symbols` knows exact `[L_start-L_end]` spans (**−94% to −98%** vs. full-file reads, saving 1–2 tool calls per lookup).
  - **Callers & impact (`ctx_impact`):** **−55%** vs. raw `git grep` + reads, with edit-ready line hashes and git badges in 1 call.
  - **Repeated unchanged reads:** hooks block duplicate full-file re-reads (**−97%**) and emit session deltas on small edits.
  - **Noisy command/log/JSON output (`ctx diag -- <cmd>`):** **128×** smaller (`−52%…−75%` live LLM input tokens).
  - **Atomic edits & multi-agent packs (`ctx_edit`, `ctx_memo`):** zero blind full-file rewrites, worktree-unified `ChangeFeed` & `1×` RAM dedup across linked git worktrees, and `[UNCHANGED]` Shared Context Pack dedup (`<= 32` selectors/pack) across subagents.

[Full Benchmarks, Edit/Polyglot & Load Results](benchmarks/README.md) ·
[Manual Setup & CLI](setup/README.md) ·
[Releases & Changelog](https://github.com/be0hhh/ctx-mcp/releases)
