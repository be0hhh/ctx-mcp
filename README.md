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

### Additional Verified Suites (`v2.5.0` – `v2.5.3`, 100% Pass, `0` Failed Edits)

| Suite | Scope & Verification | Native → CTX | Quota / Context Highlight |
|---|---|---|---|
| **Multi-Agent Swarm (`v2.5.3`)** | `10 / 50 / 100` concurrent agents across `8` linked git worktrees (`ctx-bench swarm`, `201` files, **`0` errors**) | **`1,532 ops/s`** @ 100 agents · **flat `2,847 KiB` RAM** across all 8 worktrees (`1×` dedup) | **`−93.6%…−93.7%`** swarm payload (`−84.2%` offline vs Naive / `−80.3%` vs `v2.5.2`) |
| **Live 10-Agent Parallel A/B (`v2.5.3`)** | `10` parallel AGY `Neon High` workers (`20/20` sessions, `100%` exact `file:line`) | `read_file`: **`20 → 0` (−100%)** · Uncached input: **−22.1%** · Full input: **−12.6%** · Output: **−8.1%** | Wall **−3.6%**, `14` `ctx` calls, ~**50%** less dynamic code context per wave |
| **`ctx diag -- <cmd>` (Deterministic)** | 6 payloads (Clang, cargo, pytest, syslog, JSON, CMake), **6/6** | **`375,634 B → 2,937 B`** (**−99.2%**, **128×**) | **~93,174** tokens saved in **`35.45 ms`** |
| **`ctx diag -- <cmd>` (Blind Live LLM)** | AGY `Neon XHigh` + Codex `Astra XHigh`, **4/4** | AGY: **−75.4%** input, **−45.0%** wall, `7 → 1` calls · Codex: **−52.0%** input, **−78.1%** uncached | **−51%…−57%** total quota (AGY) · **−60%…−66%** total quota (Codex) |
| **Atomic Edit & Refactor** | 5 models (`cpp_sig_edit` + `py_refactor`), **20/20**, **0** failed edits | **−31.0%** calls (**−58.1%** Codex: `43 → 18`) · **−45.4%** Codex payload | Up to **−42.0%** input & **−31.9%** wall (`Neon High` `py_refactor`) |
| **Polyglot 6-Task** | Rust, Go, JSON/TOML/MD, Config+Docs, Script `creates`+`edits`, Shared Pack (**24/24**, **0** failed edits) | Codex: **−48.1%** calls (`54 → 28`) · AGY: **−23.8%** calls (`42 → 32`) | `script_create_edit`: **−67%** calls / **−35%** input / **−32%** wall; `docs_json_nav`: `5 → 1` (`1.1 ms`) |
| **In-RAM Engine & Load (`v2.5.3`)** | 19 AVX2 kernels + `1–200` concurrent agents (`ctx-bench`, `64` workers / `1024` queue) | **34.7 GB/s** CI search · **13,664 ops/s** @ 10 · **11,616 ops/s** @ 200 agents | **99.8%** RAM hit rate, **`84.9 ms`** p99 @ 200 agents (**3.3×** vs v2.5.0), **`0`** errors |

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

## What's New in `v2.5.3`

- **Worktree-unified broker & content-addressed RAM deduplication (`1×` memory across `K` worktrees):** `shared_repo_key` unifies `MemoBoard`, `PackStore`, and `ChangeFeed` across a repository and its linked `git worktree`s using bidirectional backlink verification (with symlink-spoofing protection and full `v3` `memos.json` compatibility). Immutable file contents, line offsets, and symbol tables now live in content-addressed `Arc<ParsedBody>` entries keyed by `(hash64, size, parser_kind, clean_lang)` with exact byte-equality checks and exact refcounted RAM accounting — keeping daemon memory flat (`2,847 KiB` across `8` linked worktrees at `10`, `50`, and `100` agents).
- **In-flight search coalescing, 2s `mutation_epoch` micro-cache & fair-share CLI batch budgets:** concurrent identical searches coalesce into a single scan (`Arc<SearchHitSet>`, panic-safe RAII waiters, errors never cached, instant invalidation on `mutation_epoch` bump). CLI batch searches (`3–6` `-q` queries) auto-scale to `12 KiB` (`14 KiB` cap) with two-pass zero-div fair-share section quotas so trailing queries never starve, while Antigravity MCP retains its hard `<= 9,000 B` inline cap.
- **Active Antigravity adoption across MCP, headless/swarm CLI workers, and hooks:**
  - `--eager=core` now exposes **8** core tools (`ctx_search`, `ctx_inspect`, `ctx_read`, `ctx_symbols`, `ctx_impact`, `ctx_memo`, `ctx_git`, `ctx_edit`), preserving explicit user `{"eager": false}` overrides on upgrade.
  - Reusable `300s` **`CliLease`** tokens and quote/comment/`$'...'`-aware `PreToolUse` `run_command` injection (strictly `decision: "ask"` + `overwrite`, preserving all arguments and CLI budgets/cwd) bring session dedup, delta reads, and trusted authorship to CLI-only swarm workers.
  - **1-Strike Large-Read Symbol-First Gate** (`AGENT_CTX_LARGE_READ_LINES`, default `350`, `0` disables): intercepts full-file `read_file` on `>=350L` code files (`>=4` non-namespace symbols, never docs/configs), returning a compact RAM outline (`<=24` symbols), secret-filtered `[untrusted memo]` notes, and channel-accurate `ctx sym`/`ctx_symbols` commands with `SessionState`-backed 1-strike escape; auto-widen narrowed to `<=300L && <=16KB`.
  - **1-Strike allowlist read-only `git` redirect** (`git status`, `git diff`, `git log`, `git show`, passing through `-C`/`--porcelain`/ranges/paths/pipes), **KV-cache-safe `fork` detection** (skips duplicate `[RAM-Ctx Startup]` on forked workers), fail-closed native-edit `PostToolUse` `ChangeFeed` recording, and `4,000 B` `SessionStart` with automatic `pack:<slug>` materialization (`<=2` packs, `<=1,800 B`).
- **100–200 agent scaling & `ctx-bench swarm`:** daemon scales to `64` worker threads (`16` keep-alive waiters), `1024` accept queue, `2048` pack dedup slots, `1024` ChangeFeed ring (`64` workspaces), `16 MiB` / `256`-entry delta cache, and `8192` dedup ring — verified with `156/156` Rust tests and the new `ctx-bench swarm` multi-worktree replay suite (`11,616 ops/s`, `p99 84.9 ms`, `0` errors @ `200` agents in `ctx-bench waves`).

## What's New in `v2.5.1` – `v2.5.2`

- **Bulletproof search without system `rg` (zero silent false `0 matches`):** `ctx` resolves `PATH`, OS package directories, and bundled IDE/Claude `rg` binaries without permanently caching misses (installing `rg` works immediately without restarting the daemon), falls back to `.gitignore`-aware `git grep` and then a nested-`.git`-skipping BFS walker, and explicitly flags `(INCOMPLETE scan)` if a fallback file budget is ever hit. `WorkspaceIndex` (`ctx_impact`, shorthand paths) also uses `git ls-files` / nested-`.git` filtering, and `ctx doctor` reports `search_backend`.
- **Unrestricted batch search (`1–6` unscoped or scoped), workspace `grep`/`rg` 1-strike redirect & resilient cold startup:** `ctx_search(q=[...])` accepts up to `6` unscoped, scoped, or mixed queries in one round-trip; `PreToolUse` hooks (`agy`, `codex`, `claude`) gently redirect bare workspace `grep`/`rg` commands (1-strike escape, leaving external paths like `~/.codex/`/`/tmp/` and pipelines untouched — helping even pre-upgrade chats switch to `ctx_search`); and cold daemon auto-spawn waits up to `1s` (`10ms` fast polls) so loaded hosts don't drop turn-0 hooks.
- **Better `ctx_outline` & Rust `ctx_symbols`:** single-file `ctx_outline` is bounded only by `max_bytes` (no hardcoded 80-symbol cap; optional `max_symbols` for multi-file control). In Rust, `ctx_symbols("File.rs#Type")` returns the type definition plus a 1-line `impl` summary (`#impl:Type` and `#Type::method` fetch implementations directly), and `compact=true` raises its preview cap from `24L` to `48L` while full symbol body is now the recommended default.
- **Fast ETag checks & verified auto-patch updates (`ctx update --auto`):** `ctx daemon` checks GitHub Releases every `30 min` using conditional HTTP `ETag` (`304 Not Modified`, zero rate-limit burn). Upstream builds default to `auto=patch` (auto-installing `X.Y.Z` patch releases only after pure-Rust FIPS 180-4 SHA-256 + pre-swap `mcp --protocol-check` + `ctx.bak` backup + graceful daemon hot-swap; minor/major remain notify-only; custom flavors like `ctx-cxet` are never overwritten). Notices are strictly user-only advisories; opt out anytime via `ctx update --auto off` or `AGENT_CTX_NO_UPDATE_CHECK=1`.

## Where CTX Wins (and Honest Trade-Offs)

- **Fixed session cost:** loading all 11 MCP tool definitions adds **~6.4 KB** once per conversation (in Antigravity, `--eager=core` loads 8 tools and `--eager=search` loads 1).
- **Vs. an already-targeted native lookup (`git grep` + exact-line `Read`):** per-hit byte size is roughly even (`−20%` to `+5%`). CTX does not magically compress a line you already know the exact start and end of.
- **Where CTX actually delivers large savings:**
  - **Unknown symbol boundaries & whole-file reads:** agents natively guess line offsets or read whole files; `ctx_symbols` knows exact `[L_start-L_end]` spans (**−94% to −98%** vs. full-file reads, saving 1–2 tool calls per lookup).
  - **Callers & impact (`ctx_impact`):** **−55%** vs. raw `git grep` + reads, with edit-ready line hashes and git badges in 1 call.
  - **Repeated unchanged reads:** hooks block duplicate full-file re-reads (**−97%**) and emit session deltas on small edits.
  - **Noisy command/log/JSON output (`ctx diag -- <cmd>`):** **128×** smaller (`−52%…−75%` live LLM input tokens).
  - **Atomic edits & multi-agent packs (`ctx_edit`, `ctx_memo`):** zero blind full-file rewrites and `[UNCHANGED]` dedup across subagents.

## What's New in `v2.5.0`

- **Universal `ctx diag` v2:** Clang/GCC/Rust/Python/TS/Go/MSVC/CMake/ld/lld/test runners + AVX2/SSE2 ANSI/CR scrubbing + template deduplication for Linux/server logs + large JSON/NDJSON schema & error compactor.
- **Atomic `ctx_edit` upgrades & `ctx_git`:** atomic `creates` (with `executable: true`, full `overwrite` rollback, TOCTOU path admission), `verify_absent`, `ctx_git` `stat: true` + automatic conflict-marker scan (`<<<<<<< ` / `>>>>>>> `).
- **Deep Docs/Config/Infra indexing & Shared Context Packs:** hierarchical Markdown `H1..H4`, deep JSON/YAML dotted paths & array-object indexing (`name|id|tool|title`), `Makefile`/`Dockerfile` outlines, lossless compaction, and Shared Context Packs in `ctx_memo` (`pack`/`pack_get`/`packs`) + `ctx_capsule` (`pack_refs`) with per-session `[UNCHANGED]` dedup.
- **SIMD & In-RAM durability:** AVX2+SSE2 code scrubber (`3.14×` faster, `1,455 MB/s`), 128-bit in-RAM trigram bloom prefilter (`610 MB/s`), daemon git-recency background pre-warm, strict memory bounds across all caches/tables, host-aware AGY `<= 9 KB` hard-clamp, and `0` `.unwrap()`/`.expect()`/`div`/`idiv` in production.
- **Verified self-update & cross-platform helpers:** `ctx update [--check|--rebuild|--force]` with pure-Rust FIPS 180-4 SHA-256 verification and custom-flavor protection, `ctx --version`, plus native OS RAM budget detection and hidden Windows subprocess spawning.

[Full Benchmarks, Edit/Polyglot & Load Results](benchmarks/README.md) ·
[Manual Setup & CLI](setup/README.md) ·
[Releases](https://github.com/be0hhh/ctx-mcp/releases)
