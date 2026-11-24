# `ctx-mcp` — Zero-Dependency In-RAM Context Broker & MCP Server

[![CI](https://github.com/be0hhh/ctx-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/be0hhh/ctx-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/be0hhh/ctx-mcp)](https://github.com/be0hhh/ctx-mcp/releases/latest)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)

`ctx-mcp` (`ctx`) is a single-binary, zero-dependency Rust `std` Context Broker and Model Context Protocol (MCP) server for AI coding agents (**Google Antigravity**, **Claude Code**, and **Codex CLI**).

It keeps a shared 64-shard cache-line-padded in-RAM file & structural symbol index across parallel agents (up to `4 GiB` LRU), executes batched AVX2-accelerated searches (`q: ["Module:pattern", ...]`) with automatic `.hpp`/`.cpp`/module stem expansion, deduplicates repeated reads per agent session, and enforces strict workspace + secret-file boundaries (`.env*`, `*.pem`, `*.key`).

Dual-licensed under **MIT OR Apache-2.0**. Zero external Rust crates (`Cargo.toml` has `0` dependencies).

---

## One-Command Install (No Rust Required)

Paste **one command** in your terminal. It automatically downloads the verified prebuilt binary for your OS/CPU (or compiles from source in ~2s if `rustc` is installed and no release asset matches) and opens a lightweight **interactive harness selector**:

### Linux / macOS / WSL2
```bash
curl -fsSL https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.sh | bash
```

### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.ps1 | iex
```

### Node / `npx` (Cross-Platform)
```bash
npx github:be0hhh/ctx-mcp
```

### Interactive Setup Menu
When `install` runs in your terminal, `ctx setup` scans which AI clients are installed on your machine and opens a quick selector:

```text
  ctx-mcp setup — select AI harnesses to configure:
    [x] 1. Antigravity (Gemini)   [detected]   * Recommended (-45% time, -38% new tokens)
    [x] 2. Claude Code            [detected]   * Recommended
    [ ] 3. Codex CLI (GPT/Sol)    [detected]   (off by default: deferred MCP token overhead)

  Press Enter to confirm, type 1/2/3 to toggle (or 'all' / 'none' / 'q' to cancel):
```

- Non-interactive / CI install:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.sh | bash -s -- --targets antigravity,claude
  ```
- Re-run harness selector anytime: `ctx setup`
- Verify health & `0600` security invariants: `ctx doctor`

---

## Uninstall

Remove `ctx-mcp` (stops the background daemon, cleanly removes `agent_ctx` MCP & hook entries while preserving all other MCP servers/hooks and `.bak` backups, and deletes `~/.local/bin/ctx`):

```bash
ctx uninstall
```

- Detach from a single harness only (e.g., disable Codex while keeping Antigravity & Claude):
  ```bash
  ctx uninstall --targets codex
  ```
- Standalone terminal one-liners if `~/.local/bin` is not in `PATH`:
  - **Linux / macOS / WSL2:** `curl -fsSL https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/uninstall.sh | bash`
  - **Windows (PowerShell):** `irm https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/uninstall.ps1 | iex`

---

## Benchmarks: Direct (`rg`) vs `ctx-mcp`

> **Methodology & Transparency:** Measured on a ~1,800-file C++26 & Python repository across **5 independent 4-anchor navigation tasks** (`20` ground-truth `file:line` targets per wave, run in 5-way parallel waves).
> - **Gemini in Antigravity shows a large, consistent improvement** across wall-clock time, tool round-trips, payload size, and token consumption.
> - **Codex CLI (`GPT-6.2 Sol`) is reported honestly alongside it:** while `ctx-mcp` is slightly faster in wall-clock time and returns `-41.9%` smaller tool outputs, Codex CLI's deferred MCP loader injects a hidden `tool_search` API turn (`~16k–32k` cached tokens), increasing total input tokens on 1-step lookups. For that reason, **Codex CLI is unchecked by default** in `ctx setup`.
> - The live-model sample is currently compact (`20` end-to-end runs + synthetic `1–200` agent stress waves) and is actively expanding in [`benchmarks/`](benchmarks/).

### 1. Google Antigravity — `Gemini 4 Carbon (Low)` (5 Parallel Tasks)

| Metric | Direct (`rg`) | `ctx-mcp` | Delta (abs.) | Delta (%) |
|---|---:|---:|---:|---:|
| Ground-truth `file:line` accuracy | `20 / 20` (`100%`) | `20 / 20` (`100%`) | `0` | `0.0%` |
| 5-task parallel wave wall-clock, s | `42.22` | `20.35` | `-21.87` | **`-51.8%`** |
| Task duration (mean), s | `31.40` | `17.35` | `-14.05` | **`-44.7%`** |
| Task duration (median), s | `33.40` | `17.02` | `-16.38` | **`-49.0%`** |
| Task duration (sum across 5 tasks), s | `156.99` | `86.77` | `-70.22` | **`-44.7%`** |
| Tool calls (mean / sum) | `2.80` (`14`) | `1.00` (`5`) | `-1.80` (`-9`) | **`-64.3%`** |
| Tool execution time (mean), ms | `2,512.93` | `979.93` | `-1,533.00` | **`-61.0%`** |
| Tool output payload (sum), bytes | `11,443` | `7,513` | `-3,930` | **`-34.3%`** |
| **Uncached (new) input tokens (sum)** | `122,134` | `75,152` | `-46,982` | **`-38.5%`** |
| Cached input tokens (sum) | `164,015` | `122,395` | `-41,620` | **`-25.4%`** |
| Total input tokens (sum) | `286,149` | `197,547` | `-88,602` | **`-31.0%`** |
| Output tokens (sum) | `2,776` | `2,139` | `-637` | **`-22.9%`** |
| **Total tokens (sum across 5 tasks)** | `288,925` | `199,686` | `-89,239` | **`-30.9%`** |

### 2. Codex CLI — `GPT-6.2 Sol (Low)` (5 Parallel Tasks — Honest Baseline)

| Metric | Direct (`rg`) | `ctx-mcp` | Delta (abs.) | Delta (%) |
|---|---:|---:|---:|---:|
| Ground-truth `file:line` accuracy | `20 / 20` (`100%`) | `20 / 20` (`100%`) | `0` | `0.0%` |
| 5-task parallel wave wall-clock, s | `17.77` | `16.88` | `-0.89` | **`-5.0%`** |
| Task duration (mean / median), s | `16.20` / `16.32` | `15.28` / `15.14` | `-0.92` / `-1.18` | **`-5.7%` / `-7.2%`** |
| Tool calls (mean / sum) | `1.40` (`7`) | `1.00` (`5`) | `-0.40` (`-2`) | **`-28.6%`** |
| Median `ctx` search wire latency, ms | — *(shell)* | **`1.23`** | — | — |
| Tool output payload (sum), bytes | `11,058` | `6,425` | `-4,633` | **`-41.9%`** |
| Uncached (new) input tokens (sum) | `90,485` | `92,774` | `+2,289` | `+2.5%` |
| Cached input tokens (sum)\* | `288,256` | `385,664` | `+97,408` | `+33.8%` |
| Output tokens (sum) | `1,213` | `1,545` | `+332` | `+27.4%` |
| **Total tokens (sum across 5 tasks)**\* | `379,961` | `479,983` | `+100,022` | `+26.3%` |

*\*Codex CLI loads external MCP schemas through a deferred `tool_search` round-trip (`3` API turns instead of `2` on 1-call tasks), adding ~19k cached tokens per task when compared against raw shell-only `codex exec` with zero MCP servers configured.*

### 3. Shared Daemon Multi-Agent Load (`ctx bench --agents 1,10,50,100,200 --ops 25`)

| Concurrent Agents | Total Ops | Throughput (`ops/sec`) | `p50` | `p95` | `p99` | Isolation / RPC Errors |
|---:|---:|---:|---:|---:|---:|---:|
| `1` | `25` | `1,780` | `0.49 ms` | `0.61 ms` | `0.79 ms` | `0` |
| `10` | `250` | `8,602` | `0.89 ms` | `2.07 ms` | `3.78 ms` | `0` |
| `50` | `1,250` | `10,343` | `2.88 ms` | `14.18 ms` | `27.51 ms` | `0` |
| `100` | `2,500` | `10,555` | `5.51 ms` | `20.62 ms` | `44.43 ms` | `0` |
| `200` | `5,000` | `12,551` | `8.30 ms` | `50.15 ms` | `93.13 ms` | `0` |

---

## Ergonomic Batch Format (`q` + Grouped `@symbol` Output)

Every `ctx_*` MCP tool accepts flat string arrays so agents emit minimal output tokens and finish in a single round-trip:

```json
{
  "q": [
    "PositionTable:applyfill",
    "StartupStreamBoundary:userdata|subscrib",
    "AccountObservationExtractor:::fetchStartupSnapshotCold"
  ]
}
```

- **Bare module stems** (`"StartupStreamBoundary"`) automatically resolve to both `.hpp` and `.cpp` via `WorkspaceFiles` stem hashing without path-discovery calls.
- **Fair code-first quota:** round-robin slot balancing across matched files ensures header comments never starve `.cpp` implementations.
- **Adaptive grouped output:** 1 match emits `path:line: code`; `2+` matches print the file path once with compact `@symbol` subheaders:
  ```text
  src/src/Runtime/Hot/Position/PositionTable.hpp
    @canApplyFillHot
    145: [[nodiscard]] CXET_ALWAYS_INLINE bool canApplyFillHot(
    @applyFillHot
    168: [[nodiscard]] CXET_ALWAYS_INLINE bool applyFillHot(
    179: if (bytescan::hftUnlikely(!states_[instId].applyFillHot(
  ```

---

## MCP Tools & CLI Reference

| MCP Tool | CLI Equivalent | Purpose |
|---|---|---|
| `ctx_search` | `ctx search -q "Mod:pat"` | Parallel AVX2/ripgrep search (`1–4` queries in `q`, `8 KiB` cap, smart-case) |
| `ctx_inspect` | `ctx inspect <dir...>` | Batch directory triage (`<=80` files, line counts, `[OVER 800L]`, `#include`, symbols) |
| `ctx_symbols` | `ctx sym <Mod#Sym> --compact` | Exact symbol body extraction (`compact=true`: `<=24` lines + continuation slice) |
| `ctx_read` | `ctx read <path[:s-e]>` | Full-file or range read from RAM up to `1 MiB` (no 800-line truncation) |
| `ctx_outline` | `ctx outline <path...>` | Structural `[L_start-L_end]` symbol spans |
| `ctx_memo` | `ctx memo <put\|get\|list>` | Shared workspace findings board with automatic `[STALE]` FNV-1a tracking |
| `ctx_capsule` | `ctx capsule <prepare\|claim>` | Host-verified subagent task capsule handoff |
| `ctx_elf_audit` | `ctx elf --elf <bin>` | Optional static ELF64 section/symbol audit |

## Security & Architecture Guarantees

- **Strict workspace & secret refusal:** symlinks escaping the workspace root and secret files (`.env*`, `*.pem`, `*.key`, credentials) fail closed with `REFUSED`.
- **`0600` metadata-only reboot snapshot (`ACTXSNP2`):** stores file metadata/outlines only — **zero raw source code** is ever persisted to disk.
- **Data-oriented Rust `std` internals:** `0` `f32`/`f64` floats, `64 B` cache-line-aligned shard locks (`CachePadded<T>`), `48 B` `SymbolSpan`, `24 B` arena-backed `IndexedFile` with 64-bit trigram Bloom filter.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
