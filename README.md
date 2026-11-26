# CTX

CTX is a local MCP server and CLI for finding source lines, symbols, and file
outlines. Codex and Antigravity can share one RAM cache and workspace memo board.
Each client session tracks its own reads.

## Install

Linux, macOS, or WSL:

```bash
curl -fsSL https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.ps1 | iex
```

Select your clients in the setup menu, or configure both with
`ctx install --targets antigravity,codex`. Run `ctx doctor` to check the setup.

## Connect

For direct tool access in Codex 0.172.0, use this in the trusted workspace or
user `config.toml`, then start a new session:

```toml
[mcp_servers.agent_ctx]
command = "ctx"
args = ["mcp"]
omit_tools_from = ["deferred", "code_mode"]
```

Antigravity uses the eager core tools with
`ctx install --targets antigravity --eager=core`.

## Search a batch

```bash
ctx search -q 'PositionTable:applyFillHot' \
  -q 'StartupStreamBoundary:userDataSubscribedBeforeSnapshot' \
  --max-results 3 --max-bytes 2048
```

The MCP equivalent is `ctx_search` with a `q` array of up to four scoped
queries. `max_results` limits hits per query. `max_bytes` limits the entire
UTF-8 answer and defaults to 8192. Use `ctx help` for the CLI commands.

## Benchmark highlights

Two-turn real-session navigation benchmark on Antigravity (`agy --sandbox --mode plan`,
850-file tracked repository snapshot), comparing built-in local search/reads (**Native**,
zero MCP servers) against **CTX v2.4.0 MCP** (4 core eager tools: `ctx_search`, `ctx_read`,
`ctx_symbols`, `ctx_inspect`, isolated cold-start RAM daemon, AVX2+BMI1 in-RAM engine).
Each model runs a cold-cache 4-anchor task (**Cold**, Turn 1) followed by a 2-anchor
follow-up in the exact same conversation via `--resume` (**Warm**, Turn 2) on the warmed
LLM prompt cache and CTX RAM daemon.

### Native vs CTX — Full session totals (Cold + Warm)

| Model | Route | Exact `file:line` | Wall time | Full input | Uncached input | Cached input (LLM hit %) | Output (thinking) | Tool calls | CTX MCP time |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Gemini 4 Neon (High)** | Native | 6/6 | 81.6 s | 247,973 | 66,303 | 181,670 (73.3%) | 4,622 (3,334) | 10 | — |
| **Gemini 4 Neon (High)** | **CTX** | **6/6** | **64.7 s (−20.7%)** | **130,649 (−47.3%)** | **31,601 (−52.3%)** | 99,048 (**75.8%**) | 5,127 (4,361) | **6 (−40.0%)** | **41.9 ms** |
| **Gemini 4 Neon (XHigh)** | Native | 6/6 | 163.7 s | 413,869 | 77,927 | 335,942 (81.2%) | 14,655 (13,373) | 14 | — |
| **Gemini 4 Neon (XHigh)** | **CTX** | **6/6** | **160.6 s (−1.9%)** | **132,153 (−68.1%)** | **30,570 (−60.8%)** | 101,583 (76.9%) | **13,788** (13,279) | **4 (−71.4%)** | **29.8 ms** |
| **Gemini 4 Carbon (High)** | Native | 6/6 | 266.1 s | 356,019 | 117,902 | 238,117 (66.9%) | 14,037 (12,744) | 13 | — |
| **Gemini 4 Carbon (High)** | **CTX** | **6/6** | **252.4 s (−5.2%)** | **208,318 (−41.5%)** | **44,215 (−62.5%)** | 164,103 (**78.8%**) | 22,703 (21,863) | **6 (−53.8%)** | **39.6 ms** |

### Cold (Turn 1) vs Warm (Turn 2, same conversation & warmed cache)

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

Across all three models, CTX matched **18/18** exact `file:line` anchors, reduced full
input tokens by **53.7%** (**2.16×** less), uncached input tokens by **59.4%** (**2.46×**
less), tool calls by **56.8%** (**2.31×** fewer), and total wall time by **6.6%** while
spending only **29.8–41.9 ms** total inside MCP (daemon RSS **6.5–7.5 MiB**). On warmed
follow-up turns, every model finished in **1** CTX call (**8.3–8.5 ms**) with **72.0%**
lower input (**3.57×** less), **82.0%** lower uncached input (**5.55×** less), and
**45.8%** faster wall time (**1.84×**).

[Load & microbenchmarks](benchmarks/README.md) ·
[Releases](https://github.com/be0hhh/ctx-mcp/releases)
