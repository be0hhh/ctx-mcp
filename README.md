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

Two-turn real-session navigation benchmark on Antigravity (`agy --sandbox --mode plan`),
comparing built-in local search/reads (**Native**, zero MCP servers) against **CTX MCP**
(`ctx_search` / `ctx_symbols` with nested-dir & token root resolution and inline `@scope` hits).
Each model runs one cold-cache 4-anchor task (**Cold**, Turn 1) followed by a 2-anchor
follow-up in the exact same conversation via `--resume` (**Warm**, Turn 2) on the same
warmed LLM prompt cache and CTX RAM daemon.

### Full session totals (Cold + Warm)

| Model | Route | Exact `file:line` | Wall time | Full input | Uncached input | Cached input (LLM hit %) | Output (thinking) | Tool calls | CTX MCP time |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Gemini 4 Neon (High)** | Native | 6/6 | 141.2 s | 203,373 | 40,975 | 162,398 (79.9%) | 4,994 (3,992) | 10 | — |
| **Gemini 4 Neon (High)** | **CTX** | **6/6** | **73.5 s (−47.9%)** | **146,591 (−27.9%)** | **29,760 (−27.4%)** | 116,831 (79.7%) | 5,665 (5,009) | **6 (−40.0%)** | **89.9 ms** |
| **Gemini 4 Neon (XHigh)** | Native | 6/6 | 123.7 s | 316,776 | 76,648 | 240,128 (75.8%) | 10,960 (9,714) | 11 | — |
| **Gemini 4 Neon (XHigh)** | **CTX** | **6/6** | 172.4 s (+39.4%) | **191,733 (−39.5%)** | **39,861 (−48.0%)** | 151,872 (**79.2%**) | 18,925 (18,076) | **6 (−45.5%)** | **70.9 ms** |
| **Gemini 4 Carbon (High)** | Native | 6/6 | 189.8 s | 377,070 | 61,539 | 315,531 (83.7%) | 13,287 (11,979) | 14 | — |
| **Gemini 4 Carbon (High)** | **CTX** | **6/6** | 192.8 s (+1.6%) | **157,478 (−58.2%)** | **51,193 (−16.8%)** | 106,285 (67.5%) | 15,597 (14,872) | **5 (−64.3%)** | **81.3 ms** |

### Cold (Turn 1) vs Warm (Turn 2, same conversation & warmed cache)

| Model | Phase | Route | Wall time | Input (Δ vs Native) | Uncached (Δ vs Native) | LLM cache hit | CTX RAM cache hit | Tool calls | MCP ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Neon High** | Cold | Native | 112.2 s | 90,901 | 32,757 | 64.0% | — | 7 | — |
| **Neon High** | Cold | **CTX** | **52.1 s (−53.6%)** | **72,299 (−20.5%)** | **23,231 (−29.1%)** | **67.9%** | 85.4% (35/41) | **4** | 53.2 |
| **Neon High** | Warm | Native | 29.0 s | 112,472 | 8,218 | 92.7% | — | 3 | — |
| **Neon High** | Warm | **CTX** | **21.5 s (−25.9%)** | **74,292 (−33.9%)** | **6,529 (−20.6%)** | 91.2% | 69.9% (51/73) | **2** | 36.7 |
| **Neon XHigh** | Cold | Native | 97.2 s | 127,634 | 49,961 | 60.9% | — | 8 | — |
| **Neon XHigh** | Cold | **CTX** | 130.4 s (+34.1%) | **115,009 (−9.9%)** | **29,646 (−40.7%)** | **74.2%** | 85.7% (36/42) | **5** | 53.7 |
| **Neon XHigh** | Warm | Native | 26.5 s | 189,142 | 26,687 | 85.9% | — | 3 | — |
| **Neon XHigh** | Warm | **CTX** | 42.0 s (+58.5%) | **76,724 (−59.4%)** | **10,215 (−61.7%)** | **86.7%** | 78.6% (81/103) | **1** | 17.2 |
| **Carbon High** | Cold | Native | 155.4 s | 150,673 | 45,945 | 69.5% | — | 10 | — |
| **Carbon High** | Cold | **CTX** | 165.5 s (+6.5%) | **86,937 (−42.3%)** | **42,290 (−8.0%)** | 51.4% | 87.8% (43/49) | **4** | 65.4 |
| **Carbon High** | Warm | Native | 34.4 s | 226,397 | 15,594 | 93.1% | — | 4 | — |
| **Carbon High** | Warm | **CTX** | **27.2 s (−20.9%)** | **70,541 (−68.8%)** | **8,903 (−42.9%)** | 87.4% | 76.3% (71/93) | **1** | 15.9 |

Across all three models, CTX matched **18/18** exact `file:line` anchors, reduced tool calls by
**40–64%**, cut total input tokens by **28–58%** and uncached input tokens by **17–48%**, and
delivered **34–69%** lower input volume on warmed follow-up turns while spending under **90 ms**
total inside MCP.

[Benchmark runner](benchmarks/README.md) ·
[Releases](https://github.com/be0hhh/ctx-mcp/releases)
