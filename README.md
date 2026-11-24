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

Five parallel source-navigation tasks per client, comparing built-in search and
file reads with CTX MCP. These measurements are from the November 2026 baseline.

| Metric | Codex GPT-6.2 Sol (Low) | Antigravity Gemini 4 Carbon (Low) |
|---|---:|---:|
| Exact `file:line` matches | 20/20 → 20/20 | 20/20 → 20/20 |
| Mean task time | 16.20 s → 15.28 s (−5.7%) | 31.40 s → 17.35 s (−44.7%) |
| Tool calls | 7 → 5 (−28.6%) | 14 → 5 (−64.3%) |
| Full input tokens | 378,741 → 478,438 (+26.3%) | 286,149 → 197,547 (−31.0%) |
| Output tokens | 1,213 → 1,545 (+27.4%) | 2,776 → 2,139 (−22.9%) |

CTX reduced tool calls in both clients. Gemini used fewer input and output
tokens in this run. Codex completed slightly faster and used more tokens.

[Benchmark runner](benchmarks/README.md) ·
[Releases](https://github.com/be0hhh/ctx-mcp/releases)
