# CTX

Local zero-dependency Rust MCP server & in-RAM code index for **Antigravity**,
**Codex**, and **Claude Code**. Cuts token burn, subscription quota drain, and
navigation latency across C/C++, Rust, Python, Java, C#, Go, TS/JS, Markdown,
JSON, TOML, and YAML.

## Install

Linux, macOS, or WSL:

```bash
curl -fsSL https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.ps1 | iex
```

The installer configures Antigravity, Codex, and Claude Code automatically.
For manual configs, flags, and CLI usage, see [setup/README.md](setup/README.md).

## Savings at a Glance (Native vs CTX v2.4.0)

Measured across 5 models in two-turn **Cold → Warm** sessions (`30/30` exact `file:line`):

| Metric | Antigravity (`Neon High/XHigh`, `Carbon High`) | Codex (`GPT-6.2 Astra XHigh/Max`) | All 5 models |
|---|---:|---:|---:|
| **Full input tokens** | **−53.7%** (**2.16×** less) | **−5.6%** (`−10.4%` Warm) | **−38.9%** (**1.64×** less) |
| **Uncached input tokens** | **−59.4%** (**2.46×** less) | **−2.2%** (`−17.4%` on Max) | **−50.3%** (**2.01×** less) |
| **Warm turn input / uncached** | **−72.0%** (**3.57×**) / **−82.0%** (**5.55×**) | **−10.4%** / **−5.3%** | **−52.3%** / **−69.4%** (**3.26×**) |
| **Tool output pushed to context** | Compact `@scope` hits (no full-file dumps) | **−89.6%** (**9.7×** less; **14.8×** on Max) | **~10×** cleaner context |
| **Tool calls** | **−56.8%** (**2.31×** fewer; **1** call Warm) | **−41.2%** (**1.70×** fewer) | **−51.9%** (**2.08×** fewer) |
| **Wall time** | **−6.6%** (**−45.8% / 1.84×** faster Warm) | **−20.2%** (**1.25×**; up to **1.42×** XHigh) | **−9.0%** (**1.68×** faster Warm) |
| **Output / reasoning tokens** | +24.9% (model-driven thinking) | **−23.3%** less output | — |
| **Est. subscription quota drain*** | **−30%…−38%** (2 turns) · **−64%…−67%** Warm | **−8%…−13%** (2 turns) · compounds over 10+ turns | **−26%** (2 turns) · **−51%** Warm |
| **CTX MCP overhead** | **29.8–41.9 ms** total (`6.5–7.5 MiB` RAM) | **34.3–40.1 ms** total (`6.0–6.5 MiB` RAM) | **< 42 ms** / session |

<sub>*Weighted token-cost estimate (`1.0× uncached + 0.1–0.25× cached + 4–5× output`). In multi-turn chats, avoiding full-file dumps compounds savings on every follow-up turn and delays context compaction.</sub>

**Where & why it wins:**
- **Antigravity:** Biggest token & quota saver — replaces multi-file `read_file` chains with 1 batched `ctx_search` (`8.3–8.5 ms` Warm), cutting warmed-turn quota burn by **~2.7–3×**.
- **Codex (`Astra 6.2`):** Biggest speed & context-hygiene win — **1.25×–1.42× faster**, **−41%** tool calls, **−23%** output, and **10–15×** smaller tool payloads (`48.8 KB → 3.3 KB` on Max).
- **Zero-copy AVX2+BMI1 RAM engine:** Searches at **37–40 GB/s** (`0.62 ms` p50 for 4 batched queries), returns inline `@scope` hits under an 8 KiB budget, and resolves shorthand roots (`Module:pattern`, `Dir/Sub:pattern`) without directory crawls.
- **Shared daemon & dedup:** One 64-shard RAM cache (`~7 MiB` RSS, `11.6k ops/s`) shared across sessions and subagents with per-agent read dedup and stale-checked workspace memos.

## Native vs CTX — Full Session Totals (Cold + Warm)

Two-turn navigation benchmark on an isolated 850-file repo: **Cold** 4-anchor task (Turn 1) + **Warm** 2-anchor follow-up (Turn 2 via `--resume` / `codex exec resume`), comparing built-in search/reads (**Native**, zero MCP) against **CTX v2.4.0** (Antigravity 4 core eager tools / Codex direct MCP).

| Client & Model | Route | Exact `file:line` | Wall time | Full input | Uncached input | Output (thinking) | Tool calls | CTX MCP time |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **AGY · Gemini 4 Neon (High)** | Native | 6/6 | 81.6 s | 247,973 | 66,303 | 4,622 (3,334) | 10 | — |
| **AGY · Gemini 4 Neon (High)** | **CTX** | **6/6** | **64.7 s (−20.7%)** | **130,649 (−47.3%)** | **31,601 (−52.3%)** | 5,127 (4,361) | **6 (−40.0%)** | **41.9 ms** |
| **AGY · Gemini 4 Neon (XHigh)** | Native | 6/6 | 163.7 s | 413,869 | 77,927 | 14,655 (13,373) | 14 | — |
| **AGY · Gemini 4 Neon (XHigh)** | **CTX** | **6/6** | **160.6 s (−1.9%)** | **132,153 (−68.1%)** | **30,570 (−60.8%)** | **13,788** (13,279) | **4 (−71.4%)** | **29.8 ms** |
| **AGY · Gemini 4 Carbon (High)** | Native | 6/6 | 266.1 s | 356,019 | 117,902 | 14,037 (12,744) | 13 | — |
| **AGY · Gemini 4 Carbon (High)** | **CTX** | **6/6** | **252.4 s (−5.2%)** | **208,318 (−41.5%)** | **44,215 (−62.5%)** | 22,703 (21,863) | **6 (−53.8%)** | **39.6 ms** |
| **Codex · GPT-6.2 Astra (XHigh)** | Native | 6/6 | 45.6 s | 233,161 | 18,889 | 1,259 (12) | 9 | — |
| **Codex · GPT-6.2 Astra (XHigh)** | **CTX** | **6/6** | **32.1 s (−29.5%)** | **212,821 (−8.7%)** | 23,125 (+22.4%) | **816 (−35.2%)** (30) | **5 (−44.4%)** | **34.3 ms** |
| **Codex · GPT-6.2 Astra (Max)** | Native | 6/6 | 62.3 s | 220,811 | 30,475 | 3,389 (1,878) | 8 | — |
| **Codex · GPT-6.2 Astra (Max)** | **CTX** | **6/6** | **53.9 s (−13.4%)** | **215,625 (−2.3%)** | **25,161 (−17.4%)** | **2,750 (−18.9%)** (1,935) | **5 (−37.5%)** | **40.1 ms** |

[Cold vs Warm & Load Benchmarks](benchmarks/README.md) ·
[Manual Setup & CLI](setup/README.md) ·
[Releases](https://github.com/be0hhh/ctx-mcp/releases)
