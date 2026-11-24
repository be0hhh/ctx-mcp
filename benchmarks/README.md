# `ctx-mcp` Benchmarks

This directory preserves reproducible benchmark harnesses and raw telemetry comparing **Direct (`rg` + local file reads)** against **`ctx-mcp` (in-RAM Context Broker + MCP)**.

> **Status:** Initial live-model baseline (`20` end-to-end agent runs across `5` multi-file tasks × `2` routes × `2` harnesses, plus `1–200` concurrent-agent synthetic waves). Additional models, repositories, and larger file-reading workloads (`>800` lines) are being added incrementally.

## Contents

- [`run_benchmark.py`](run_benchmark.py) — Standalone benchmark runner:
  1. Synthetic multi-agent load waves (`ctx bench --agents 1,10,50,100,200 --ops 25 --json`).
  2. Optional live-agent A/B evaluation (`--tasks-json <file>`) across Antigravity CLI (`agy`) and/or Codex CLI (`codex`).
- [`results/v2_2_dual_matrix.json`](results/v2_2_dual_matrix.json) — Sanitized telemetry from the 20-session `Direct (rg)` vs `CTX MCP` comparison (`Gemini 4 Carbon Low` in Antigravity + `GPT-6.2 Sol Low` in Codex) and `1..200` concurrent-agent stress waves on a ~1,800-file C++26 / Python codebase.

## Quick Run (Synthetic 1–200 Concurrent Agents, Zero API Tokens)

```bash
python3 -B benchmarks/run_benchmark.py --synthetic-only
```

## Running Custom Live Model Benchmarks

Create a JSON task definition file (`tasks.json`):

```json
[
  {
    "id": "T1_example",
    "question": "Find the 2 exact file:line locations where ...",
    "anchors": [
      ["MyModule.hpp", ["void targetMethod("]],
      ["MyModule.cpp", ["MyModule::targetMethod("]]
    ]
  }
]
```

Then run:

```bash
# Antigravity (Gemini 4 Carbon Low):
python3 -B benchmarks/run_benchmark.py --workspace /path/to/repo --tasks-json tasks.json --harnesses agy --agy-model gemini-4-carbon-low

# Both Antigravity and Codex:
python3 -B benchmarks/run_benchmark.py --workspace /path/to/repo --tasks-json tasks.json --harnesses agy,codex
```
