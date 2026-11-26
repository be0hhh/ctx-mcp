# CTX Setup, Manual Configuration & CLI

The one-line installer in the [main README](../README.md#install) downloads the
static/native release binary (or compiles locally via `rustc` with zero crates)
and configures your chosen AI clients automatically. Use this guide for
non-interactive installs, manual client configs, diagnostics, and CLI usage.

## Installer Commands

```bash
# Interactive harness menu (Antigravity, Claude Code, Codex)
ctx setup

# Non-interactive selective or full install
ctx install --targets antigravity,codex
ctx install --all

# Control Antigravity eager tool exposure (default: core = 4 tools)
ctx install --targets antigravity --eager=core    # ctx_search, ctx_read, ctx_symbols, ctx_inspect
ctx install --targets antigravity --eager=search  # ctx_search only
ctx install --targets antigravity --eager=all     # all 8 catalog tools
ctx install --targets antigravity --eager=none    # lazy via call_mcp_tool

# Optional flags
ctx install --all --no-codex-rules   # keep ~/.codex/AGENTS.md managed externally
ctx install --targets antigravity --no-wsl-bridge
ctx install --check                  # verify zero drift without writing

# Health check & clean removal
ctx doctor
ctx doctor --json
ctx uninstall --all
```

## Manual Client Configuration

### Codex (`0.172.0+`)

Add to your trusted workspace `.codex/config.toml` or `~/.codex/config.toml`,
then start a new session:

```toml
[mcp_servers.agent_ctx]
command = "ctx"
args = ["mcp"]
omit_tools_from = ["deferred", "code_mode"]
```

### Antigravity

Configure `~/.gemini/config/mcp_config.json` (and optional Windows WSL bridge)
automatically with:

```bash
ctx install --targets antigravity --eager=core
```

### Claude Code

Configure `~/.claude.json` and hooks automatically with:

```bash
ctx install --targets claude
```

## CLI Quick Reference

```bash
# Batched in-RAM search (1–4 scoped queries, smart-case, 8 KiB default cap)
ctx search -q 'PositionTable:applyFillHot' \
  -q 'StartupStreamBoundary:userDataSubscribedBeforeSnapshot' \
  --max-results 3 --max-bytes 2048

# Single search with optional context or verbose scopes
ctx search 'applyFillHot' src/ --context-lines 1 --max-results 10
ctx search 'applyFillHot' src/ --detail scopes

# Directory / file triage (exact line counts, includes/imports, symbol ranges)
ctx inspect src/ --max-files 80

# Exact symbol bodies (use --compact for <=24 lines + continuation slice)
ctx sym 'PositionTable#applyFillHot' --compact

# Full-file or line-slice reads (up to 1 MiB, zero 800-line truncation)
ctx read src/Engine.cpp:1-120

# Structural outlines & shared workspace memos (auto-marked [STALE] on file edit)
ctx outline src/
ctx memo put --topic arch --summary 'Key invariants' src/Engine.cpp
ctx memo list

# Static ELF64 + ASM audit & daemon management
ctx elf --elf ./build/app --asm ./build/app.s
ctx status | clear | save-snapshot | shutdown
ctx mcp --protocol-check
```

## Build from Source

Zero external crates — builds identically with Cargo or bare `rustc`:

```bash
# Cargo (builds `ctx` and `ctx-bench`)
cargo build --release --bins

# Native CPU build (e.g. AVX2/BMI1/Zen 3/Apple Silicon)
RUSTFLAGS="-C target-cpu=native" cargo build --release --bin ctx

# Single-command bare rustc (no Cargo required)
rustc --edition 2021 -C opt-level=3 -C panic=abort -C lto=fat -C codegen-units=1 src/main.rs -o ctx
```
