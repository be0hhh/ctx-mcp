# CTX Setup, Manual Configuration & CLI

The one-line installer in the [main README](../README.md#install) downloads the
static/native release binary (or compiles locally via `rustc` with zero crates)
and configures your chosen AI clients automatically. Use this guide for
non-interactive installs, self-updates, manual client configs, diagnostics, and
CLI usage.

## Installer & Update Commands

```bash
# Interactive harness menu (Antigravity, Claude Code, Codex)
ctx setup

# Non-interactive selective or full install
ctx install --targets antigravity,codex
ctx install --all

# Control Antigravity eager tool exposure (default: core = 4 tools)
ctx install --targets antigravity --eager=core    # ctx_search, ctx_read, ctx_symbols, ctx_inspect
ctx install --targets antigravity --eager=search  # ctx_search only
ctx install --targets antigravity --eager=all     # all catalog tools (11 write / 10 read-only)
ctx install --targets antigravity --eager=none    # lazy via call_mcp_tool

# Toggle persistent write mode (controls ctx_edit exposure; applies live on next call)
ctx mode                  # inspect current mode & flavor
ctx mode write            # enable atomic ctx_edit (11 MCP tools)
ctx mode read-only        # read-only mode (10 MCP tools)

# Verified self-update (pure-Rust SHA-256 against GitHub Releases SHA256SUMS)
ctx update --check        # check latest release without modifying files
ctx update                # download, verify SHA-256, hot-swap daemon (custom-flavor safe)
ctx update --rebuild      # run configured local rebuild command on custom-flavor builds

# Optional flags & health check
ctx install --all --no-codex-rules   # keep ~/.codex/AGENTS.md managed externally
ctx install --targets antigravity --no-wsl-bridge
ctx install --check                  # verify zero drift without writing
ctx --version                        # print version & build flavor
ctx doctor [--json]
ctx uninstall --all
```

## Manual Client Configuration

### Codex

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
# Batched in-RAM search (1–6 scoped queries, smart-case, 8 KiB default cap)
ctx search -q 'Engine:handleRequest' \
  -q 'AuthService:verifyToken' \
  --max-results 3 --max-bytes 2048

# Single search with optional context or verbose scopes
ctx search 'handleRequest' src/ --context-lines 1 --max-results 10
ctx search 'handleRequest' src/ --detail scopes --code-only

# Directory / file triage (exact line counts, includes/imports, symbol ranges)
ctx inspect src/ --max-files 80

# Exact symbol bodies (use --compact for <=24 lines + continuation slice, --hashes for edit anchors)
ctx sym 'Engine#handleRequest' --compact
ctx sym 'docs/Guide.md#Architecture'

# Full-file or line-slice reads (up to 1 MiB, zero 800-line truncation)
ctx read src/Engine.cpp:1-120 --hashes

# Impact analysis, atomic edits (edits + renames + creates + verify_absent), and read-only git
ctx impact 'Engine#handleRequest'
ctx edit --dry-run --json '{"edits":[{"path":"src/Engine.cpp","start_line":10,"end_line":10,"expected_hash":"a1b","replacement":"..."}]}'
ctx git diff --stat
ctx git status

# Universal build / test / Linux log / JSON compressor
ctx diag -- cargo test
ctx diag -- pytest -q
ctx diag --file /var/log/app.log

# Structural outlines, shared workspace memos & Shared Context Packs
ctx outline src/
ctx memo put --topic arch --summary 'Key invariants' src/Engine.cpp
ctx memo pack --topic core-rules docs/Architecture.md#Core config.json#limits
ctx memo pack-get core-rules
ctx memo packs

# Static ELF64 + ASM audit & daemon management
ctx elf --elf ./build/app --asm ./build/app.s
ctx status | clear | save-snapshot | shutdown
ctx mcp [--read-only|--write] --protocol-check
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
