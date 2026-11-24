#!/usr/bin/env bash
# One-command terminal uninstaller for ctx-mcp (Linux, macOS, WSL2).
# Usage:
#   ctx uninstall
#   curl -fsSL https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/uninstall.sh | bash
set -euo pipefail

CTX_BIN="${AGENT_CTX_HOME:-$HOME}/.local/bin/ctx"
if [ -x "$CTX_BIN" ]; then
  exec "$CTX_BIN" uninstall "$@"
elif command -v ctx >/dev/null 2>&1; then
  exec ctx uninstall "$@"
else
  printf 'ctx-mcp: no installed ctx binary found at %s (already uninstalled).\n' "$CTX_BIN"
fi
