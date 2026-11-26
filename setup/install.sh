#!/usr/bin/env bash
# One-command terminal installer for ctx-mcp (Linux, macOS, WSL2).
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.sh | bash
#   bash setup/install.sh [--targets antigravity,claude] [--from-source]
set -euo pipefail

REPO="${CTX_MCP_REPO:-be0hhh/ctx-mcp}"
FROM_SOURCE=0
FORWARD_ARGS=()

for arg in "$@"; do
  if [ "$arg" = "--from-source" ]; then
    FROM_SOURCE=1
  else
    FORWARD_ARGS+=("$arg")
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ctx-mcp-setup.XXXXXX")"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

detect_asset() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$os" in
    linux*)  os="linux" ;;
    darwin*) os="macos" ;;
    *)       return 1 ;;
  esac
  case "$arch" in
    x86_64|amd64)  arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)             return 1 ;;
  esac
  if [ "$os" = "linux" ] && [ "$arch" = "arm64" ]; then
    printf 'ctx-linux-aarch64'
  else
    printf 'ctx-%s-%s' "$os" "$arch"
  fi
}

verify_sha256() {
  local file="$1" sums="$2" asset="$3" expected actual
  expected="$(awk -v name="$asset" '$2 == name || $2 == ("*" name) { print $1; exit }' "$sums")"
  [ -n "$expected" ] || return 1
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    return 0
  fi
  [ "$actual" = "$expected" ]
}

CTX_TMP="$TMP_DIR/ctx"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
LOCAL_MAIN="${SCRIPT_DIR:+$SCRIPT_DIR/../src/main.rs}"

find_rustc() {
  if command -v rustc >/dev/null 2>&1; then
    command -v rustc
  elif [ -x "$HOME/.cargo/bin/rustc" ]; then
    printf '%s' "$HOME/.cargo/bin/rustc"
  else
    return 1
  fi
}

# 1. Always prefer the prebuilt verified binary from GitHub Releases first (including npx & git clone),
#    unless --from-source was explicitly requested. Zero Rust toolchain required.
BUILT=0
if [ "$FROM_SOURCE" -eq 0 ]; then
  if ASSET="$(detect_asset)" && command -v curl >/dev/null 2>&1; then
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
    if curl -fsSL "${BASE_URL}/${ASSET}" -o "$CTX_TMP" 2>/dev/null \
       && curl -fsSL "${BASE_URL}/SHA256SUMS" -o "$TMP_DIR/SHA256SUMS" 2>/dev/null \
       && verify_sha256 "$CTX_TMP" "$TMP_DIR/SHA256SUMS" "$ASSET"; then
      chmod 0755 "$CTX_TMP"
      printf 'Downloaded prebuilt %s from GitHub Releases (SHA-256 verified).\n' "$ASSET"
      BUILT=1
    fi
  fi
fi

# 2. Fallback to rustc only when --from-source is passed or no prebuilt release exists for this OS/CPU.
if [ "$BUILT" -eq 0 ]; then
  if [ -f "${LOCAL_MAIN:-}" ] && RUSTC_BIN="$(find_rustc)"; then
    printf 'Building ctx from local source (%s)...\n' "$RUSTC_BIN"
    "$RUSTC_BIN" --edition 2021 -C opt-level=3 -C panic=abort -C lto=fat -C codegen-units=1 -C strip=symbols "$LOCAL_MAIN" -o "$CTX_TMP"
    chmod 0755 "$CTX_TMP"
    BUILT=1
  elif RUSTC_BIN="$(find_rustc)" && command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
    printf 'No prebuilt release found for this platform; compiling from %s main...\n' "$REPO"
    curl -fsSL "https://codeload.github.com/${REPO}/tar.gz/refs/heads/main" | tar -xz -C "$TMP_DIR"
    SRC_MAIN="$(find "$TMP_DIR" -maxdepth 3 -path '*/src/main.rs' | head -n 1)"
    "$RUSTC_BIN" --edition 2021 -C opt-level=3 -C panic=abort -C lto=fat -C codegen-units=1 -C strip=symbols "$SRC_MAIN" -o "$CTX_TMP"
    chmod 0755 "$CTX_TMP"
    BUILT=1
  fi
fi

if [ "$BUILT" -eq 0 ]; then
  printf 'ctx-mcp error: prebuilt binary unavailable and rustc not found.\n' >&2
  printf 'Install Rust (https://rustup.rs) or download a release from https://github.com/%s/releases\n' "$REPO" >&2
  exit 1
fi

export PATH="$HOME/.local/bin:$PATH"
if [ "${#FORWARD_ARGS[@]}" -gt 0 ]; then
  "$CTX_TMP" install "${FORWARD_ARGS[@]}"
else
  "$CTX_TMP" setup
fi
