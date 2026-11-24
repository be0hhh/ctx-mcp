# One-command terminal uninstaller for ctx-mcp (Windows PowerShell).
# Usage:
#   ctx uninstall
#   irm https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/uninstall.ps1 | iex
$ErrorActionPreference = "Stop"
$HomeBase = if ($env:AGENT_CTX_HOME) { $env:AGENT_CTX_HOME } else { $HOME }
$CtxBin = Join-Path $HomeBase ".local\bin\ctx.exe"
if (Test-Path $CtxBin) {
    & $CtxBin uninstall @args
} elseif (Get-Command ctx -ErrorAction SilentlyContinue) {
    & ctx uninstall @args
} else {
    Write-Host "ctx-mcp: no installed ctx.exe found at $CtxBin (already uninstalled)."
}
