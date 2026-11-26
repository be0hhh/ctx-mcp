# One-command terminal installer for ctx-mcp (Windows PowerShell).
# Usage:
#   irm https://raw.githubusercontent.com/be0hhh/ctx-mcp/main/setup/install.ps1 | iex
#   powershell -ExecutionPolicy Bypass -File setup/install.ps1 [--targets antigravity,claude] [--from-source]
$ErrorActionPreference = "Stop"
$Repo = if ($env:CTX_MCP_REPO) { $env:CTX_MCP_REPO } else { "be0hhh/ctx-mcp" }
$FromSource = $false
$ForwardArgs = @()

foreach ($a in $args) {
    if ($a -eq "--from-source") {
        $FromSource = $true
    } else {
        $ForwardArgs += $a
    }
}

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ctx-mcp-setup-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

try {
    $CtxTmp = Join-Path $TmpDir "ctx.exe"
    $Asset = "ctx-windows-x86_64.exe"
    $Built = $false
    $LocalMain = if ($PSScriptRoot) { Join-Path $PSScriptRoot "..\src\main.rs" } else { "" }

    # 1. Always prefer the prebuilt verified binary from GitHub Releases first (including npx & git clone),
    #    unless --from-source was explicitly requested. Zero Rust toolchain required.
    if (-not $FromSource) {
        try {
            $BaseUrl = "https://github.com/$Repo/releases/latest/download"
            Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$Asset" -OutFile $CtxTmp
            $SumsPath = Join-Path $TmpDir "SHA256SUMS"
            Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/SHA256SUMS" -OutFile $SumsPath
            $Expected = (Get-Content $SumsPath | Where-Object { $_ -match "\b$([regex]::Escape($Asset))$" } | Select-Object -First 1)
            if ($Expected) {
                $ExpectedHash = ($Expected -split '\s+')[0].ToLowerInvariant()
                $ActualHash = (Get-FileHash -Algorithm SHA256 $CtxTmp).Hash.ToLowerInvariant()
                if ($ExpectedHash -ne $ActualHash) {
                    throw "SHA256 mismatch for $Asset"
                }
                Write-Host "Downloaded prebuilt $Asset from GitHub Releases (SHA-256 verified)."
                $Built = $true
            }
        } catch {
            $Built = $false
        }
    }

    # 2. Fallback to rustc only when --from-source is passed or prebuilt download failed.
    if (-not $Built) {
        $Rustc = Get-Command rustc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        if (-not $Rustc -and (Test-Path "$HOME\.cargo\bin\rustc.exe")) {
            $Rustc = "$HOME\.cargo\bin\rustc.exe"
        }
        if (-not $Rustc) {
            throw "Prebuilt release binary unavailable and rustc not found. Install Rust (https://rustup.rs) or check https://github.com/$Repo/releases"
        }
        if ($LocalMain -and (Test-Path $LocalMain)) {
            Write-Host "Building ctx.exe from local source..."
            & $Rustc --edition 2021 -C opt-level=3 -C panic=abort -C lto=fat -C codegen-units=1 $LocalMain -o $CtxTmp
        } else {
            Write-Host "Downloading source archive from $Repo and compiling..."
            $ZipPath = Join-Path $TmpDir "src.zip"
            Invoke-WebRequest -UseBasicParsing -Uri "https://codeload.github.com/$Repo/zip/refs/heads/main" -OutFile $ZipPath
            Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force
            $SrcMain = Get-ChildItem -Path $TmpDir -Recurse -Filter "main.rs" | Where-Object { $_.FullName -match "[\\/]src[\\/]main\.rs$" } | Select-Object -First 1 -ExpandProperty FullName
            & $Rustc --edition 2021 -C opt-level=3 -C panic=abort -C lto=fat -C codegen-units=1 $SrcMain -o $CtxTmp
        }
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $CtxTmp)) {
            throw "rustc failed to build ctx.exe"
        }
    }

    if ($ForwardArgs.Count -gt 0) {
        & $CtxTmp install @ForwardArgs
    } else {
        & $CtxTmp setup
    }
} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
