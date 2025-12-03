Param(
  [string]$ProjectRoot = "$PSScriptRoot\.."
)

Write-Host "[setup] Installing Rust toolchain and configuring environment..."

# Ensure cargo exists
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
  Write-Host "Rust not found. Please install from https://www.rust-lang.org/" -ForegroundColor Yellow
}

# Optional: set environment hints for network
$env:CARGO_HTTP_MULTIPLEXING = 'false'
$env:CARGO_NET_RETRY = '10'

Write-Host "[setup] Building project in release mode..."
Push-Location $ProjectRoot
cargo build --release
Pop-Location

Write-Host "[setup] Generating sample config..."
Push-Location $ProjectRoot
cargo run -- generate -o config.json
Pop-Location

Write-Host "[setup] Done. Use scripts/run.ps1 to start."

