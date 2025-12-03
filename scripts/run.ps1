Param(
  [string]$ProjectRoot = "$PSScriptRoot\..",
  [string]$Config = "config.json"
)

Write-Host "[run] Starting rust-core with config: $Config"
Push-Location $ProjectRoot
cargo run -- run -c $Config
Pop-Location

