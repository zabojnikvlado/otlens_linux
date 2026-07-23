$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Bin = Join-Path $Root "bin"
New-Item -ItemType Directory -Force -Path $Bin | Out-Null

Push-Location $Root
try {
    go build -o (Join-Path $Bin "otlens-central.exe") ./cmd/otlens-central
} finally {
    Pop-Location
}
Write-Host "Built $Bin\otlens-central.exe"
