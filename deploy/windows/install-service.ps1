param(
    [string]$InstallDir = "C:\Program Files\OTLens",
    [string]$ServiceName = "OTLensCentral",
    [string]$ListenAddress = ":9090",
    [string]$PostgresDsn = "",
    [string]$CentralToken = ""
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "otlens-central.exe"
if (!(Test-Path $exe)) { throw "Missing $exe. Build/copy otlens-central.exe first." }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Persist service environment in a machine-level environment file.
$envFile = Join-Path $InstallDir "central.env.ps1"
@"
`$env:OTLENS_CENTRAL_ADDR='$ListenAddress'
`$env:OTLENS_POSTGRES_DSN='$PostgresDsn'
`$env:OTLENS_CENTRAL_TOKEN='$CentralToken'
"@ | Set-Content -Encoding UTF8 $envFile

# The service wrapper uses PowerShell to load environment variables before
# starting the native Go executable. For production, prefer a dedicated
# service account and protect the installation directory.
$wrapper = Join-Path $InstallDir "run-central.ps1"
@"
`$env:OTLENS_CENTRAL_ADDR='$ListenAddress'
`$env:OTLENS_POSTGRES_DSN='$PostgresDsn'
`$env:OTLENS_CENTRAL_TOKEN='$CentralToken'
& '$exe'
"@ | Set-Content -Encoding UTF8 $wrapper

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

New-Service -Name $ServiceName `
    -DisplayName "OTLens Central Management" `
    -Description "OTLens Central Management API and PostgreSQL-backed management service" `
    -BinaryPathName "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$wrapper`"" `
    -StartupType Automatic

Start-Service $ServiceName
Write-Host "OTLens Central service installed and started."
