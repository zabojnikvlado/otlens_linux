param(
    [string]$InstallDir = "C:\Program Files\OTLens",
    [string]$ConfigDir = "C:\ProgramData\OTLens",
    [string]$ServiceName = "OTLensCentral"
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "otlens-central.exe"
$config = Join-Path $ConfigDir "config.yaml"
if (!(Test-Path $exe)) { throw "Missing $exe. Build/copy otlens-central.exe first." }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

if (!(Test-Path $config)) {
    $template = Join-Path $InstallDir "central.config.example.yaml"
    if (Test-Path $template) {
        Copy-Item $template $config
        Write-Host "Created $config from $template. Edit PostgreSQL credentials before starting the service."
    } else {
        throw "Missing Central config at $config and template $template was not found."
    }
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

New-Service -Name $ServiceName `
    -DisplayName "OTLens Central Management" `
    -Description "OTLens Central Management API and PostgreSQL-backed management service" `
    -BinaryPathName "`"$exe`" --config `"$config`"" `
    -StartupType Automatic

Start-Service $ServiceName
Write-Host "OTLens Central service installed and started using $config."
