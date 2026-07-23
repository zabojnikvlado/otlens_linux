param([string]$ServiceName = "OTLensCentral")
$ErrorActionPreference = "Stop"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Write-Host "Removed $ServiceName"
}
