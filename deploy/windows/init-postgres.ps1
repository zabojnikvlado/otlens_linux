param(
    [string]$Psql = "psql.exe",
    [string]$Host = "127.0.0.1",
    [int]$Port = 5432,
    [string]$Database = "otlens",
    [string]$User = "otlens",
    [string]$Password
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Password)) {
    throw "Pass -Password with the PostgreSQL password for the otlens database user."
}

$schema = Join-Path (Split-Path -Parent $PSScriptRoot | Split-Path -Parent) "db\central_phase3.sql"
if (!(Test-Path $schema)) { throw "Schema not found: $schema" }

$env:PGPASSWORD = $Password
& $Psql -h $Host -p $Port -U $User -d $Database -f $schema
if ($LASTEXITCODE -ne 0) { throw "PostgreSQL schema initialization failed." }
Write-Host "OTLens PostgreSQL schema initialized."
