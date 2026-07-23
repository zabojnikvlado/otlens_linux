# OTLens Phase 3.3 – Separate Sensor and Central configuration

## Sensor (Linux)

Binary: `otlens`
Default config: `/etc/otlens/config.yaml`
Override: `otlens --config /path/to/config.yaml`
Template: `configs/sensor.config.example.yaml`

The sensor config contains local capture, detection, SQLite persistence, logging, API, and the other sensor runtime settings.

## Central (Windows)

Binary: `otlens-central.exe`
Default config: `C:\ProgramData\OTLens\config.yaml`
Override: `otlens-central.exe --config C:\path\to\config.yaml`
Template: `configs/central.config.example.yaml`

The Central config contains the Central listener, PostgreSQL connection, and optional management API Bearer token. PostgreSQL is not embedded in the executable; it runs as a separate Windows service on the same server by default.

## Environment overrides

Sensor uses the `OTLENS_` prefix. Central uses `OTLENS_CENTRAL_`.

Examples:

```powershell
$env:OTLENS_CENTRAL_DATABASE_PASSWORD = "secret"
$env:OTLENS_CENTRAL_AUTH_TOKEN = "token"
```
