# OTLens Central on Windows + PostgreSQL

This deployment runs the Central Management server and PostgreSQL on the same Windows server. Linux machines run the OTLens sensors.

## Topology

```text
Windows Server
├── OTLens Central :9090 (or HTTPS reverse proxy :443)
└── PostgreSQL 127.0.0.1:5432

Linux OT Sensors
└── outbound HTTPS/HTTP to Central
```

PostgreSQL should bind to `127.0.0.1` so it is not directly reachable from sensor networks.

## 1. PostgreSQL

Create a PostgreSQL database and user:

```sql
CREATE USER otlens WITH PASSWORD 'change-me';
CREATE DATABASE otlens OWNER otlens;
```

Initialize the schema:

```powershell
.\init-postgres.ps1 -Password 'change-me'
```

For a production environment, use a secret-management solution instead of putting passwords in shell history.

## 2. Build Central

From the repository root:

```powershell
.\deploy\windows\build-central.ps1
```

Copy `bin\otlens-central.exe` to:

```text
C:\Program Files\OTLens\
```

## 3. Configure and install the Windows service

Example:

```powershell
.\install-service.ps1 `
  -PostgresDsn "postgres://otlens:change-me@127.0.0.1:5432/otlens?sslmode=disable" `
  -CentralToken "replace-with-a-long-random-token"
```

The service listens on `:9090` by default.

For a real deployment, place a TLS reverse proxy in front of the Go API and expose only HTTPS to sensors. Do not expose PostgreSQL to the sensor network.

## 4. Firewall

Allow inbound TCP 9090 only from the sensor management networks, or expose HTTPS 443 through a reverse proxy.

Do not open TCP 5432 to OT networks.

## 5. Linux sensors

Build:

```bash
make build-linux-sensor
```

Install the resulting `bin/otlens-linux-amd64` on each Linux sensor and run it using the systemd unit in `deploy/systemd/otlens.service`.

Configure the sensor's central URL/token according to the sensor sync configuration in `sensor.config.example.yaml`.

## 6. Service operations

```powershell
Get-Service OTLensCentral
Start-Service OTLensCentral
Stop-Service OTLensCentral
Restart-Service OTLensCentral
```

Remove:

```powershell
.\uninstall-service.ps1
```

## Security notes

- Use a long random central token for bootstrap/simple deployments.
- Prefer per-sensor mTLS before production rollout.
- Put Central behind HTTPS; the current Go server is HTTP and is intended to sit behind a TLS terminator/reverse proxy.
- Keep PostgreSQL bound to localhost.
- Back up the PostgreSQL database.
- Restrict Windows service account privileges.


Central runtime configuration is stored in `C:\ProgramData\OTLens\config.yaml`. The executable accepts `--config` to override this path. PostgreSQL is a separate Windows service, normally listening on `127.0.0.1:5432`.
