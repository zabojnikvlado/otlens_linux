# OTLens Central on Windows

## Ports

- Web/management listener: TCP 8443 (default)
- Sensor API listener: TCP 9443 (default)
- PostgreSQL: TCP 5432 on localhost only (default)

## Scripts

- `build-central.ps1` — builds `bin\otlens-central.exe` from source.
- `init-postgres.ps1` — runs `db\central_phase3.sql` against a PostgreSQL
  database to create Central's schema. Optional: Central creates the same
  schema automatically on first startup, so this is only useful for
  pre-provisioning a database before the service's first run.
- `install-service.ps1` — installs/starts the `OTLensCentral` Windows
  service (default install dir `C:\Program Files\OTLens`). If
  `config.yaml` doesn't exist yet next to `otlens-central.exe`, it's
  auto-created from a `central.config.example.yaml` template placed
  alongside the exe — edit the PostgreSQL credentials in it before the
  service will actually work.
- `uninstall-service.ps1` — stops and removes the service.

## Configuration

Central looks for `config.yaml` **in the same directory as
otlens-central.exe** by default — no separate ProgramData path. Copy
`configs/central.config.example.yaml` to wherever you install the exe, as
`config.yaml`:

`C:\Program Files\OTLens\config.yaml` (or wherever you actually put the exe)

The Central process reads it with:

`otlens-central.exe --config C:\Program Files\OTLens\config.yaml`

— or just run it with no `--config` at all from that same directory, since
that's already the default. `install-service.ps1` passes `--config`
explicitly regardless, so it works correctly even if you customize
`-InstallDir`.

The web listener is intended for administrator/browser access. The sensor API
listener is intended for Linux sensor registration, heartbeat and rule sync.

For production, enable TLS on both listeners and use trusted certificates.
Keep PostgreSQL bound to `127.0.0.1` so it is not reachable from the OT network.


## Web UI
Copy the `web\central` directory next to `otlens-central.exe`. Open `http(s)://<central-ip>:8443/ui/`.
