# OTLens Central on Windows

## Ports

- Web/management listener: TCP 8443 (default)
- Sensor API listener: TCP 9443 (default)
- PostgreSQL: TCP 5432 on localhost only (default)

## Configuration

Copy `configs/central.config.example.yaml` to:

`C:\ProgramData\OTLens\config.yaml`

The Central process reads it with:

`otlens-central.exe --config C:\ProgramData\OTLens\config.yaml`

The web listener is intended for administrator/browser access. The sensor API
listener is intended for Linux sensor registration, heartbeat and rule sync.

For production, enable TLS on both listeners and use trusted certificates.
Keep PostgreSQL bound to `127.0.0.1` so it is not reachable from the OT network.


## Web UI
Copy the `web\central` directory next to `otlens-central.exe`. Open `http(s)://<central-ip>:8443/ui/`.
