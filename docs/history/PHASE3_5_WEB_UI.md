# OTLens Phase 3.5 - Central Web Management Console

The Central Windows executable now serves a dedicated management UI from the web listener.

- Web UI: `http://<central-ip>:8443/ui/` (or HTTPS if enabled)
- Sensor API: `http://<central-ip>:9443` (or HTTPS if enabled)
- PostgreSQL: `127.0.0.1:5432`

The UI provides a dashboard, sensor inventory/status, and rule-management guidance. It polls `/v1/sensors` every 10 seconds.

## Deployment

The `web/central` directory must be present next to the executable under `web/central`, unless `OTLENS_CENTRAL_WEB_DIR` is set to an absolute path.

Example:

```text
C:\Program Files\OTLens\
  otlens-central.exe
  web\central\
    index.html
    app.js
    style.css
```

## Authentication note

The Web UI uses `auth.management_token`; after a 401 response it prompts for the token and stores it in browser local storage. Sensor endpoints use the separate `auth.sensor_token`.

## Authentication fix (Phase 3.5.1)

Central now uses separate credentials:

- `auth.management_token` for the Web UI and management API on port 8443.
- `auth.sensor_token` for Linux sensor registration, heartbeat, and rule synchronization on port 9443.

The Web UI prompts for the management token after an HTTP 401 response and stores it in browser local storage. The Linux sensor must have `central.enabled: true` and a token matching `auth.sensor_token`; it then registers itself and sends heartbeat records to PostgreSQL through the Central Sensor API. Sensors never connect directly to PostgreSQL.
