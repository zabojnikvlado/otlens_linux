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

The current bearer-token middleware protects `/v1/*`. If `auth.token` is enabled, the browser UI does not yet have a login/session flow and `/v1/sensors` will return 401. For initial internal deployments either leave the token empty and restrict the web listener with Windows Firewall/VPN, or add an admin login/session layer before exposing the UI broadly.
