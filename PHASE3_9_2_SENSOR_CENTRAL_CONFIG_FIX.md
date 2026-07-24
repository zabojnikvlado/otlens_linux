# Phase 3.9.2 — Sensor Central connection configuration fix

The Linux sensor configuration again contains the required outbound `central` section.

Files:

- `configs/sensor.config.example.yaml` — documented template
- `configs/sensor.config.yaml` — deploy-ready copy intended to be copied to `/etc/otlens/config.yaml`

Required values when `central.enabled` is `true`:

- `central.url`
- `central.sensor_id`
- `central.token`

Supported connection settings:

- `central.name`
- `central.site_id`
- `central.interval`
- `central.timeout`
- `central.insecure_skip_verify`

The sensor validates these values during startup. The token can be supplied through the `OTLENS_CENTRAL_TOKEN` environment variable instead of storing it in the YAML file.
