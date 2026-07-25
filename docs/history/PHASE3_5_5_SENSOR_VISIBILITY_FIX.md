# OTLens Phase 3.5.5 — Sensor visibility and diagnostics

Fixes:

- `/v1/sensors` now handles nullable PostgreSQL `site_id` using `COALESCE`.
- The Web UI no longer remains indefinitely in `connecting`; it displays the failing endpoint and still renders successful tabs.
- The Linux sensor retries registration every sync interval.
- Registration, rules, heartbeat and telemetry failures are written to the sensor log.

After deployment rebuild and restart both Central and Linux sensor binaries.
