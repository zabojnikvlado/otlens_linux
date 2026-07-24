# Phase 3.7.0 – Data Management & Backup

Phase 3.7.0 adds a management-token-protected **Data Management** tab for Central PostgreSQL data and sensor SQLite state.

## Central backups

`POST /v1/data/backups` with `scope: central` stores a consistent JSON snapshot of sites, sensors, rule sets, assignments and telemetry in PostgreSQL table `system_backups`. Backups can be listed, downloaded and deleted. The payload has a SHA-256 checksum.

## Sensor backups

For selected sensors Central queues `sensor.backup.create`. The sensor runs SQLite `VACUUM INTO` after a WAL checkpoint and stores the backup under a `backups` directory next to the configured SQLite database. Sensor backup transfer to Central and remote restore are deliberately not enabled in this release; restore is an operator-controlled file replacement while the sensor service is stopped.

## Reset operations

Central supports database/telemetry, alerts, analysis, SIEM queue, rules and factory reset. Sensors support database, learning, assets, alerts, tags, analysis cache and factory reset. Sensor commands are delivered through `sensor_commands`.

Every destructive request must include exact confirmation `RESET`. Management authentication and audit middleware apply to all endpoints.

## API

- `GET /v1/data/backups`
- `POST /v1/data/backups`
- `GET /v1/data/backups/:backup/download`
- `DELETE /v1/data/backups/:backup`
- `POST /v1/data/reset`

## Operational note

A sensor reset clears both live in-memory state and SQLite persistence, then immediately writes an empty consistent snapshot. Configuration, sensor identity, token and TLS files are not removed.
