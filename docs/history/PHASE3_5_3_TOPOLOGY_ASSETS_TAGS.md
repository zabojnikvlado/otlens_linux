# OTLens Phase 3.5.3 — Central Topology, Assets and OT Tags

## Added Central UI tabs

- Topology: aggregated interactive graph from all connected sensors, search by IP, MAC, hostname or sensor ID.
- Assets: aggregated passive asset inventory with sensor, IP, MAC, vendor, hostname, OT/IT classification, protocols, VLAN, packet count and last seen.
- OT Tags: aggregated Modbus/S7 variable inventory with current/previous value, address, operation, poll/change counters and timestamps.
- Sensors: retained for operational visibility.

## Data path

Sensors do not connect to PostgreSQL. Each sensor builds a telemetry snapshot from its in-memory discovery engines and sends it to:

`POST /v1/sensors/telemetry` on the Sensor API listener (default port 9443).

Central validates the sensor token and sensor identity, then stores the latest snapshot per sensor in PostgreSQL table `sensor_telemetry`.

The management UI reads aggregated data from authenticated endpoints on the Web listener (default port 8443):

- `GET /v1/topology`
- `GET /v1/assets`
- `GET /v1/tags`
- `GET /v1/sensors`

## Upgrade

Central automatically creates the `sensor_telemetry` table at startup. The SQL definition is also included in `db/central_phase3.sql` for clean installations.

After upgrading, rebuild and restart both Central and Linux sensors. Existing Phase 3.5.2 tokens remain valid.
