# OTLens telemetry ingest stall fix — 2026-08-12

## Symptom

Sensor authentication, `/sync`, and heartbeat succeed, but Central does not show a completed `POST /v1/sensors/telemetry` and current Assets remain empty/stale after sensor restart.

## Root cause

The sensor restores a large retained state and then builds a bounded telemetry delta. Flow and alert deltas are capped, but DNS, SMB, and generic protocol observation buffers can contain thousands of records. Central previously persisted those observations with one PostgreSQL `INSERT` round trip per row. A full bounded buffer could therefore execute roughly 20,000 observation INSERT statements in a single telemetry transaction, before asset/topology/alert writes. With a short sync interval this can exceed the sensor telemetry timeout. Gin writes its access log only when the request finishes, so the Central console appears to show only `/sync` and heartbeat while telemetry is still blocked in ingestion.

## Fixes

- DNS observations are inserted in batches of up to 1,000 rows.
- SMB observations are inserted in batches of up to 1,000 rows.
- Generic protocol observations are inserted in batches of up to 1,000 rows.
- Existing unique indexes and `ON CONFLICT DO NOTHING` preserve idempotent resend semantics.
- Provisional `ip:<addr>` -> `mac:<addr>` operator-state promotion is changed from up to eight SQL statements per asset to a fixed number of set-based statements per snapshot.
- Multi-address MAC promotion is collision-safe: only one provisional row is promoted when several old IP identities map to the same MAC; remaining duplicates are removed only after the MAC-owned state exists.
- `asset.Engine.GetAll()` now deep-copies `Addresses` to prevent a live capture/snapshot slice race.
- Sensor worker logs snapshots/uploads that take >=2 seconds, including payload component sizes, making future telemetry stalls directly visible.

## Deployment

Rebuild and deploy both Sensor and Central from the cumulative source. No database reset is required.

For very busy test sensors, a 15-30 second Central sync interval is still recommended over 5 seconds to avoid continuously retransmitting bounded observation buffers faster than they can materially change.
