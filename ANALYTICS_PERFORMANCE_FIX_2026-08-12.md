# OTLens — Analytics performance fix

Date: 2026-08-12

## Problem

The four Traffic Analytics views could take a very long time to open or appear stuck on installations with large `flow_observations` history. The initial options endpoint scanned up to 90 days of flow history to build the protocol dropdown. Each analytics request then executed six independent analytical SQL statements; every statement repeated event-time identity `LATERAL` lookups for both endpoints for every matching flow bucket. The active-view recovery poll also re-ran the analytical request every minute.

## Fix

- Analytics option loading no longer scans flow history. The service/protocol catalogue is deterministic and returned from the built-in protocol/service mapping.
- Modern flow rows use the `src_identity` / `dst_identity` written at ingest time directly.
- Legacy rows no longer perform two unconditional per-row `LATERAL` history lookups. Asset queries resolve a bounded alias list once and only verify event-time ownership for legacy `ip:` rows that actually match those aliases.
- Asset identity/IP filters are pushed into the raw `flow_observations` scan before enrichment joins.
- Known services such as SMB, DNS, NTP, SNMP, Modbus and S7 use direct indexed port predicates instead of evaluating the full service CASE expression across the entire time window.
- Current-window series, summary, top protocols, top ports and top peers are generated from one `selected AS MATERIALIZED` filtered row set rather than rebuilding the full analytics CTE five times.
- Only the historical baseline remains a second analytical query. Interactive baselines are bounded adaptively: 24h for <=6h analyses, 3d for <=24h analyses and 30d for larger windows.
- Counter aggregates are explicitly cast back to PostgreSQL `BIGINT` before Go scanning.
- Each analytics request has a 20-second backend deadline so pathological broad queries cannot hold a worker indefinitely.
- Analytics tabs load their controls immediately and wait for the operator to press **Analyze**. They are no longer recomputed by the one-minute recovery poll.
- Re-running the same dashboard aborts its previous browser request.
- The UI reports the completed query duration.

## Database migration v18

Additive indexes were added for large flow-history reads:

- BRIN index on `flow_observations.bucket_start`;
- `(sensor_id, src_ip, bucket_start)` and `(sensor_id, dst_ip, bucket_start)` for legacy alias prefiltering;
- source/initiator port time indexes to complement the existing destination/responder port indexes.

No database reset is required.

## Deployment

Rebuild and deploy Central/Web UI. No sensor change is required for this performance fix. New sensor flow telemetry already carries stable identities from migration v17; legacy history remains queryable through the bounded event-time alias fallback.
