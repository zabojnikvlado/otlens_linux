# OTLens Phase 3 — Central Management, Sensor Registry and Rule Distribution

Phase 3 adds the foundation for multi-sensor central management.

## Architecture

```text
                    OTLens Central
             ┌────────────────────────┐
             │ Sensor Registry        │
             │ Site Management        │
             │ Rule Set Management    │
             │ Rule Assignment        │
             │ Heartbeat / Health     │
             └───────────┬────────────┘
                         │ HTTPS
              ┌──────────┼──────────┐
              ▼          ▼          ▼
           Sensor A   Sensor B   Sensor C
              │          │          │
           SQLite     SQLite     SQLite
           Detect     Detect     Detect
```

The management direction is **pull**: sensors periodically ask the central server for their current rule set. Sensor telemetry/heartbeat is **push**.

## Added components

- `internal/management`: shared management API models.
- `internal/central`: PostgreSQL-backed central repository and HTTP management API.
- `cmd/otlens-central`: Linux central management server.
- `internal/syncagent`: sensor enrollment, heartbeat and rule-set pull client.
- `db/central_phase3.sql`: PostgreSQL schema.
- `deploy/systemd/otlens-central.service`: systemd unit.

## Central API

- `GET /health`
- `POST /v1/sensors/register`
- `POST /v1/sensors/heartbeat`
- `GET /v1/sensors`
- `GET /v1/sensors/:id/sync`
- `POST /v1/rulesets`
- `PUT /v1/sensors/:id/ruleset/:ruleset`

The API supports a shared bearer token through `OTLENS_CENTRAL_TOKEN` as a bootstrap/simple deployment mechanism. Production deployments should move to per-sensor mTLS identities; the sensor model already has a certificate fingerprint field for this transition.

## PostgreSQL setup

Run `db/central_phase3.sql` against the central PostgreSQL database.

Start the central service:

```bash
export OTLENS_POSTGRES_DSN='postgres://otlens:password@127.0.0.1:5432/otlens?sslmode=require'
export OTLENS_CENTRAL_TOKEN='replace-with-a-long-random-token'
export OTLENS_CENTRAL_ADDR=':9090'
./otlens-central
```

## Sensor synchronization

The sensor-side `internal/syncagent` package provides:

1. registration;
2. periodic heartbeat;
3. periodic rule-set pull;
4. version-aware rule updates;
5. application of centrally managed custom rules through `detect.Engine.ReplaceManagedRules`.

The worker is intentionally independent from packet capture and detection. If the central server is unreachable, the local detection engine continues running; the next sync cycle retries automatically.

## Important next step

Phase 3 establishes management primitives. Before production use, Phase 4 should add:

- per-sensor mTLS enrollment and certificate rotation;
- signed rule bundles;
- persistent local management state in SQLite;
- transactional rule activation/rollback;
- central alert ingestion and deduplication;
- incident/correlation engine;
- audit trail for rule changes;
- role-based access control.
