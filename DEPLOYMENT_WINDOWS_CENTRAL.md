# OTLens deployment: Windows Central + PostgreSQL + Linux Sensors

## Components

- `cmd/otlens`: Linux-only sensor deployment. Captures OT traffic, parses protocols, detects locally, stores local state in SQLite and synchronizes with Central.
- `cmd/otlens-central`: cross-platform Go central service. It can run on Windows or Linux and uses PostgreSQL.
- PostgreSQL: colocated on the same Windows server as Central in the recommended deployment.

## Build matrix

| Component | Target | Build |
|---|---|---|
| Sensor | Linux amd64 | `make build-linux-sensor` |
| Central | Windows amd64 | `make build-windows-central` |
| Central | current OS | `make build-central` |

The repository remains one Go module, but the deployments are separate binaries.

## Runtime flow

```text
Linux Sensor
  ├─ packet capture
  ├─ local detection
  ├─ SQLite
  └─ outbound sync
        │
        ▼
Windows Central
  ├─ sensor management
  ├─ rule management
  ├─ correlation/management services
  └─ PostgreSQL client
        │
        ▼
127.0.0.1:5432
PostgreSQL
```

The sensor never connects directly to PostgreSQL.

## Recommended network policy

- Sensor -> Central: outbound TCP to Central's Sensor API port (default
  9443).
- Central -> PostgreSQL: localhost TCP 5432 (or wherever `database.host`
  points).
- Sensor networks -> PostgreSQL: denied.
- Internet -> PostgreSQL: denied.

## Future hardening

1. mTLS per sensor.
2. TLS termination at Central/reverse proxy.
3. Signed rule bundles.
4. Persistent local rule state and transactional rollback.
5. Central alert ingestion and incident correlation.

RBAC and an audit trail already exist — see `DOCUMENTATION.md`'s
"Roles and permissions" section.

## Data management and backup

Central includes backup and reset controls under the Data Management tab
(admin only) — see `DOCUMENTATION.md`'s "Data Management" section for
what each operation does and its safety confirmations.
