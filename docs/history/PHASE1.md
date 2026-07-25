# OTLens Phase 1 — Linux Sensor Foundation

This branch is the first refactoring step toward a multi-sensor OTLens deployment.

## Included

- SQLite is now the runtime local persistence backend for the sensor.
- The persistence API used by the existing engines is intentionally unchanged.
- SQLite uses WAL mode, `synchronous=NORMAL`, a single writer connection, and a busy timeout.
- Existing bbolt snapshots can be imported once into the new SQLite database.
- The legacy bbolt file is never deleted automatically.
- The EventBus is concurrency-safe and supports cancellable subscriptions.
- EventBus publication is non-blocking; a slow subscriber drops its oldest queued event instead of stopping packet processing.
- Linux-friendly `pcap` naming replaces the Windows-specific `npcap` terminology in configuration and documentation. The underlying gopacket/libpcap backend remains the same and works with libpcap on Linux.
- A systemd service example is included under `deploy/systemd/otlens.service`.

## Storage layout

The local SQLite file contains a small generic key/value table:

- `assets`
- `flows`
- `tags`
- `alerts`
- `rules`
- `meta`

The existing engines still own their domain models. SQLite is only the persistence implementation, which keeps the later PostgreSQL migration behind the persistence boundary.

## Migration

With `persist.path: otlens.sqlite`, startup checks for:

1. `otlens.sqlite.bbolt`
2. `otlens.db`

If the SQLite database is empty and one legacy bbolt file exists, its buckets are imported. The original bbolt file remains untouched.

## Linux runtime

Install libpcap development/runtime support for the target distribution, then build OTLens normally. The live capture backend is still gopacket/pcap, so on Linux it uses the system libpcap implementation.

The supplied systemd unit runs the sensor as a non-root `otlens` user with `CAP_NET_RAW` and `CAP_NET_ADMIN`.

## Next phase

Phase 2 can add:

- transactional local outbox;
- sensor identity and registration;
- authenticated central ingestion API;
- retry/backoff and offline buffering;
- PostgreSQL central metadata/alert storage;
- rule distribution from central to sensor.
