# OTLens documentation

## Architecture

OTLens consists of two runtime roles:

1. **Linux sensor (`cmd/otlens`)** — headless capture and detection process. It uses packet capture or IPFIX, decodes OT protocols, builds assets/flows/topology, evaluates detection rules, stores local state in SQLite, and initiates outbound synchronization to Central.
2. **Windows Central (`cmd/otlens-central`)** — the only web/API server. It serves the UI, receives sensor telemetry on the Sensor API listener, queues commands, aggregates multiple sensors, stores data in PostgreSQL, manages rules/alerts/backups, and exports selected events to SIEM.

A sensor does **not** run a dashboard, REST management API, TLS listener, CORS middleware, Basic Auth endpoint, or local vulnerability browser. No inbound HTTP port is required on a sensor. Remote management uses the existing outbound Sensor → Central synchronization channel and command queue.

## Network listeners

Central has two separate listeners:

- Web and Management API: default `8443`
- Sensor API: default `9443`

Sensors open only the configured capture interface or IPFIX UDP listener. They connect outbound to Central.

## Sensor components

- capture engine (`pcap`) or IPFIX collector
- packet parser and protocol dispatcher
- asset, hostname, flow and topology engines
- OT protocol decoders: Modbus/TCP, S7comm, EtherNet/IP/CIP, DNP3, OPC UA identification, BACnet/IP, IEC-104 and PROFINET DCP
- baseline and detection/policy engine
- OT tag/event store
- SQLite snapshotter, backup and reset operations
- Central synchronization and command worker
- optional diagnostic packet logging

## Central components

- Central Web UI and Management API
- Sensor API and sensor registration/heartbeat
- PostgreSQL repository
- topology, assets, OT tags, alerts, rules and baseline aggregation
- command queue
- PCAP analysis jobs
- Data Management and backups
- SIEM outbox/export
- audit of management mutations
- periodic sweep marking sensors offline once their heartbeat goes stale (`sensors.offline_after`/`sensors.check_interval`, see Configuration)

## Configuration

Use separate files:

- sensor template: `configs/sensor.config.example.yaml`
- Central template: `configs/central.config.example.yaml`

Sensor default path: `/etc/otlens/config.yaml`.
Central Windows default path: `C:\ProgramData\OTLens\config.yaml`.
Override either with `--config`.

The sensor configuration intentionally has no `api`, sensor-side `export`, sensor-side `audit`, or `vulnerability` section. SIEM export and management auditing are Central responsibilities.

## Persistence

Sensors use SQLite for local resilience. Central uses PostgreSQL. Sensors never connect directly to PostgreSQL.

Sensor reset and backup commands are delivered through the command queue. A stopped capture engine leaves the sensor process and sync worker running so Central can start capture again.

## UI

The only supported UI is `web/central`. It includes Sensors, Topology, Assets, OT Tags, Rules, Alerts, Analysis, Settings and Data Management. Tables support sorting and page sizes 10, 50, 100 and All.

Settings is read-only: it shows the operational values Central loaded from `central.config.yaml` at startup (sensor offline-detection thresholds, whether SIEM export/PCAP analysis/vulnerability lookup are enabled, TLS status on both listeners) via `GET /v1/settings`, plus a field to set the browser's management token. There's no corresponding write endpoint — change `central.config.yaml` and restart Central to actually change any of it.

Clicking an asset row in the Assets tab opens a vulnerability lookup for that device's vendor (`GET /v1/assets/vulnerabilities?vendor=...`), matched against an optional offline CSV snapshot (`vulnerability.csv_path` in Configuration) — see package `internal/vuln`'s doc comment for why this is vendor-only and never a live network call.

The Topology tab draws one edge per asset pair, not one per underlying flow — a sensor's raw graph has a separate flow per protocol/port combination, so a single busy pair (e.g. an HMI polling a PLC over several sessions) could otherwise produce dozens of parallel lines between the same two nodes. Central's `/topology` handler aggregates these server-side (see `aggregateEdges` in `internal/central/server.go`); the aggregated edge's tooltip shows the flow count and combined traffic.

## Authentication and roles

Central users authenticate with a username and password (bcrypt-hashed in
Postgres, never stored in cleartext) through the Web UI's login screen,
which gets a session cookie (`otlens_session`, `HttpOnly`, `SameSite=Strict`,
sent only over TLS when `web.tls.enabled` is true) — not a token the person
handles directly. Sessions use a sliding expiry (`auth.session_duration`,
6h by default): every authenticated request pushes the expiry back out, so
an active user is never logged out mid-session, but an idle one expires
that long after their last request.

Three built-in roles ship by default — Administrator (full view+action
access), Analyst (everything except starting/stopping sensors, and no
access to Settings or Data Management), and View only (Dashboard, Topology,
and Alerts, read-only). Both the tabs a role can see and the actions it can
perform are stored in Postgres (`roles.permissions`) and editable from the
Settings tab (admin only) — including editing the built-in roles'
permissions, though their ids can't be deleted. Every route is gated
server-side by the same permission check the UI uses to decide what to
show (`requireView`/`requireAction` in `internal/central/server.go`) — the
UI hiding a tab or button is a convenience, not the actual access control.

The very first time Central starts against a database with no users at
all, it creates an "administrator" account (`auth.bootstrap_username`/
`bootstrap_password`, default `administrator`/`administrator`) with a
forced password change on first login. Password validity (in days, or
never-expiring) is set per user when they're created and can be changed
later; an expired-but-not-yet-changed password still logs in but is
immediately forced through the same change-password flow as a brand-new
account. There's no self-service "forgot password" — that needs an email/
SMS system this doesn't assume, and OT networks are often air-gapped
anyway — instead an admin resets a user's password from the Users tab,
which generates a random temporary password shown exactly once (never
retrievable again) and forces a real password to be set at next login;
the reset also signs out any of that user's existing sessions.

`auth.management_token`, the single shared bearer token from earlier
versions, still works as an emergency/break-glass fallback if the session
cookie is absent or invalid — it grants full access with no per-user
identity, so it's meant for operational emergencies, not day-to-day login.
Leave it empty to disable that fallback entirely.

## Security boundaries

- Bind Central listeners only to intended interfaces.
- Protect Central with TLS and management credentials.
- Restrict PostgreSQL to Central.
- Sensors require no inbound management access.
- Long-lived configuration tokens are a transitional mechanism; per-sensor mTLS enrollment and user accounts with short-lived sessions are planned.

## Build and verification

```bash
make fmt
make test
make vet
make build-linux-sensor
make build-windows-central
```

See the phase documents for feature-specific behavior and migration notes. `PHASE3_8_2_PROJECT_CLEANUP.md` records the removal of the obsolete sensor web/API stack.

## Central Dashboard

The first tab in Windows Central is the operational Dashboard. It summarizes running, stopped and offline sensors, open alerts, detected assets, active rules, OT tags, analysis jobs, alert severities, observed OT protocols, baseline state and the most recent backup. Dashboard cards link directly to their corresponding detailed tabs. Detailed behavior is documented in `PHASE3_9_0_DASHBOARD.md`.

## Sensor packet-capture runtime diagnostics

From Phase 3.9.1, live-capture sensors require libpcap 1.10.0 or newer. Startup fails before opening the interface when an older library is detected. Heartbeats include OTLens, Go, libpcap and gopacket versions plus capture backend, interface, snap length and promiscuous mode. Central persists and displays these values in the Sensors table.
