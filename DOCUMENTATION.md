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

The only supported UI is `web/central`. It includes Sensors, Topology, Assets, OT Tags, Alerts, Rules, Analysis and Data Management. Tables support sorting and page sizes 10, 50, 100 and All.

The Topology tab draws one edge per asset pair, not one per underlying flow — a sensor's raw graph has a separate flow per protocol/port combination, so a single busy pair (e.g. an HMI polling a PLC over several sessions) could otherwise produce dozens of parallel lines between the same two nodes. Central's `/topology` handler aggregates these server-side (see `aggregateEdges` in `internal/central/server.go`); the aggregated edge's tooltip shows the flow count and combined traffic.

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
