# otlens
Lightweight OT Network Intelligence Platform

See [DOCUMENTATION.md](DOCUMENTATION.md) for architecture, data model,
configuration reference, and the REST API surface. See
[DETECTION_RULES.md](DETECTION_RULES.md) for how the alert/detection
rules work and how to add new ones.

Quick start:

```
go get go.etcd.io/bbolt
go mod tidy
go run ./cmd/otlens --config configs/sensor.config.example.yaml
```

## Runtime architecture

- `otlens` is a headless Linux sensor. It captures or receives traffic, detects events, persists local state in SQLite, and initiates outbound synchronization to Central. It does not serve a dashboard or management API and should not expose an HTTP port.
- `otlens-central` is the only web/API server. It serves the Central UI, accepts sensor telemetry and commands, and stores aggregated data in PostgreSQL.

Central UI: `https://<central-host>:8443/ui/` (or HTTP when TLS is disabled).
Sensor API: `<central-host>:9443`; this listener belongs to Central, not to sensors.

## Build targets

OTLens is built as two separate binaries from the same Go module:

- `cmd/otlens` — Linux OT sensor
- `cmd/otlens-central` — central management/ingestion server

Build both:

```bash
make build
```

Build separately:

```bash
make build-sensor
make build-central
```

The binaries are written to:

```text
bin/otlens
bin/otlens-central
```

Run tests:

```bash
make test
make test-race
```

The Go module path is:

```text
github.com/zabojnikvlado/otlens_linux
```


## Deployment targets

The recommended production topology is Windows Central + local PostgreSQL + Linux sensors. See `DEPLOYMENT_WINDOWS_CENTRAL.md` and `deploy/windows/README.md`.

Build a Linux sensor: `make build-linux-sensor`.
Build a Windows Central binary: `make build-windows-central`.

## Runtime configuration

The sensor and Central use separate configuration files.

- Linux sensor template: `configs/sensor.config.example.yaml`
- Linux sensor default: `/etc/otlens/config.yaml`
- Central template: `configs/central.config.example.yaml`
- Windows Central default: `C:\ProgramData\OTLens\config.yaml`

Override either path with the `--config` command-line option.

## Phase 3.6 Policy & Detection Engine

OTLens now supports multi-condition custom detection rules with AND/OR groups, packet-field operators, severity, priority, simulation mode, suppression, enable/disable, editing, deletion and JSON import/export. See [PHASE3_6_POLICY_ENGINE.md](PHASE3_6_POLICY_ENGINE.md).

### Alert review

The Central Alerts tab supports checkbox-based bulk Confirm and Approve actions. Confirm acknowledges the current finding but allows a later recurrence to alert again. Approve remembers the alert pattern on the sensor and suppresses future occurrences of the same alert ID. See `PHASE3_6_4_ALERT_REVIEW_WORKFLOW.md`.

### Honeypot/lateral-movement detection

Sensors support per-asset deception scores (0–100) and a configurable honeypot threshold. Outbound communication initiated by a honeypot raises a critical lateral-movement alert and is shown as a thick red directed topology edge. See `PHASE3_6_5_HONEYPOT_LATERAL_MOVEMENT.md`.

## Phase 3.6.6 – PCAP Analysis

Windows Central now provides an Analysis tab for authenticated `.pcap`/`.pcapng` upload and import on a selected Linux sensor. The sensor processes the capture through its existing Modbus/TCP, Siemens S7comm, asset, flow, OT tag and detection pipeline. See `PHASE3_6_6_PCAP_ANALYSIS_IMPORT.md`.


## Phase 3.6.7

The Central Sensors tab supports bulk start/stop control of live capture while keeping the sensor process and Central sync online. See `PHASE3_6_7_SENSOR_START_STOP.md`.

## Phase 3.6.8 — Stable topology layout

The Central topology now disables vis-network physics after stabilization. Telemetry refreshes preserve node positions, including manual drag positions. A short constrained stabilization is performed only when a new asset is discovered; existing assets remain fixed during that pass. See `PHASE3_6_8_TOPOLOGY_STABILITY_FIX.md`.


## Phase 3.7.0 – Data Management & Backup

Central now includes management-token-protected backup and reset controls. See `PHASE3_7_0_DATA_MANAGEMENT.md` for API, safety and recovery details.


## Phase 3.8.0 – Extended OT protocol decoding

The sensor decodes Modbus/TCP, S7comm, EtherNet/IP (CIP encapsulation), DNP3, OPC UA, BACnet/IP, IEC 60870-5-104 and PROFINET DCP. See `PHASE3_8_0_EXTENDED_OT_PROTOCOLS.md`.

## Phase 3.8.1 — Advanced Data Tables

Windows Central tables support sortable data columns and independent pagination with 10, 50, 100 or all rows per page. Table preferences persist across refreshes. See `PHASE3_8_1_ADVANCED_DATA_TABLES.md`.

## Phase 3.9.0 dashboard

Windows Central now opens on a Dashboard tab with sensor health, open alerts, asset and OT-tag totals, enabled-rule coverage, PCAP queue status, severity and protocol summaries, recent activity, baseline status, and latest backup information. See `PHASE3_9_0_DASHBOARD.md`.
