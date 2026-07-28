# OTLens

Lightweight OT (operational technology) network visibility platform:
headless Linux sensors passively watch industrial network traffic, decode
OT protocols, and raise alerts; a Central server aggregates every sensor
into one web UI with PostgreSQL-backed history.

**Start here: [`DOCUMENTATION.md`](DOCUMENTATION.md)** — full installation,
configuration, and user-manual walkthrough of every Central UI tab. This
file is just a pointer.

## Quick start

```bash
make build           # bin/otlens + bin/otlens-central, current OS
bin/otlens --config configs/sensor.config.example.yaml         # sensor (edit the config first)
bin/otlens-central --config configs/central.config.example.yaml # central (edit the config first)
```

Then open `http://<central-host>:8443/ui/` and log in — see
[DOCUMENTATION.md § First login](DOCUMENTATION.md#first-login).

## Repository layout

- `cmd/otlens` — the Linux sensor (headless, no inbound port).
- `cmd/otlens-central` — Central: the only web/API server, cross-platform.
- `cmd/tools/interfaces` — small helper to list capture-able network
  interfaces when configuring a sensor.
- `internal/` — everything else, organized by engine/concern.
- `web/central/` — the Central UI (served by `otlens-central`, not a
  separate app).
- `configs/*.example.yaml` — annotated config templates for both binaries.
- `db/central_phase3.sql` — a reference snapshot of Central's PostgreSQL
  schema; not executed at runtime (Central creates its own schema
  automatically on startup).
- `DETECTION_RULES.md` — how detection rules work and how to add one.
- `DEPLOYMENT_WINDOWS_CENTRAL.md` — recommended production topology.
- `docs/history/` — phase-by-phase development log; historical record, not
  user documentation.

Module path: `github.com/zabojnikvlado/otlens_linux`.

## Build targets

```bash
make build                 # both binaries, current OS
make build-sensor           # bin/otlens
make build-central          # bin/otlens-central
make build-linux-sensor      # bin/otlens-linux-amd64
make build-windows-central    # bin/otlens-central-windows-amd64.exe
make test
make test-race
make vet
make fmt
```

## Advanced detection MVP

This build includes OT value anomaly detection, lateral movement heuristics and correlated C2 scoring. See `docs/ADVANCED_DETECTIONS.md` for signals, configuration and limitations.

## TCP stream reassembly

Generic bounded TCP stream reconstruction is documented in `docs/TCP_STREAM_REASSEMBLY.md`. SMB2/SMB3 consumes reconstructed streams by default and retains packet-level fallback when disabled.

Detailed operational and developer references are available in `docs/TCP_STREAMER_MODULE.md` and `docs/PROTOCOL_PARSERS_REFERENCE.md`.
