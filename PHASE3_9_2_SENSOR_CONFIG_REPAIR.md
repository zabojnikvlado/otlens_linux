# Phase 3.9.2 — Sensor configuration and build repair

## Fixed

- Restored the `central` section in `configs/sensor.config.example.yaml`.
- Documented the Sensor API URL, sensor identity, site, token, synchronization interval, timeout, and TLS verification setting.
- Added startup validation for required Central connection values when `central.enabled: true`.
- Restored the missing `core.Event` envelope used by the event bus.
- Added `-buildvcs=false` to the supplied Makefile and build script so builds also work from WSL-mounted repositories with Git ownership restrictions.

## Sensor-to-Central functions verified in source

The sensor still contains outbound registration, heartbeat, rule/command synchronization, telemetry upload, and Central PCAP analysis job handling through `internal/syncagent`.
