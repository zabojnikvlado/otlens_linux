# OTLens — UDP zero-KPI pipeline fix

Date: 2026-08-12

## Symptom

Central showed live `New UDP communication` alerts while Dashboard reported:

- UDP conversations: 0
- UDP average RTT: —
- UDP timeouts: 0
- Top UDP protocol: —
- UDP packets: 0

This combination proved that packet parsing/detection was seeing UDP, while the separate UDP conversation telemetry path was not contributing counters.

## Root causes fixed

1. When `capture.udp_conversations.enabled=false`, `udpconversation.Engine` intentionally forwarded UDP packets to DNS/protocol parsers but skipped `Manager.ObserveWithContext`. Because packet/byte/protocol counters lived inside that method, disabling conversation retention also incorrectly disabled UDP traffic telemetry.
2. Packet counters were incremented only after conversation admission. Packets rejected because the per-conversation retention ceiling had been reached were omitted from traffic telemetry even though the sensor had observed them.
3. Central trusted `udp_telemetry` as the only packet-count source. A disabled tracker, tracker reset, older sensor, or mixed-version rollout could therefore produce all-zero UDP KPIs even while the independent flow engine was reporting UDP edges.
4. Dashboard did not expose whether a sensor had UDP conversation retention disabled or whether Central was using compatibility flow fallback.

## Changes

### Sensor

- UDP packet/byte/protocol counters are now traffic counters, independent of conversation retention.
- Disabled conversation tracking still keeps lightweight UDP traffic counters while retaining zero 4-tuple conversations as configured.
- Packets beyond `max_packets_per_conversation` still count toward UDP traffic telemetry.
- `udp_telemetry` includes `udp_conversation_tracking_enabled`.
- Heartbeat metrics schema v5 includes an `udp_pipeline` diagnostic block with:
  - tracking enabled state;
  - active conversations;
  - packets/bytes total;
  - created/expired/evicted conversations;
  - packets dropped from conversation tracking.

### Central

`GET /v1/udp-telemetry` now uses a conservative per-sensor fallback from the latest topology flow snapshot when the sensor counter/conversation data for that sensor is empty:

- recent UDP flow edges can supply active conversation count;
- UDP flow packet counts can supply a non-zero packet fallback;
- well-known UDP ports provide DNS/DHCP/NTP/SNMP/SIP/DTLS/OpenVPN/BitTorrent/generic UDP protocol fallback.

The endpoint returns diagnostics showing how many sensors required flow fallback and how many explicitly reported conversation tracking disabled.

### Web UI

- UDP packet detail changes to `Observed via flow fallback` when compatibility fallback is in use.
- UDP conversation detail reports `Conversation retention disabled on sensor` when applicable.
- `app-detection.js` cache version bumped to v33.

## Important Dashboard semantics

Several other zero values are not communication counters and can legitimately remain zero while network traffic exists:

- `Threat intel hits` = only traffic matching malicious IP/domain intelligence.
- `SMB risk activity` = risky SMB artifacts/operations such as admin shares, scripts or executables; ordinary SMB traffic does not increment it.
- `Operational warnings` = unhealthy/stopped/offline sensor conditions.
- `OT anomalies` = open OT process-value anomalies.
- `Profiled assets` = assets with passive/recon identity profile evidence; it is not the detected asset count.
- `Asset coverage` = assets with hostname + vendor + OS evidence.
- `Exposure` = confirmed or accepted-risk vulnerability findings.
- `PCAP analysis queue` / `Recon jobs` = queued/running jobs, not observed traffic.

## Validation performed

- `go test ./internal/udpconversation` passes.
- Added tests for disabled conversation tracking retaining packet/protocol telemetry.
- Added test that packet telemetry continues beyond the per-conversation retention ceiling.
- Added Central topology-fallback unit tests; full Central package execution is blocked in this environment by unavailable external module downloads, but all Go files parse and `gofmt` cleanly.
- `node --check web/central/app-detection.js` passes.

No database reset or schema migration is required for this fix.
