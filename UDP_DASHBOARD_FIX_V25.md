# OTLens v25 — UDP Dashboard Telemetry Fix

Date: 2026-08-12

## Problem

The Central dashboard contained UDP KPI cards, and `/v1/udp-telemetry` was already part of the dashboard data domain, but the JavaScript module actually loaded by `web/central/index.html` (`app-detection.js`) did not render those fields. The equivalent render code existed only in the unused `web/central/views/detection.js` fragment, so the browser kept the static HTML defaults (`0` / `—`).

A second issue made `Top UDP protocol` fragile: Central derived it only from conversations still active in the current sensor snapshot. With a 30 second conversation idle timeout, short DNS/DHCP/NTP bursts could disappear before the next dashboard refresh and the KPI could return to `—` even though UDP traffic had been observed.

The timeout KPI was also narrower than its label: the sensor supplied the DNS timeout counter only, while DHCP/NTP/SNMP/SIP/DTLS/OpenVPN/BitTorrent correlations maintain their own timeout state.

## Fixes

### Web UI

- `web/central/app-detection.js` now renders:
  - active UDP conversations;
  - correlated UDP average RTT;
  - UDP request timeouts;
  - top UDP protocol;
  - cumulative UDP packet count.
- The packet KPI shows `udp_packets_total` directly, so the first page load no longer falsely shows zero because a browser-side rate baseline has not yet been established.
- `web/central/index.html` cache-busts `app-detection.js` to `v=32`.
- KPI descriptions now state that top protocol is based on observed packets and UDP packets are cumulative since sensor start.
- The legacy `web/central/views/detection.js` fragment was kept consistent with the loaded module to prevent the same divergence on a future module rebuild.

### Sensor UDP telemetry

- `udpconversation.Manager` now maintains cumulative per-protocol packet counters for:
  - DNS
  - DHCP
  - NTP
  - SNMP
  - SIP
  - DTLS
  - OpenVPN
  - BitTorrent
  - generic UDP
- Counters use `atomic.Uint64`; no global packet-path mutex was added.
- Counters survive conversation idle expiry and reset only on explicit manager reset/process restart.
- Telemetry now includes `udp_protocol_packets_total`.

### UDP timeout telemetry

- `protocolobs.Engine` maintains a cumulative timeout counter for DHCP/NTP/SNMP/SIP/DTLS/OpenVPN/BitTorrent completed correlations.
- Sensor telemetry reports `DNS timeouts + protocol-engine timeouts` as `udp_request_timeouts_total`.
- The count is independent of the bounded protocol-exchange history.

### Central aggregation

- `/v1/udp-telemetry` accepts both old numeric-only sensor telemetry and the new nested protocol-counter field.
- Active-conversation protocol counts remain available as `protocols` for compatibility.
- Cumulative packet counts are returned as `protocol_packets`.
- `top_protocol` prefers cumulative packet counts and falls back to active conversations for older sensors during a rolling upgrade.
- Ties are deterministic.

## Validation performed

- `gofmt` applied to all changed Go files.
- `node --check` passed for the changed dashboard JavaScript.
- With a temporary Go 1.23-compatible copy of `go.mod`, the dependency-free changed packages passed:
  - `go test ./internal/udpconversation ./internal/protocolobs`
  - `go test -race ./internal/udpconversation ./internal/protocolobs`
- The production source retains `go 1.25.0` in `go.mod`.
- Full Central/build tests cannot run in this environment because Go 1.25 and uncached external dependencies cannot be downloaded.

## Deployment

Deploy/rebuild both the Sensor and Central/Web UI. A database migration is not required for this UDP telemetry fix.

After deployment, verify `/v1/udp-telemetry` contains non-zero `udp_packets_total` when UDP is present and a `udp_protocol_packets_total` object after the updated sensor has sent telemetry. Then hard-refresh the browser once if an older cached UI bundle is still open.
