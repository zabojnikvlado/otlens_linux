# OTLens — UDP Dashboard Data-Binding Fix

Date: 2026-08-12

## Root cause

The dashboard domain correctly requested `/v1/udp-telemetry`, and the backend
returned the aggregated sensor UDP telemetry, but the production bundle
`web/central/app-operations.js` never copied that fulfilled response into the
global `udpTelemetry` state consumed by `renderDashboard()`.

The old source fragment `web/central/views/operations.js` still contained the
assignment, which made the omission easy to miss during earlier backend work.
The same production-bundle omission also affected the active
`/udp-conversations?active=true` response.

Consequently the browser continuously rendered the initialization value:

`udpTelemetry={totals:{},protocols:{},top_protocol:''}`

This exactly produced `UDP packets = 0`, `UDP conversations = 0`,
`Top UDP protocol = —`, `UDP timeouts = 0`, and `UDP average RTT = —` even
while live UDP alerts proved that UDP traffic existed.

## Fix

- `web/central/app-operations.js` now assigns successful
  `/udp-telemetry` responses to `udpTelemetry` before dashboard rendering.
- Successful `/udp-conversations?active=true` responses are now assigned to
  `udpConversations` before UDP/topology rendering.
- `app-operations.js` cache-bust is increased from `v=27` to `v=28`.

No database migration and no sensor reset are required for this UI binding fix.
The cumulative package retains all prior sensor/backend UDP telemetry fixes.
