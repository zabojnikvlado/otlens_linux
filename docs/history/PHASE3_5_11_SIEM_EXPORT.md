# Phase 3.5.11 - Central SIEM export

Central can export alerts and management audit events to an HTTP(S) SIEM
collector. The feature is configured under `siem:` in the Central config.

## Delivery model

Events are first inserted into PostgreSQL table `siem_outbox`. A background
worker POSTs each event as JSON. HTTP/network errors are recorded and retried
with incremental backoff. A SIEM outage does not block sensor telemetry,
management actions, or the Central UI.

## Event types

- `kind: "alert"`: alert snapshots received from sensors. A changed alert
  count, status, or last-seen value is treated as a new exportable event.
- `kind: "audit"`: mutating management API operations such as rule creation,
  rule toggle/delete, asset confirm/delete, alert review, and ruleset changes.

## JSON envelope

```json
{
  "source": "otlens-central",
  "kind": "alert",
  "event_time": "2026-07-23T18:30:00Z",
  "sensor_id": "sensor-001",
  "alert": {}
}
```

Audit events use an `audit` object containing method, path, HTTP status,
source IP, user agent, sensor/rule identifiers, and success state.

## Security

The client supports public or private CA validation, optional mutual TLS,
Bearer authentication, and custom HTTP headers. Do not use
`insecure_skip_verify: true` in production.
