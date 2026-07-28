# Healthcheck and sensor metrics

OTLens sensors now include operational metrics in the existing heartbeat. Central stores raw samples for seven days and exposes both the latest sample and selectable 15 minute, 1 hour, 6 hour, and 24 hour history.

## Web UI

- Click a row in **Sensors** to open the sensor metrics modal.
- **Healthcheck** provides an estate-wide view of sensor and Central health.
- The Dashboard includes total packet rate, active TCP streams, and operational-warning KPIs.
- Dashboard and sensor charts use device-pixel-ratio-aware canvas rendering to remain sharp on HiDPI displays.

## Sensor metrics

The heartbeat contains system memory/runtime data, capture rates, TCP reassembly counters, pipeline placeholders, sync health, capture identity, and component versions. TCP metrics include active streams, buffered bytes, gap recoveries, overlap conflicts, retransmissions, evictions, and dropped segments.

Capture and pipeline fields that the current capture backend cannot report are emitted as zero rather than guessed. They are ready for native libpcap/AF_PACKET counters in a future capture-backend iteration.

## Health states

- `healthy`: no active threshold violation
- `warning`: drop rate >= 1%, memory >= 80%, queue >= 75%, or a sync failure
- `critical`: drop rate >= 5%, memory >= 95%, queue >= 95%, or at least three consecutive sync failures
- `offline`: no recent heartbeat

The UI always displays the reasons rather than only a color.

## API

- `GET /v1/sensors/metrics`
- `GET /v1/sensors/:id/metrics?range=15m|1h|6h|24h`
- `GET /v1/healthcheck`
