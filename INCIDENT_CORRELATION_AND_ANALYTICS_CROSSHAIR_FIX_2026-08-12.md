# OTLens — Incident correlation timeout & Analytics crosshair fix

Date: 2026-08-12

## Incident correlation timeout

Observed Central log symptom:

`incident correlation refresh failed: timeout: context deadline exceeded`

Telemetry ingestion itself remains healthy (`POST /v1/sensors/telemetry -> 200`). The timeout came from the asynchronous incident correlation refresh.

### Root cause

`SyncCorrelatedIncidents` re-read and regrouped the complete active alert window for every enabled rule on each refresh. The built-in Multi-stage activity rule has a 1440-minute lookback. On installations with tens of thousands of retained active alerts, the same unchanged rows were repeatedly scanned and grouped even when only one or zero assets had changed.

### Fix

- Added an incremental `incident_correlation_watermark` stored in `central_runtime_state`.
- On upgrade, the watermark begins five minutes before the newest retained alert instead of replaying the entire retained alert history.
- Each refresh first resolves only stable asset identities whose alert `last_seen` advanced after the watermark.
- Full rule windows are then evaluated only for those changed identities, preserving multi-stage and sequence correlation semantics.
- Network Behavior Analytics candidates are also bounded by the watermark.
- The watermark advances only after a successful correlation transaction and is based on the newest processed alert timestamp, not the Central wall clock.
- Incident reset updates both the correlation cutoff and watermark, so old retained alerts cannot recreate cleared incidents.
- Added partial/expression indexes for active identity correlation and behavior candidates.
- Slow/failing correlation logs now include elapsed duration.

Database migration: **v21 — incremental incident correlation**. No reset is required.

## Analytics vertical hover axis

All four traffic Analytics canvases share one renderer, so the interaction is implemented centrally:

- Communication Analysis
- Asset Traffic
- Network / Zone Traffic
- Protocol Analytics

When the pointer is over a graph:

- a vertical dashed guide follows the exact mouse X position;
- the nearest time bucket is selected;
- A→B / B→A (or equivalent sent/received) points are highlighted;
- the timestamp is drawn next to the guide;
- the existing detail line shows timestamp, both directional byte counts, connections and anomaly ratio.

On mouse leave the original chart is restored. The renderer keeps a bitmap of the base chart and paints only the overlay during hover, avoiding a full chart reconstruction on every mousemove. Mousemove rendering is throttled through `requestAnimationFrame`.

`app-analytics.js` cache version is bumped from v6 to v7.

## Validation performed

- All Go sources parsed successfully with Go's parser: 215 files.
- Modified Go sources were formatted with `gofmt`.
- `web/central/app-analytics.js` passes `node --check`.
- `web/central/app-core.js` passes `node --check`.
- Full `go test ./internal/central` could not finish in this environment because external Go dependencies are not cached and downloads time out.
