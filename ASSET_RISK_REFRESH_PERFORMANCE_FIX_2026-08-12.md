# OTLens — Asset Risk Refresh Performance Fix

Date: 2026-08-12

## Problem

The background asset-risk refresh was timing out with `context deadline exceeded` while sensor telemetry itself was already healthy (`POST /v1/sensors/telemetry -> 200`). The risk calculator executed multiple SQL reads and writes per active asset. With ~169 assets this produced roughly one thousand database operations per refresh, including repeated scans of alert, vulnerability, flow, topology, exception and risk-history data.

## Fix

`RecalculateAssetRisk` is now set-based:

- current canonical assets are loaded once;
- active high/critical alert counts are loaded once for all stable identities, including event-time legacy IP attribution;
- vulnerability counts are loaded once;
- seven-day external exposure is evaluated once across flow history, using stored stable identities and event-time binding fallback only for legacy rows;
- risky-neighbour propagation is loaded once;
- active risk exceptions are loaded once;
- previous current risk scores are loaded once;
- all computed current risk rows are written with one `jsonb_to_recordset` bulk UPSERT;
- changed history points are written with one bulk INSERT;
- stale current-IP risk rows are removed once at the end.

The calculation semantics and score caps are preserved.

## Migration v20

Adds read-performance indexes for:

- active high/critical alerts by stable identity;
- vulnerability findings by identity/IP and status;
- recent topology edges used for propagation;
- current risk lookup by stable identity.

No reset is required.

## Runtime diagnostics

The background risk budget is 45 seconds after the set-based rewrite. If a successful refresh still takes more than five seconds, Central logs:

`asset risk refresh completed slowly: duration=...`

On failure it logs the elapsed time as well.

## Validation

- `gofmt` applied to modified Go files.
- All 215 Go source files parse successfully with the Go parser.
- Full `go test ./internal/central` could not finish in the sandbox because required external modules were not cached and dependency downloads exceeded the execution window.
