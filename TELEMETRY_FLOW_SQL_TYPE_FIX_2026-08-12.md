# Telemetry flow SQL type fix — 2026-08-12

## Symptom

Central returned HTTP 500 for `POST /v1/sensors/telemetry` with:

`persist flow observations: ERROR: operator does not exist: timestamp with time zone <= text (SQLSTATE 42883)`

## Root cause

The set-based flow insert uses a derived PostgreSQL `VALUES` table. Bind parameters inside that untyped `VALUES` relation can be resolved as `text`. The event-time identity lookup then compared `asset_ip_binding_history.valid_from` / `valid_to` (`TIMESTAMPTZ`) against `v.bucket_end` / `v.bucket_start` from the derived relation, producing the type mismatch.

## Fix

`persistFlowObservations` now explicitly casts every derived `VALUES` field before use:

- timestamps -> `timestamptz`
- ports/VLAN -> `integer`
- counters -> `bigint`
- OT flag -> `boolean`
- identifiers/IP/protocol fields -> `text`

The event-time identity predicates also explicitly compare `TIMESTAMPTZ` to `TIMESTAMPTZ`.

This prevents the timestamp error and avoids a follow-on numeric/boolean-vs-text error in the same batch insert.

## Deployment

Central only. No sensor rebuild, database reset, or schema migration is required.
