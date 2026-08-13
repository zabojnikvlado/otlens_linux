# OTLens — Network / Zone Analytics runtime & UI-state fix

Date: 2026-08-12

## Symptoms

- Network / Zone Traffic remained on `Loading traffic analytics…` for a long time or ended with a generic load failure.
- After a failed request, the old `Traffic analytics could not be loaded` card remained visible while a new Analyze request was already running.
- Broad scopes such as `Any ↔ Device category: IT` were especially expensive.

## Root causes

1. The bundle query materialized the filtered flow working set, but then scanned that materialization separately for series, summary, protocols, ports and peers. On a broad six-hour scope the same working set could be traversed five times.
2. Historical baseline was part of the same success/failure path as the current graph. A slow baseline query therefore blanked an otherwise valid current-window result.
3. UI error state was written directly into the KPI container and was not cleared at the beginning of a new request, on filter changes, or when re-entering the Analytics view.

## Fixes

- Replaced the five aggregate rescans with one PostgreSQL `GROUPING SETS` aggregation plus ranking of top protocol/port/peer rows.
- Current-window query has an independent execution budget.
- Historical baseline is best-effort with a short timeout. The visible current series is always used as a fallback baseline, so baseline slowness cannot make the whole dashboard fail.
- Selected VLAN/Zone/Purdue/Category scopes that resolve to zero current assets return an immediate empty analytics response rather than executing a broad `AND FALSE` query path.
- A new Analyze request immediately removes a stale error card and shows a loading state.
- Changing filters or re-entering an Analytics tab clears a stale error state until a new request actually fails.
- Analyze is disabled while its request is running, and a repeated request still aborts the previous browser request.
- Error status includes Central `request_id` when available.
- `app-analytics.js` cache version bumped to v5.

## Validation performed

- `node --check web/central/app-analytics.js`
- all 215 Go source files parsed successfully with `go/parser`
- `gofmt` on changed Go files
- added regression tests asserting the grouping-sets query shape and empty resolved-scope short-circuit

A full package test could not complete in this environment because required external Go modules were not locally cached and dependency download timed out.

## Deployment

Rebuild/redeploy Central + Web UI. Sensor and database reset are not required. No new schema migration is required for this fix.
