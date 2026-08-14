# Behavior candidate Promote runtime fix — 2026-08-13

## Problem

The Candidate baseline table could make **Promote** look completely inert. Two independent behaviors caused this:

1. candidates below the configured evidence threshold were rendered with a disabled button whose label still said `Promote`; disabled HTML buttons emit no click event, so there was no feedback;
2. a real promotion was queued asynchronously and the UI used timed refreshes instead of following the state-confirmed sensor acknowledgement.

## Fix

- Candidate action labels now describe the actual state: `Collecting…`, `Excluded`, `No access`, `Promote`, `Queuing…`, `Queued…`.
- Disabled candidates include a tooltip with the current evidence and why promotion is unavailable.
- Central validates the requested candidate against the latest sensor baseline telemetry before queueing it.
- Central returns HTTP 409 when a candidate is stale/missing, excluded, or still collecting evidence instead of silently queueing an operation the sensor cannot apply.
- Identical pending promotion commands are de-duplicated.
- The browser polls `/baseline` after queueing and waits for the sensor's `promoted_candidates` telemetry acknowledgement.
- UI status text reports queued, confirmed, still-pending, and failed states explicitly.
- `app-nba.js` cache version is bumped to v38.

## Evidence threshold

The current default sensor configuration requires 20 observations across 3 distinct days before a normal candidate is ready for promotion. This patch does not weaken that trust threshold; it makes the state visible instead of presenting a dead-looking Promote button.

## Deployment

Rebuild/deploy Central + Web UI. The sensor-side state-confirmed promotion support is already present in the cumulative source. No database migration or reset is required.
