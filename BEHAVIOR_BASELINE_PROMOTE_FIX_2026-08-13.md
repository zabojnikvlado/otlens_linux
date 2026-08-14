# Behavior baseline candidate Promote fix — 2026-08-13

## Problem

The Candidate baseline `Promote` action was effectively fire-and-forget. Central marked `baseline.candidate.promote` commands delivered as soon as the sensor downloaded them. The UI refreshed after 1.5 seconds, commonly before the next sensor telemetry snapshot, so the row reverted to `Promote` and looked like a no-op. If the sensor failed to apply the promotion, Central had no state-level acknowledgement and no retry.

## Fix

- `baseline.candidate.promote` is now a state-confirmed sensor command and remains pending after download.
- The behavior baseline engine retains recently promoted candidate IDs for seven days and exposes them in behavior status telemetry.
- Promotion is idempotent while the acknowledgement is retained, so repeated `/sync` command delivery is safe.
- Recently promoted IDs are persisted in the sensor snapshot (behavior snapshot version 6), so a sensor restart cannot lose the acknowledgement before Central sees it.
- A successful promotion immediately flushes the sensor persistence snapshot.
- Central acknowledges only candidate IDs explicitly reported in `behavior.promoted_candidates` telemetry.
- `/baseline` exposes pending candidate promotion targets to the UI.
- Candidate rows now show `promotion queued` / `Queued…` until telemetry confirms application.
- The Promote API returns an explicit JSON `202 Accepted` response with status, sensor ID and candidate ID.
- UI refreshes at short intervals after queueing, without reverting the button to an apparently idle state.

## Compatibility

No PostgreSQL migration or database reset is required. Sensor and Central/Web UI should both be rebuilt/deployed because the acknowledgement is carried in sensor behavior telemetry.

## Validation

- `go test ./internal/behaviorbaseline` passes, including idempotent promotion and persistence/restore acknowledgement coverage.
- All Go source files parse successfully.
- `web/central/app-nba.js` passes `node --check`.
