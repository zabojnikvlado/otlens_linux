# Behavior candidate promotion acknowledgement diagnostics fix

Date: 2026-08-14

## Problem

A candidate promotion could remain indefinitely in `promotion queued` state. Central intentionally keeps `baseline.candidate.promote` commands pending until the sensor proves the operation in telemetry. Successful promotions were reported, but failed sensor-side promotions were only written to the sensor log. Central therefore had no terminal failure state and replayed the command forever.

The disabled `Queued…` button also retained normal secondary-button hover/focus visuals, so it could appear interactive even though the browser would not execute its click handler.

## Fix

- Behavior baseline now retains recent promotion failures with candidate ID, error and timestamp.
- Sensor logs command receipt with command ID and target.
- A failed promotion is exposed in behavior telemetry as `promotion_failures` and persisted with the behavior baseline snapshot.
- Central acknowledges a pending promotion command when telemetry reports either success (`promoted_candidates`) or failure (`promotion_failures`).
- Candidate UI renders a terminal failed state as `promotion failed` with a `Retry` action and the sensor-side error in the tooltip/details.
- Successful retry clears the prior failure record.
- `Queued…` buttons are truly non-interactive (`pointer-events:none`) and cannot acquire the normal hover/focus border; the clicked button is blurred as soon as it enters the queued state.

## Upgrade behavior

Existing queued promotion commands are preserved. After deploying the updated sensor, they are replayed idempotently. Each command will then resolve as either promoted or failed instead of remaining queued without explanation.

No Central database migration or reset is required.
