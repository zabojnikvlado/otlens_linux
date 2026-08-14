# OTLens Analytics — schedule-aware baseline comparison

Date: 2026-08-13

## Scope

This cumulative change adds an opt-in historical baseline comparison to:

- Communication Analysis;
- Asset Traffic.

Normal Analytics queries remain unchanged unless the operator selects **Compare with baseline**.

## Operator workflow

The two supported Analytics views now contain:

- `Baseline: Off / Compare with baseline`;
- `Baseline history: 7 / 14 / 30 / 60 days` (30 days by default).

The browser sends its UTC offset with the request so schedule comparison uses the operator's local time-of-day rather than UTC clock time.

## Baseline model

The model is stable-identity based. DHCP address changes therefore do not create a new baseline for the same canonical asset identity.

Historical traffic is bucketed and zero-filled after the first historical observation so quiet periods are represented without treating time before the asset existed as zero traffic.

For each visible graph bucket the engine builds an expected envelope from historical traffic at the same local time-of-day. It prefers weekday/weekend-specific samples when at least four samples exist and falls back to all-days time-of-day samples when required.

Returned expected values include:

- median transferred bytes;
- P10 / P95 expected envelope;
- anomaly threshold;
- expected sent / received medians;
- sample count and profile source.

For short current windows, historical data is queried at a minimum five-minute resolution and normalized to the current graph bucket size. This bounds interactive 30-day reads without changing the units shown in the graph.

## Maturity

The comparison reports:

- `Learning` — less than two active history days;
- `Limited` — fewer than seven active history days;
- `Established` — fewer than fourteen active history days;
- `Mature` — fourteen or more active history days;
- `Stale` — historical traffic exists but the last baseline observation is older than seven days relative to the selected window.

The UI explicitly shows the number of active history days and requested lookback.

## UI

When baseline comparison is available, the Analytics chart adds:

- an expected P10–P95 band;
- a dashed baseline median line;
- schedule-aware anomaly markers;
- hover details with actual and expected values.

A separate Baseline comparison panel shows:

- maturity;
- traffic-volume deviation from expected volume;
- new top peers absent from the retained baseline peer set;
- new services absent from the retained baseline service set;
- schedule-aware volume anomalies;
- a `Baseline match` score (0–100, a behavior-similarity indicator rather than a security-risk score);
- expected vs observed transfer volume.

## Safety / performance

- The enhanced baseline is opt-in.
- Historical query work has a separate 15-second deadline.
- A baseline timeout never hides the current traffic graph; the response falls back to the lightweight current-window baseline and exposes a warning.
- Historical peer/service coverage is capped at 4096 ranked values and the response indicates when that cap is reached.
- No new table or database reset is required; this feature reads the existing stable-identity `flow_observations` history.
- Current graph series are now explicitly zero-filled, so quiet time retains the correct width on the time axis instead of being visually compressed.

## Deployment

Rebuild/deploy Central + Web UI. Sensor changes and database migrations are not required.

Static verification performed in the available environment:

- all Go files parse successfully;
- no duplicate package-level declarations were introduced in `internal/central`;
- `app-analytics.js` passes `node --check`;
- HTML ID uniqueness was checked.

A full `go test ./internal/central` could not complete because the environment attempted to download uncached external Go modules and timed out.
