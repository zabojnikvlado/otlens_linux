# Phase 3.9.0 — Central Dashboard

The Windows Central web console now opens on a dedicated Dashboard tab. The dashboard is built from the same management API data already used by the detailed tabs and refreshes with the existing ten-second Central polling cycle.

## Primary indicators

The first row shows:

- running sensors,
- stopped sensors,
- offline sensors,
- open alerts (`status = new`),
- detected assets,
- enabled rules out of all rules,
- observed OT tags,
- pending or running PCAP analysis jobs.

Every indicator is clickable and opens the corresponding detail tab.

## System health

A combined health banner provides an immediate operational summary:

- **Healthy** — no offline or stopped sensors and no open alerts,
- **Warning** — at least one stopped sensor or an open non-critical alert,
- **Critical** — at least one offline sensor or an open critical alert.

## Additional dashboard panels

- Open alert distribution by severity.
- OT protocol distribution based on protocols observed on assets, with OT tags used as a fallback source.
- Recent open security activity.
- Baseline state.
- Latest Central backup time.
- Number of unconfirmed assets.
- Last successful UI refresh time.

The dashboard does not duplicate the topology map or complete data tables. It is intended as a concise operational overview and links to the existing detailed views.

## Implementation

The dashboard is implemented in the Central static UI:

- `web/central/index.html`
- `web/central/app.js`
- `web/central/style.css`

No additional inbound service, database table, or sensor endpoint is required.
