# OTLens Analytics UI Style Alignment — 2026-08-12

## Scope

Reviewed the four new Analytics views against the existing OTLens Central UI design system:

- Communication analysis
- Asset traffic
- Network / zone traffic
- Protocol analytics

The review compared the Analytics HTML/CSS/JS against Dashboard, explorer, inventory and shared Central form/panel primitives.

## Findings corrected

1. Analytics page headings used 22 px while the operational Dashboard uses 27 px display headings.
2. Analytics filters used `var(--bg)` and custom padding rather than the shared raised-panel form-control treatment.
3. Analytics KPI cards overrode the shared Dashboard KPI height to 84 px, making them visually denser than the rest of Central.
4. Static Analytics KPI cards inherited the Dashboard clickable hover lift even though they have no click action.
5. Analytics panels used 14 px padding while Dashboard panels use 18 px.
6. Analytics legends were smaller than the existing metric legends.
7. Breakdown tracks used a one-off 9 px height instead of the established 8 px metric/bar treatment.
8. Analytics KPI responsiveness did not follow the Dashboard 4 → 2 → 1 column behavior.
9. The chart renderer forced a minimum 600 px backing width and a 320 px inline height, partially defeating responsive CSS on narrow displays.
10. The canvas font did not explicitly use the Central mono typeface.

## Result

Analytics now follows the same Central visual language:

- 27 px display page heading;
- shared `--panel`, `--panel-raised`, `--line`, `--text`, `--text-dim`, `--ot`, `--warn`, and `--crit` tokens;
- 34 px form controls with the same padding, typography and focus ring as other Central forms;
- Dashboard-style KPI cards and 4/2/1 responsive grid;
- 18 px desktop panel padding and 14 px compact mobile padding;
- 15 px display-font panel headings;
- 12 px metric legends and 8 px bar tracks;
- responsive 320/260 px chart height and no forced 600 px minimum canvas width;
- IBM Plex Mono canvas labels.

The time-series chart intentionally remains taller than ordinary Dashboard sparklines because it is the primary analytical content rather than a compact summary widget.

## Cache busting

- `style.css?v=27` → `style.css?v=28`
- `app-analytics.js?v=1` → `app-analytics.js?v=2`

A normal reload should obtain the new files; a hard refresh is still recommended after deploying a replaced Central binary/static bundle.

## Validation

- `node --check web/central/app-analytics.js` passed.
- `node --check web/central/app-core.js` passed.
- CSS opening/closing brace counts match.
- Only Web UI files were changed; no database or sensor change is required.
