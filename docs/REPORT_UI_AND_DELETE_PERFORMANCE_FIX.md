# Report presentation and delete performance

## Report presentation

Generated HTML reports now use a responsive operational-report layout with:

- branded header and reporting period,
- four KPI cards,
- severity distribution with percentages,
- clearer correlated incident and sensor-health sections,
- print-friendly styles,
- improved standalone PDF typography, section rules, header, and page numbering.

## Report deletion

The Reports page previously called `refreshAll()` after a successful delete. That function reloads nearly every Central API resource, so the deleted row remained visible until all unrelated requests completed.

Deletion now:

1. disables and fades the selected row,
2. sends the DELETE request,
3. removes the report from the local list immediately after success,
4. performs a small targeted `/reports` refresh in the background.

This makes confirmation immediate and avoids waiting for topology, alerts, assets, audit, settings, and other unrelated endpoints.
