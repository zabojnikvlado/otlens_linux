# Phase 3.8.1 — Advanced Data Tables

Windows Central now uses a reusable client-side data-table component for every operational table.

## Covered tables

- Assets
- OT Tags
- Alerts
- Rules
- PCAP Analysis jobs
- Sensors
- Central backups

## Sorting

Every data column can be sorted by clicking its header. A second click reverses the direction. Selection-checkbox and action columns are intentionally excluded.

The comparator recognizes:

- IPv4 addresses
- numeric values and file sizes
- timestamps
- severity levels
- natural text and version-like values

The active header displays an ascending or descending indicator. Keyboard sorting with Enter or Space is supported and `aria-sort` is maintained.

## Pagination

Each table has an independent page-size selector:

- 10
- 50
- 100
- All

The footer shows the visible range, total number of records, current page and Previous/Next controls. Pagination is applied after filtering and sorting.

## Persistence

Sort column, sort direction, page size and current page are stored in browser local storage separately for every table. Periodic telemetry refreshes preserve the selected view.

## Implementation

The shared component is located at:

```text
web/central/datatable.js
```

It works with existing table renderers and does not alter the Central API or database schema.
