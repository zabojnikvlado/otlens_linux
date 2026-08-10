# Alert history search and correlation semantics

The Alerts tab no longer treats the newest 2,000 rows as the complete alert set.
`GET /v1/alerts/search` performs server-side PostgreSQL filtering and pagination
across the complete retained `alert_history` table. The lightweight
`GET /v1/alerts` endpoint remains capped at 2,000 rows for dashboard and nearby
UI helpers that only need a recent snapshot.

Supported alert-history filters are free-text (`q`), exact sensor ID, status,
severity, date range (`from`/`to`), newest/oldest order, `limit` (max 500), and
`offset`. Free-text search covers sensor ID, alert key, type, severity, message,
and IP.

Alert review status has explicit correlation semantics:

- `new`: unreviewed/unconfirmed; participates in automatic incident correlation
  and asset-risk scoring. Correlation is intended to surface multi-stage
  activity before an analyst has manually reviewed every component alert.
- `confirmed`: analyst-confirmed genuine issue; continues to participate in
  correlation and risk.
- `approved`: analyst accepted the pattern as expected/benign; remains in
  searchable history and reports, but is excluded from new incident correlation
  and alert-driven asset-risk scoring.

Existing managed incidents are not deleted if an underlying alert is approved
later. The incident is an auditable investigation record and should be resolved
or closed through its workflow rather than disappearing retroactively.

Alert visibility is separate from retention. By default Central retains
`alert_history` for `database_retention.alerts_days` (180 days). Once retention
physically deletes a row, no UI filter can recover it; use backups or increase
retention if a longer audit window is required.
