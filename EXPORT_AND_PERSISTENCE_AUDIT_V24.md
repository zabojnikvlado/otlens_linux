# OTLens v24 — Alert persistence and outbound/export audit

Date: 2026-08-11

## Scope

This audit covers the current cumulative v24 tree from sensor persistence through Central alert history and every explicit outbound/download path found in the codebase:

- sensor SQLite persistence and sensor backup,
- Alerts counters and review/activity semantics,
- SIEM HTTP JSON export,
- alert email and webhook notifications,
- scheduled/manual reports and PDF rendering,
- Central core JSON snapshots,
- Rules JSON export/import,
- UDP JSON/CSV export,
- diagnostics ZIP,
- browser-side download handling.

No syslog, CEF, LEEF, Splunk-specific, QRadar-specific, or Sentinel-specific exporter exists in this tree. The SIEM integration is HTTP JSON.

## 1. Sensor alert persistence — verdict

The sensor does persist alerts in the configured SQLite database. Alert ID, count, status, first/last seen, synced state and evidence are serialized in the `alerts` bucket and restored through `DetectEngine.RestoreAlerts` before engines start. A graceful SIGINT/SIGTERM calls `Application.Shutdown`, and `Snapshotter.Close` performs a final flush.

A Central “active alerts” count beginning near zero after a sensor restart is therefore not by itself evidence that the sensor alert database was reset. Central defines **active** as a non-approved alert observed during the last five minutes. Historical/unreviewed rows can remain in `alert_history` while the active counter starts low and rises as traffic causes findings to recur.

Two persistence-hardening changes were made:

1. The sensor now logs the absolute SQLite path, whether that file existed before startup, its pre-open size, flush interval and retention. This catches the common case where the same relative `persist.path` is launched from a different working directory and therefore opens a different file.
2. Alerts are restored before unrelated asset/flow/baseline state. Older restore ordering could abort on an incompatible unrelated bucket before the alert bucket was reached. The startup warning now states that restore was incomplete rather than falsely claiming the whole process started from empty state.

On startup verify these log records:

- `Sensor persistence database opened` — `database=...`, `existed_before_start=true`
- `Restored persisted alerts from disk` — `alerts=...`, `alerts_synced=...`, `alerts_dirty=...`, `alerts_unreviewed=...`

The supplied project config uses a relative `persist.path` (`otlens.sqlite`). Under the supplied systemd unit the working directory is `/opt/otlens`; a manually launched binary from a different directory can therefore open another SQLite file unless an absolute path is configured.

A round-trip persistence test was added for alert ID/count/status/synced/timestamps/evidence.

### Remaining persistence limits

- Persistence is snapshot based. An unclean kill can lose up to one flush interval of the newest in-memory changes. Graceful shutdown performs a final flush.
- Retention may legitimately prune old sensor alerts according to `persist.retention`.
- The user's actual SQLite file was not supplied, so this audit verifies code behavior and adds runtime proof logging; it cannot state how many rows are physically present in that specific file.

## 2. Alerts counters — fixed

The sidebar Alerts badge previously displayed Central's five-minute **active** count. This was misleading because the Alerts tab is a retained analyst review queue.

The badge now displays **unreviewed (`status='new'`)** alerts. The Alerts page summary separately displays:

- matching query rows,
- active in the last 5 minutes,
- unreviewed,
- total retained.

So a state such as `238 active · 2,200 unreviewed · 2,200 retained` is explicit rather than showing only `238` beside Alerts.

## 3. SIEM HTTP JSON — fixed and hardened

### Fixed

- Alert `event_time` now uses the alert observation time (`last_seen`, then `first_seen`) instead of telemetry upload time.
- Alert event identity hashes the complete alert snapshot, so evidence/severity/message changes are not silently suppressed by an overly narrow dedup key.
- Payloads have `schema_version=otlens.siem.v1`, stable `event_id`, source, kind and sensor identity.
- HTTP sends stable `X-OTLens-Event-ID` and `Idempotency-Key` headers.
- Redirects are rejected, preventing a 301/302/303 from turning an ingestion POST into a GET and being misreported as success.
- SIEM URL is validated as absolute HTTP(S); TLS has a minimum of TLS 1.2.
- Non-2xx responses are failures and include a bounded response-body diagnostic.
- Database failures while marking delivery/failure are no longer ignored.
- Delivered queue rows are removed; `alert_history` and `audit_log` remain the authoritative history.
- Finite `max_attempts` produces an observable exhausted/dead-letter count in Settings/diagnostics.
- The configured SIEM `source` is frozen into the event when queued. A later config change cannot mutate the payload while reusing the same idempotency key.
- Audit SIEM export now originates from the authoritative `audit_log` insert itself. Every persisted audit row, including rich GET export records such as rules/backup/diagnostics downloads, is queued atomically with stable `audit:<db-id>` identity; the old middleware-only subset is removed.
- **Important:** temporarily disabling `export_alerts` or `export_audit` no longer deletes already queued events as if delivered. Disabled kinds remain in the outbox and resume if re-enabled. New events of a disabled type are not queued.

### Delivery guarantee

SIEM is **at-least-once**, not exactly-once. If the receiver accepts an event and Central loses the acknowledgement before recording it, Central can retry. The receiver should deduplicate on `event_id` / `Idempotency-Key`.

## 4. Real-time email/webhook notifications — fixed, but intentionally best-effort

### Fixed

- SMTP connect has a 10 s timeout and the full exchange has a 30 s deadline.
- TLS minimum is 1.2; implicit TLS on port 465 and STARTTLS behavior are handled explicitly.
- Mail headers are sanitized against CR/LF injection and envelope values are checked.
- Webhook payload now contains stable event identity, sensor/alert keys, severity/type/message/IP/status/count/timestamps/evidence and schema version.
- Webhook uses `X-OTLens-Event-ID` / `Idempotency-Key`, rejects redirects, has bounded timeouts and treats only 2xx as success.
- Configuration validation rejects invalid severity, incomplete SMTP settings and invalid webhook URLs.
- Notification work is detached from the sensor telemetry request context so an HTTP response completing does not cancel an in-progress notification.
- New-alert detection now checks the SQL `RETURNING` result directly instead of silently ignoring a row-scan failure.

### Remaining limitation

Notifications are still fire-and-forget and have no durable notification outbox. A Central crash during a notification can lose that notification. SIEM should be used for a durable external event stream.

## 5. Scheduled/manual reports and PDF — fixed

### Data correctness

- Report KPI queries now run in one read-only, repeatable-read PostgreSQL transaction. A concurrent sensor sync cannot produce a report whose tables represent different database moments.
- The report distinguishes **unreviewed alerts** from **active in the last five minutes**.
- Severity normalization and exact report-period incident queries were corrected.

### Persistence/delivery

- A report is saved to `report_history` before SMTP delivery is attempted.
- Scheduled report IDs are deterministic for the anchored weekly slot, preventing duplicate regeneration for the same slot.
- The scheduler checks immediately on startup and every 15 minutes during normal operation.
- Saved unsent reports have durable retry metadata (`email_attempts`, last/next attempt) and are retried independently of the one-hour generation window with 15-minute linear backoff capped at six hours.
- Schema migration 9 adds the retry fields/index additively; no reset is required.

### PDF safety

- Generated HTML has a restrictive CSP and is self-contained.
- Chromium no longer receives `--allow-file-access-from-files`.
- PDF execution is time bounded and validates that the produced file begins with `%PDF-`.
- Report JSON/PDF responses are `Cache-Control: no-store`.

### Remaining limitation

SMTP has no transactional exactly-once primitive. If the SMTP server accepts a message but Central loses the connection or cannot persist `email_sent`, a retry can produce a duplicate email.

## 6. Central core JSON snapshot — critical fixes

The UI previously described this too broadly as a PostgreSQL backup. It is now explicitly a **Central core snapshot**.

### Fixed

- The old generic `SELECT * FROM sensors` included `auth_token_hash`. Downloadable snapshots now explicitly select safe sensor metadata and exclude that credential verifier.
- Snapshot creation uses one repeatable-read transaction across all included tables, preventing a concurrent telemetry sync from creating internally inconsistent table versions.
- A versioned manifest describes included/excluded data.
- Included core data covers sites, safe sensor metadata, managed rules/assignments, latest telemetry, alert history, managed incidents/events/comments, correlation rules, report history and pending SIEM outbox.
- User password/session data, sensor auth-token hashes, recon credentials, high-volume DNS/SMB/protocol/flow history and PCAP contents are excluded.
- SHA-256 is recomputed before download and an integrity mismatch fails rather than serving corrupt bytes.
- Download filename is sanitized, `Cache-Control: no-store` is used, and download requires `data_management` permission.

### Remaining limitation

The core snapshot is itself stored in the same PostgreSQL database. It is **not disaster-recovery backup**. Use `pg_dump` / external PostgreSQL backup for full database restore capability.

## 7. Sensor SQLite backup — fixed with one protocol limitation

### Fixed

- Backup name is sanitized so a management command cannot path-traverse outside the backup directory.
- Blank/`auto` names receive a unique nanosecond timestamp; repeated custom names get a suffix rather than overwrite/fail unexpectedly.
- Current in-memory sensor state is flushed before the SQLite backup is made.
- SQLite backup uses checkpoint/`VACUUM INTO` semantics.
- Multi-sensor backup queueing is per sensor and returns `202` for all queued or `207 Multi-Status` with separate queued/failed sets for partial success.
- UI wording reports **commands queued**, not “backup completed”.

### Remaining limitation

The current management command protocol acknowledges command delivery, not remote filesystem execution result. Central therefore cannot yet prove that the sensor created the `.sqlite` file. Confirm the sensor log/backups directory after a backup command. A future command-result acknowledgement would close this gap.

## 8. Rules JSON export/import — multi-sensor correctness fixed

Rules export now uses `otlens-policy-v3`:

- complete runtime rules remain tagged by sensor,
- `runtime_snapshots` record sensor context,
- `custom_rules_by_sensor` is the authoritative import source,
- compatibility `custom_rules` is exact-deduplicated,
- malformed sensor rule telemetry produces warnings rather than silent omission,
- importing a multi-sensor export requires selecting a source sensor before a target sensor, preventing divergent custom rules from multiple sensors being merged into one target,
- target import removes source `SensorID`,
- export is audited and sent with `Cache-Control: no-store`.

## 9. UDP JSON/CSV export — fixed where possible

- CSV cells beginning (after whitespace) with `=`, `+`, `-` or `@` are prefixed to prevent spreadsheet formula injection.
- Browser Blob URLs are revoked after a delay rather than immediately, avoiding download cancellation races.

UDP export is intentionally a snapshot of the **current filtered live/active conversation set**. Central does not currently keep durable UDP-conversation history, so expired conversations cannot be exported later from this module.

## 10. Diagnostics ZIP — fixed

- ZIP/JSON write errors are no longer ignored. A partial/corrupt bundle is not returned as success.
- Manifest includes schema/runtime state and SIEM queue statistics/errors.
- Sensitive authentication secrets and raw PCAP/token material are excluded.
- Export requires `data_management`, is audited, and uses `Cache-Control: no-store`.

The “redacted runtime config” still contains operationally useful non-secret values such as service addresses, usernames/recipients and paths. Treat diagnostics bundles as administrative data.

## 11. Browser download paths — fixed

Rules JSON, diagnostics, Central snapshots, UDP export, report PDF, and CSV template downloads now avoid immediate Blob URL revocation races. Server-provided safe `Content-Disposition` is honored for Central snapshot downloads.

## Deployment

This cumulative patch changes sensor persistence/backup code, Central database/export/report/SIEM code, and Web UI.

- **Sensor:** rebuild and redeploy.
- **Central:** rebuild and redeploy.
- **Web UI:** deploy the included files.
- **PostgreSQL reset:** **not required**. Migration 9 is additive and is applied at Central startup.
- **Sensor persistence DB reset:** **do not reset it**. Keep the existing file and verify the startup path/count logs.

## Validation performed in this environment

- `gofmt` parses/formats all modified Go files successfully.
- `node --check` passes for all modified JavaScript files.
- Added targeted Go tests for alert SQLite roundtrip, sensor backup naming, report schedule/labels/retry/CSP, SIEM alert event time/idempotency and notification helpers.
- A full `go test` could not be completed in the sandbox: the project requires Go 1.25, the installed local compiler is Go 1.23.2, and required modules/toolchain are not available offline.
