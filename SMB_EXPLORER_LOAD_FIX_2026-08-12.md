# OTLens — SMB Explorer load fix

Date: 2026-08-12

## Symptom

The Web UI connection badge could show `partial: /smb-observations?limit=1000`, and the SMB Explorer could remain in a loading/error state even though TCP/445 communication and SMB-related alerts existed.

## Root causes addressed

1. The Dashboard and Alerts refresh domains fetched full SMB evidence even when the SMB Explorer was not open. A failure or slow SMB query therefore marked the whole UI connection state as partial.
2. PostgreSQL `NUMERIC(20,0)` SMB identifiers (message/session/file IDs) were scanned directly into unsigned Go fields. That behavior depends on the database/sql driver representation and can fail on valid retained data.
3. Transport fallback aggregated the full retained TCP/445 `flow_observations` ledger with SQL `GROUP BY` before `LIMIT`. On large installations this can be expensive despite the partial SMB index.
4. The Explorer initially requested/rendered up to 5,000 evidence rows, creating unnecessary API and browser work.

## Changes

- Added a lightweight `/v1/smb-stats` Dashboard endpoint for the SMB risk KPI. Dashboard refresh no longer downloads full SMB evidence.
- Alerts refresh no longer downloads full SMB evidence. SMB observations are fetched on demand by the SMB Explorer or incident detail.
- SMB NUMERIC identifiers are explicitly selected as text and parsed as uint64. Signed schema values are scanned as int64 and range checked before conversion.
- One malformed retained SMB row is skipped instead of making the entire Explorer unavailable.
- TCP/445 transport evidence now reads a bounded newest-first candidate window through the existing SMB partial index and aggregates those buckets per flow in Go. It no longer runs a full-history SQL GROUP BY.
- Transport fallback is fail-open: if historical transport evidence fails, decoded SMB evidence is still returned.
- Initial SMB Explorer result cap is 1,000 rows. Search remains server-side and can retrieve older matching evidence.
- SMB UI errors now include the Central request ID when available.
- Cache versions bumped for app-core, app-detection and app-operations.

## Deployment

Rebuild/deploy Central + Web UI. No sensor rebuild and no database reset/migration are required for this fix.

## Validation

- All 214 Go source files parse successfully with the Go parser.
- All production `web/central/app-*.js` files pass `node --check`.
- Full central package tests could not be executed in the isolated environment because required external Go modules were not cached and network module lookup is disabled.
