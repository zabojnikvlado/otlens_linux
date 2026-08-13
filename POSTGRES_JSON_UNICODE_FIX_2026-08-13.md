# PostgreSQL telemetry JSON Unicode fix — 2026-08-13

## Symptom

Central rejected an otherwise valid sensor telemetry batch with:

```
store telemetry snapshot: ERROR: unsupported Unicode escape sequence (SQLSTATE 22P05)
POST /v1/sensors/telemetry -> 500
```

## Root cause

Sensor telemetry contains packet-derived strings (for example SMB file/share names, generic protocol host/resource fields, DNS-derived strings, topology hostnames and alert evidence). A captured string can contain an actual NUL code point (`U+0000`). Go's `encoding/json` correctly serializes that code point as `\u0000`, but PostgreSQL `jsonb` cannot represent U+0000 and rejects the complete row.

The failure happened at the first `sensor_telemetry` JSONB upsert, before the derived DNS/SMB/protocol/flow persistence paths. As a result one bad string could roll back the entire telemetry transaction.

## Fix

A PostgreSQL-bound telemetry sanitizer now runs inside `Repository.PutTelemetry` after the HTTP handler has verified the original sensor checksum.

It covers every JSON-bearing telemetry field:

- topology
- tags / tag changes / tag events
- alerts
- baseline
- rules
- DNS observations
- SMB observations
- generic protocol observations
- UDP conversations / telemetry / protocol exchanges

The normal path does not decode/re-encode JSON. Sanitization is activated only when the raw JSON may contain a NUL escape/raw NUL.

When activated, JSON is decoded with `json.Decoder.UseNumber`, recursively inspected, and actual U+0000 characters in string values or object keys are replaced with U+FFFD (`�`). This preserves large integer precision and keeps the rest of the telemetry evidence intact.

A literal six-character string such as `\\u0000` is not modified.

## Integrity semantics

The sensor checksum is still verified against the exact original wire payload before sanitization. Only the copy handed to PostgreSQL is sanitized, so the change does not weaken telemetry integrity or require a sensor protocol change.

## Deployment

Rebuild/redeploy Central only. Sensor changes and a database migration/reset are not required.

After deployment, the expected result is:

```
POST /v1/sensors/telemetry -> 200
```

instead of SQLSTATE 22P05.

## Validation

- Modified Go files are `gofmt` clean.
- All Go source files in the cumulative tree parse successfully with `gofmt`.
- Added regression coverage for real NUL replacement, literal `\\u0000` preservation, large integer preservation and coverage of multiple telemetry fields.
- Full package `go test` could not be completed in the sandbox because external module downloads timed out.
