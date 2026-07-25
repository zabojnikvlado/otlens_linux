# Phase 3.8.2 — Project cleanup and sensor hardening

## Goal

Align the repository with the final architecture: Linux sensors are headless and Windows Central is the sole management plane.

## Removed from the sensor

- embedded dashboard and static files (`web/index.html`, `web/app.js`, `web/style.css`)
- local Gin management API (`internal/api`)
- sensor-side Basic Auth, CORS and API TLS configuration
- sensor-side direct alert export (`internal/export`)
- sensor-side API audit file subsystem (`internal/audit`)
- local vulnerability CSV browser (`internal/vuln` and `ics_advisories.csv.example`)
- event-bus types used only by those removed subsystems

Central SIEM export, Central management audit and the Central UI remain intact.

## Runtime impact

The sensor no longer binds TCP port 8080. Existing `api`, `export`, `audit` and `vulnerability` keys in old sensor YAML files are ignored by Viper and should be removed. Capture/IPFIX, SQLite persistence, detection, telemetry, analysis jobs, backup/reset commands and Central synchronization are unchanged.

## Verification

- all Go sources formatted with `gofmt`
- JavaScript syntax checked with Node
- stale source references searched twice after cleanup
- ZIP integrity verified
- a full `go test ./...` was attempted but dependency downloads exceeded the execution timeout in the build environment
