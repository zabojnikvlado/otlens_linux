# OTLens testing strategy

The default suite is hermetic: it does not require packet-capture privileges,
PostgreSQL, a running sensor, or a Central server.

## Local and CI commands

```sh
make test          # all unit and HTTP handler tests
make test-race     # the same suite with Go's race detector
make vet           # static analysis
make fmt-check     # formatting verification
make frontend-check
make verify        # all checks plus both binaries
```

Use `go test -count=1 ./...` when validating changes without cached results.

## Test layout

- Tests live beside the production package they exercise. Do not create
  placeholder packages or tests that contain no assertions.
- `internal/asset` covers asset identity, ARP trust, lifecycle and retention.
- `internal/protocolobs`, `internal/ics`, `internal/smb` and `internal/dcerpc`
  cover protocol parsing with small synthetic payloads. Payloads must not
  contain real credentials or captured customer traffic.
- `internal/tcpreassembly` covers ordering, retransmission, gaps and closure.
- `internal/central` covers pure correlation/risk logic, HTTP security and
  handlers that can be exercised without an external database.

## Integration and end-to-end tests

Repository tests that require PostgreSQL must create an isolated database,
apply the runtime migrations through `OpenPostgres`, and clean up their own
records. Gate them with the `integration` build tag and a documented
`OTLENS_TEST_POSTGRES_DSN` environment variable:

```sh
go test -tags=integration ./internal/central
```

End-to-end tests should start the compiled Central and sensor binaries using
temporary configuration and storage, wait on `/health`, exercise telemetry,
and always terminate child processes. Keep them behind an `e2e` build tag so
the default suite stays deterministic.

## Quality rules

- Every test must make a behaviorally meaningful assertion.
- Prefer table-driven boundary and malformed-input cases for parsers.
- Run the race suite for changes to event buses, live hubs, caches or engines.
- A regression fix includes a test that fails before the fix.
- Coverage is a diagnostic, not a target: `go test -coverprofile=coverage.out
  ./...` and `go tool cover -func=coverage.out`.
