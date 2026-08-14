# Traffic baseline comparison compile fix — 2026-08-13

Fixed a Central compile regression in `internal/central/traffic_baseline_compare.go`.

`buildTrafficBaselineComparison` returns `(TrafficBaselineComparison, []TrafficAnomaly)`, but the final return path returned only the comparison value. The function now returns both values:

```go
return TrafficBaselineComparison{...}, anomalies
```

Validation:
- `gofmt` applied to the changed Go file.
- All Go source files parse successfully with the Go parser.
- A full `go test ./internal/central` was attempted, but the environment timed out while downloading external modules (`gin`, `pgx`, `x/crypto`, `zap`).
