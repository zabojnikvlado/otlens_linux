# Central build fix — 2026-08-12

This cumulative source fixes the compile regressions reported when building `cmd/otlens-central` on Go 1.25.

## Fixed

- `internal/central/itot_attack_path.go`: declare the `ExecContext` error in the correct scope instead of assigning to an out-of-scope `err`.
- `internal/central/server.go`: remove the unused `started` variable from `auditMiddleware`.
- `internal/central/udp_conversations.go`: decode `udp_conversations_active` from `json.RawMessage` before converting it to `uint64`; `json.RawMessage` cannot be cast directly to a number.
- Weighted UDP average-duration aggregation now uses that decoded active-conversation count.

## Validation

- All Go source files in the cumulative tree pass `go/parser` syntax parsing.
- The three modified files pass `gofmt`.
- A complete local build cannot be executed in the provided environment because its installed Go version is 1.23.2 while the project requires Go 1.25.0 and external toolchain/module downloads are blocked.
