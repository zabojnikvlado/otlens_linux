# Stability and diagnostics release

This release adds a first stabilization layer:

- Pipeline diagnostics on the Healthcheck tab for capture, event bus, TCP classification, reassembly, packet type compatibility and Central sync.
- Durable `schema_migrations` tracking with the current schema version exposed in Settings and Healthcheck.
- Shared UI primitives for inputs, panels, tables, toolbars and compact chips.
- A `make verify` release gate covering formatting, frontend syntax, vet, tests and both builds.

The diagnostics distinguish a disabled reassembly engine from a running engine receiving no TCP segments. This makes `Active streams = 0` actionable instead of ambiguous.
