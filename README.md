# otlens
Lightweight OT Network Intelligence Platform

See [DOCUMENTATION.md](DOCUMENTATION.md) for architecture, data model,
configuration reference, and the REST API surface. See
[DETECTION_RULES.md](DETECTION_RULES.md) for how the alert/detection
rules work and how to add new ones.

Quick start:

```
go get go.etcd.io/bbolt
go mod tidy
go run ./cmd/otlens
```

Dashboard: http://localhost:8080/ui/ (once running).

## Build targets

OTLens is built as two separate Linux binaries from the same Go module:

- `cmd/otlens` — Linux OT sensor
- `cmd/otlens-central` — central management/ingestion server

Build both:

```bash
make build
```

Build separately:

```bash
make build-sensor
make build-central
```

The binaries are written to:

```text
bin/otlens
bin/otlens-central
```

Run tests:

```bash
make test
make test-race
```

The Go module path is:

```text
github.com/zabojnikvlado/otlens_linux
```
