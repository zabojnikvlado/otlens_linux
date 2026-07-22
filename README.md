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
