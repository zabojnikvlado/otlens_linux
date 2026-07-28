# Sensor build regression fix

Fixed in `cmd/otlens/main.go`:

- removed the unused `internal/core` import;
- removed the duplicate `Versions` worker callback;
- removed the duplicate `CaptureInfo` worker callback;
- kept the richer callbacks that report the effective capture backend, libpcap, Go and application versions.

Validation performed:

- `gofmt` completed;
- Go parser duplicate-key scan completed for both sensor and Central entry points;
- the reported compiler errors are no longer present in the source.

A full module build could not finish in the packaging environment because dependency downloads did not complete before the execution timeout.
