# Discovery pipeline audit and Linux enrichment

This change makes active discovery diagnosable from the Central UI and improves enrichment of ordinary Linux servers.

## Pipeline audit

Every target result now records timestamped stages for command receipt, policy validation, reverse DNS, port scan, service enumeration, OT probes, authenticated inventory, asset enrichment, and Central persistence. The Reconnaissance job detail modal displays these stages together with collected services and evidence.

## Linux discovery

SSH banners are retained, OpenSSH versions are parsed, and Ubuntu or Debian identity is inferred when the distribution marker is present in the SSH banner. HTTP discovery now falls back from HEAD to a bounded GET request when a server does not expose a useful Server header to HEAD.

## Persistence

Central appends a successful `persist_results` stage only after the asset profile upsert succeeds. The stored job result therefore proves that the result was attached to `asset_recon_profile` for the same sensor and IP.

## Verification

Run:

```bash
go build -o ./bin/otlens-linux-amd64 ./cmd/otlens
go build -o ./bin/otlens-central ./cmd/otlens-central
```

Open Reconnaissance, select Jobs, and click a job row. The Discovery debug section shows exactly where a target did or did not yield data.
