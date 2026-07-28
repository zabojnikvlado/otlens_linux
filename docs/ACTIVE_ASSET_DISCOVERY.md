# Active asset discovery (Phase 2)

OTLens Central can queue a bounded `safe-discovery` job for execution by a sensor in the target network zone.

The profile performs only:

- reverse DNS lookup;
- TCP connect checks against an explicit port list;
- SSH banner read;
- HTTP HEAD metadata;
- TLS certificate metadata;
- conservative service inference for SMB, RDP, Modbus/TCP, S7comm, EtherNet/IP and OPC UA ports.

It does not authenticate, write to an OT protocol, enumerate SMB shares, execute commands, or run aggressive TCP/IP OS fingerprint probes.

## Safety policy

Every job includes allowed CIDRs, denied targets, a maximum probe rate, a single-target concurrency limit and a timeout. Central rejects rates over 20 probes per second. The sensor validates each target again before opening any connection.

Results are stored in `reconnaissance_jobs`, `reconnaissance_results`, and the latest per-asset profile in `asset_recon_profile`. Active evidence is merged into the Assets API without deleting passive evidence.

## API

- `GET /v1/reconnaissance/jobs`
- `POST /v1/reconnaissance/jobs`
- sensor result callback: `POST /v1/sensors/:id/reconnaissance/jobs/:job/result`

All Central-side creation actions are covered by the existing authenticated audit middleware.
