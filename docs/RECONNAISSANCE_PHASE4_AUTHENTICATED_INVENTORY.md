# Reconnaissance Phase 4: Authenticated Inventory

Phase 4 adds an explicitly approved `authenticated-inventory` profile. The first supported method is SSH read-only inventory for Linux/Unix and network appliances.

## Security model

- Credentials are created and managed centrally.
- Secrets are AES-256-GCM encrypted at rest using `OTLENS_CREDENTIAL_MASTER_KEY`.
- The API only returns credential metadata, never passwords or private keys.
- A decrypted secret is attached only to the selected sensor command and is kept in memory for one job.
- Jobs require manual approval, allowed-network policy, bounded rate and timeout.
- The sensor executes only a fixed command allowlist; arbitrary commands are not accepted from the UI or API.

Set a stable master key before starting Central:

```sh
export OTLENS_CREDENTIAL_MASTER_KEY='replace-with-a-long-random-secret'
```

Losing or changing this key makes existing stored credentials unreadable.

## SSH inventory fields

The sensor retrieves hostname, kernel/OS details, hardware vendor, model and serial number using fixed read-only commands. Evidence is marked `authenticated_ssh` with high confidence.

## Planned adapters

The credential and job model is prepared for SNMPv3, WinRM/WMI and vendor APIs. Those adapters are intentionally not enabled until their protocol-specific authentication, certificate validation and command allowlists are implemented and tested.
