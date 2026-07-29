# Critical security fixes

## Per-sensor authentication

`auth.sensor_token` is now an enrollment credential, not the long-lived credential used by every sensor request.

On first registration Central generates a unique 256-bit token, stores only its SHA-256 digest, and returns the plaintext once with `Cache-Control: no-store`. The sensor persists it in `central.credential_file` with mode `0600`. Later registrations and token rotations for an existing sensor require that sensor's current token; the shared enrollment credential cannot take over an already enrolled sensor.

All heartbeat, telemetry, sync, analysis and reconnaissance endpoints bind the authenticated token to `X-OTLens-Sensor-ID` or the sensor ID in the route. Body/header identity mismatches are rejected.

Legacy sensor rows have an empty token digest after migration. Their first successful registration performs the one-time enrollment. Protect the enrollment credential and complete this migration in a controlled maintenance window.

## Live Operations RBAC

SSE delivery and replay history are filtered per authenticated user's view grants. Event families are explicitly mapped to their module permission, and unknown event types are denied by default.

Presence reads and writes require a supported entity type, an entity ID, and the corresponding module permission. Unscoped presence enumeration is rejected.
