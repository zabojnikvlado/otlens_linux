# Live Operations

Central exposes an authenticated Server-Sent Events stream at `GET /v1/live/events`.
The browser keeps one connection open and receives compact event envelopes for:

- new alerts and telemetry snapshots;
- incident correlation, workflow changes and comments;
- asset risk recalculation;
- sensor registration and heartbeat health;
- completed or failed discovery jobs.

The stream uses the existing authenticated Central session cookie. It does not send
packet payloads, credentials, configuration secrets, management tokens or session
material. A bounded replay buffer and `Last-Event-ID` allow short reconnects to catch
up. Slow browsers cannot block sensor telemetry ingestion.

The UI debounces bursts into one refresh, shows actionable toast notifications and
keeps a 60-second poll as a consistency fallback for proxies that buffer or disable
streaming. The connection badge reports `live push` while the SSE channel is open and
`live reconnecting` while the browser reconnects automatically.
