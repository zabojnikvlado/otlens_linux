# OTLens v24 – detection/network data integrity audit

Audit scope: sensor → telemetry sync → Central PostgreSQL → correlation/API → Web UI, with emphasis on detections/incidents, DNS, SMB, UDP and TCP/flow/application-protocol data.

## Fixed correctness issues

### Telemetry ordering and idempotency
- Central now serializes telemetry ingestion per sensor and rejects an older sequence or a same-sequence/different-checksum payload before **any** derived write is executed.
- An exact retry of an already committed sequence/checksum is acknowledged without replaying flow deltas, topology, DNS/SMB/protocol history, alert history or other side effects.
- Sensor understands `telemetry_sequence_conflict`, adopts Central's current sequence and retries on the next cycle without marking rejected data synchronized.
- Malformed topology JSON now fails the complete telemetry transaction instead of committing the snapshot while silently skipping topology/flow persistence.

### Sensor ACK races
- Alerts are marked synchronized only when the live alert still exactly matches the version acknowledged by Central. A Count/LastSeen/status/evidence change while HTTP is in flight remains dirty for the next sync.
- Flows use the same version-aware ACK behavior for counters, LastSeen, endpoint roles and VLAN.
- Flow ACK uses a runtime-only manifest of every dirty flow selected for the sync, not only edges that survive Topology filtering. External/public flows intentionally omitted from the topology map therefore no longer remain dirty indefinitely and consume future batches.

### Alert/detection history
- A stale alert version can no longer overwrite newer severity/message/IP/evidence/status metadata in `alert_history`.
- Zero `LastSeen` is rejected instead of being converted to `NOW()`, preventing malformed/restored detections from becoming fake fresh alerts.
- Behavior Findings query behavior alerts directly rather than taking a slice of the newest alerts of all types; unrelated alert volume can no longer evict behavior findings from the view.
- Behavior finding detail is keyed by `(sensor_id, alert_key)` so identical alert keys from different sensors cannot return the wrong sensor's finding.

### Incident correlation and timeline
- `resolved` incidents are no longer treated as open by the unique active-incident index. A new episode after resolution creates a new incident instead of being attached to the resolved one.
- Active incident score, confidence and severity retain the peak reached during that incident and are not downgraded when stronger evidence ages out of the correlation window.
- Correlation candidates and event insertion are restricted to the rule's required/sequence alert types when such filters exist; unrelated detections on the same IP are no longer included in rule-specific incidents.
- Repeated incident evidence updates timestamp/message/metadata instead of `ON CONFLICT DO NOTHING` leaving stale timeline data.
- Timeline fallback reconstruction from `alert_history` applies the same rule-type filter.
- Incident UI timeline is independent from optional DNS/SMB requests, so a failing enrichment endpoint cannot erase an otherwise valid timeline response.

### TCP / flow history and topology
- Flow deltas are ordered by the flow event's `LastSeen`, not upload time.
- `flow_counters` persists `last_seen`; an older restored flow cannot lower a newer counter and cause a false counter-reset delta.
- Historical/restored flows are bucketed at their actual event time rather than appearing as current traffic after a sensor restart.
- Older topology records cannot overwrite newer node/edge mutable metadata; first/last seen remain monotonic.

### DNS
- Zero-timestamp observations are skipped instead of manufacturing a new event on every resend.
- Durable DNS event identity now includes resolver, transaction ID and query type in addition to timestamp/client/name/direction, preventing distinct same-time transactions from collapsing under the previous coarse unique key.
- Central now retains transaction ID, UDP conversation ID, direction, answer count and payload size that were already produced by the sensor but previously discarded.
- Explorer keeps its own stable dataset; the generic 60-second dashboard refresh does not replace it with only the latest 1000 rows. Server-side search queries retained PostgreSQL data (up to the explicit result cap).

### SMB
- Zero-timestamp observations are skipped.
- Event identity now includes SMB session ID, preventing the same MessageID reused in different sessions from collapsing.
- Central now retains dialect, persistent/volatile File IDs, matched request command and TCP stream gap/resync metadata that were previously discarded.
- Explorer uses a stable dedicated dataset and server-side retained-data search.

### Application protocol / TCP metadata
- Central now retains `conversation_id`, `flow_id`, direction and RTT supplied by the sensor.
- Protocol observation dedup identity includes conversation/flow/direction so distinct same-time exchanges are not collapsed by the old coarse unique constraint.
- `protocol_observations` is now covered by telemetry retention; previously it could grow without the configured telemetry retention policy.

### UDP
- UDP conversation IDs now include session start time. Reusing the same endpoint tuple after idle expiry creates a new conversation identity instead of inheriting old protocol exchanges.
- Central filters protocol exchanges against the current conversation's `StartedAt` for compatibility with older deterministic IDs.
- Concurrent live/filter requests use request sequence guards so a slower old HTTP response cannot overwrite a newer UDP table/detail result.
- Central no longer labels the sensor's historical DNS-only average RTT as an all-UDP metric; aggregate UDP RTT is recomputed from actual correlated UDP protocol exchanges.
- The UI explicitly labels UDP Explorer as active-conversation data rather than historical storage.

## Intentional/remaining limits

1. **UDP conversation history is not durable.** The UDP table is a live active-conversation view. Idle/expired sessions disappear on the sensor. A historical UDP Explorer requires a dedicated durable observation/conversation table.
2. **DNS/SMB/protocol sensor buffers are bounded and memory-resident.** DNS retains 5,000 observations, SMB 5,000 and protocol observations/exchanges 10,000. Normal periodic sync persists these into Central, but a prolonged Central outage can overflow the sensor buffer before data is uploaded. Zero-loss offline operation requires a sensor-side persistent event journal.
3. **Alert history is finding-oriented, not packet/event-source oriented.** Repeated occurrences of the same detection key update Count/LastSeen. Incident timeline similarly keeps the latest correlated event per source key. It is not a packet-forensic event log of every recurrence.
4. **Presentation/search caps are not database deletion.** DNS/SMB server searches cap one response at 5,000 matches and the Behavior Findings view caps at 10,000 retained findings; narrower filters/paging are needed beyond those UI/query caps.
5. **Retention can intentionally remove data.** `telemetry_days`, `alerts_days`, `audit_days` and the database-size backstop may delete retained rows according to configuration. A row disappearing because of retention is different from an overwrite/race bug.

## Deployment impact

This patch changes Sensor, Central and Web UI behavior and introduces additive PostgreSQL schema migrations/index changes. Rebuild/redeploy **Sensor + Central** and deploy the included Web UI. A full database reset is not required; Central startup migrations preserve existing rows. Newly added metadata columns on historical rows naturally contain defaults because the older Central never stored those fields.

## Validation performed in this environment

- `gofmt` clean on modified Go sources.
- Go parser/AST syntax and import-usage scan passed across the repository.
- `node --check` passed for modified Web UI JavaScript.
- Targeted unit tests were added for alert ACK races, flow ACK races and UDP tuple/session ID reuse.
- Full `go test` cannot run in this sandbox because the project requires Go 1.25 and the environment has Go 1.23.2 with dependency/network access unavailable.
