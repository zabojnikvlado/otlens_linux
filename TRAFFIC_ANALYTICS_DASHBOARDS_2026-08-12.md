# OTLens — Traffic Analytics dashboards

Date: 2026-08-12

## Scope

This cumulative patch adds a dedicated **Analytics** area to Central with four traffic-analysis views built on the existing minute-level `flow_observations` history. It does not add a second raw-flow store and does not change the Sensor wire format.

## Dashboards

### Communication analysis

Analyze one stable asset identity against another asset, or against any peer. Filters include Sensor, Device A, Device B, time range/custom timestamps, protocol/service, port and direction. Results include:

- total transferred bytes;
- A→B and B→A bytes;
- observed packets and flow/connection count;
- peak observed throughput per selected bucket;
- time-series graph;
- top protocols/services;
- top peers;
- volume-anomaly intervals and learned baseline.

The asset selector is MAC/stable-identity based. A DHCP move therefore keeps the selected device identity instead of silently turning the query into a query for whichever device currently owns an old IP.

### Asset traffic

Analyze one asset across all peers. The view exposes sent/received volume, packets, flow count, peak throughput, protocol mix, top peers and volume anomalies. The same stable identity is followed across known IP aliases.

### Network / zone traffic

Compare two logical scopes. Each side can be:

- Any;
- VLAN;
- Purdue level;
- Central zone;
- device category, including operator-created custom categories.

The view supports protocol, port, sensor, time and direction filters and returns the same time series, summaries, top protocols/counterparts and anomaly evidence.

### Protocol analytics

Analyze one observed application/service class or L4 protocol across the network, optionally filtered by sensor, device category and port. Common services are classified from responder/service ports, including SMB, DNS, NTP, SNMP, Modbus, S7COMM, HTTP, HTTPS, SSH, RDP, LDAP/LDAPS, SMTP and NetBIOS. Unknown services fall back to the L4 protocol.

The view shows directional volume over time, top assets/peers, top service ports and volume anomalies.

## Time-series resolution

Central returns bounded aggregated series instead of raw flow rows:

- up to 6 hours: 1-minute buckets;
- up to 24 hours: 5-minute buckets;
- up to 7 days: 15-minute buckets;
- up to 31 days: 1-hour buckets;
- longer custom ranges: 6-hour buckets;
- maximum query range: 180 days.

`flow_observations` already stores minute-level byte/packet deltas, so no duplicate telemetry path is needed.

## Volume anomaly baseline

Each query learns a volume threshold from the matching traffic in the previous 30 days using median, MAD and P95. When fewer than 20 previous samples exist, the selected window is used as the fallback baseline. A 1 MiB minimum floor prevents tiny/noisy flows from being marked as high-volume anomalies.

The UI marks anomalous buckets on the graph and lists timestamp, transferred bytes, baseline, threshold and deviation. This patch intentionally detects **traffic-volume anomalies**; it does not claim that every high-volume interval is malicious.

## Stable identity and DHCP/IP reuse

Migration v17 adds `src_identity` and `dst_identity` to `flow_observations`.

New flow-minute deltas are stamped at ingestion with the identity that owned each endpoint IP at that event time using `asset_ip_binding_history`. If more than one identity overlaps the same IP/time, Central keeps the fail-safe `ip:<IP>` attribution instead of choosing an arbitrary MAC.

Historical pre-v17 flow rows are not rewritten in a large startup migration. Analytics resolves their identity lazily from the event-time binding ledger. Ambiguous historical ownership similarly falls back to the IP identity.

The topology snapshot is reconciled before flow deltas in the same telemetry transaction so a newly observed DHCP binding is available when current flow rows are attributed.

## Database migration

Migration **v17 — stable identity traffic analytics** is additive and creates:

- `flow_observations.src_identity`;
- `flow_observations.dst_identity`;
- time/sensor/protocol/port indexes for analytics reads;
- stable-identity time indexes;
- an event-time IP-binding lookup index.

No database reset is required.

## API

New read endpoints, protected by the existing Dashboard view permission:

- `GET /v1/analytics/options`
- `GET /v1/analytics/communication`
- `GET /v1/analytics/asset-traffic`
- `GET /v1/analytics/network-traffic`
- `GET /v1/analytics/protocol-traffic`

## UI integration

The left navigation now has an **Analytics** group with:

- Communication analysis;
- Asset traffic;
- Network / zone traffic;
- Protocol analytics.

The views use a native canvas time-series graph and the existing Central visual language; no third-party chart dependency is added.

## Deployment

Rebuild/deploy **Central + Web UI**. The Sensor protocol is unchanged, so an existing compatible Sensor does not need to be rebuilt solely for this feature.

Keep the existing PostgreSQL database. Migration v17 runs automatically on Central startup.

## Validation performed in this environment

- all Go source files parse with the standard Go parser;
- all production `web/central/app-*.js` files pass `node --check`;
- focused pure-helper regression tests were added for time-bucket selection and volume anomaly detection;
- a complete `go test ./internal/central` could not finish here because the environment timed out while downloading external Go modules (`gin`, `pgx`, `x/crypto`, `zap`). This was an environment/dependency-download timeout, not a reported source compile failure.
