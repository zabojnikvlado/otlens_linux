# Central-managed Threat Intelligence

Threat-intelligence sources are managed in Central rather than repeated in every sensor configuration.

## Supported sources

- Manual IP/domain indicators
- CSV upload
- JSON upload
- Scheduled HTTP/HTTPS URL feeds

CSV accepts a header with `value,type,threat_type,confidence`; a single-column IOC list is also accepted. JSON accepts an array of objects with `value`, `type`, `threat_type`, `confidence`, and optional RFC3339 `valid_until`.

Central normalizes domains and IP addresses, rejects malformed entries, deduplicates indicators per source, records accepted/rejected counts, and increments a global snapshot version after every change.

## Sensor delivery

Sensors keep matching local. During the existing `/sync` request the sensor supplies its current IOC version. Central returns a full snapshot only when the version changed. This preserves offline detection and avoids a Central lookup for every packet or DNS observation.

Sensor configuration now only needs:

```yaml
detect:
  threatintel:
    enabled: true
    maxdnsobservations: 5000
```

## URL feed security

Only HTTP/HTTPS is accepted. Loopback and link-local targets are blocked, redirects are limited, responses are size-limited, and requests use a timeout. Feed credentials are intentionally not part of the first implementation and are never distributed to sensors.

## Audit

All source creation, refresh, deletion, manual IOC changes, and file imports pass through Central's mutating API audit middleware.
