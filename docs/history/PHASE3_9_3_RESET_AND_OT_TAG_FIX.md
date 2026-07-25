# Phase 3.9.3 – Data reset safety and OT Tag history

- Central Telemetry database reset now truncates only `sensor_telemetry`. It preserves sensors, sites, rule configuration, pending commands, SIEM data, analysis jobs and backups.
- Empty post-reset telemetry snapshots are accepted, allowing a sensor to repopulate Central immediately.
- Alerts, analysis, SIEM, rules and factory resets remain explicitly scoped operations.
- The Central UI safely replaces topology with an empty graph after reset instead of retaining stale state or crashing.
- OT Tags are deduplicated by sensor and stable tag key. The table shows one current row per register; clicking the row opens the existing value-history graph, change history and control-event history.
