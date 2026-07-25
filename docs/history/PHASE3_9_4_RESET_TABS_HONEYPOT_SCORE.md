# Phase 3.9.4 — coordinated resets, tab order, honeypot score

- Central telemetry/database, alerts, analysis and factory resets now queue the corresponding reset on every registered sensor before clearing PostgreSQL. This prevents the next sensor sync from restoring deleted data.
- Full Central reset preserves the sensor registry and queued reset commands until sensors receive them.
- Sensor database reset clears live and PCAP-derived observations while preserving rule configuration; factory reset also removes managed custom rules while retaining built-ins.
- Honeypot classification is calculated with each sensor's own threshold and emitted explicitly as `IsHoneypot`, fixing color after resets and in multi-sensor deployments.
- Assets show Score and classification (standard/elevated/critical/honeypot).
- Tabs are ordered Dashboard, Topology, Assets, OT Tags, Rules, Alerts, Sensors, Analysis, Data Management.
