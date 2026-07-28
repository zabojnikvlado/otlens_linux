# Web UI security explorer additions

The Central web UI now surfaces the detection and telemetry features added in the recent backend work:

- Threat Intelligence explorer derived from malicious IP/domain alerts.
- Passive DNS explorer with sensor/search filters and alert correlation highlighting.
- SMB explorer with admin-share, executable, script, named-pipe and encryption flags.
- Incident detail timeline combining related alerts, DNS and SMB observations.
- Dashboard KPIs for threat-intelligence hits, risky SMB activity, C2/lateral movement and OT anomalies.
- Existing incident and asset workflows remain in place.

## Topology performance constraint

No topology physics, force/gravity, stabilization, zoom/pan, animation or movement settings were changed. The existing topology render/update caches and dense-network behavior remain intact.
