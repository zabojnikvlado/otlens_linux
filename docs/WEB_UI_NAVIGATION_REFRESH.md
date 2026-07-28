# Web UI navigation and feature coverage refresh

The Central sidebar is organized by operator workflow instead of a flat list.

- Overview: Dashboard
- Network & architecture: Topology, Purdue model, Segmentation
- Assets & inventory: Assets, Device classification, OT tags, Vulnerabilities, Reconnaissance
- Detection & response: Alerts, Incidents, Detection rules, Threat intelligence
- Investigation: DNS Explorer, SMB Explorer, PCAP Analysis, Reports
- Operations: Sensors, Healthcheck, Data management
- Administration: Users & roles, Settings, Audit log

Groups are collapsible, remember their state locally, automatically open for the active page, and are filtered by role permissions. The sidebar includes page search (`Ctrl/Cmd+K`) and a mobile drawer.

The feature audit confirmed UI entry points for the implemented Purdue architecture view, segmentation, sensor health and metrics, passive/active/authenticated reconnaissance, credential vault, centrally managed threat intelligence, DNS and SMB investigation, reports, audit, data management, asset import and OT tag import.

CSV template downloads were added for asset and OT tag imports so the accepted schema is available directly in the UI.
