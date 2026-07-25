# Phase 3.5.10 – Inter-VLAN topology and rule management

## Topology

Edges whose source and destination assets belong to different VLANs are rendered as an amber dashed line. The label shows the source and destination VLAN. Honeypot lateral-movement styling keeps priority over the VLAN style.

## Detection rules

The Central Rules tab now supports:

- creating a custom packet-match rule for a selected sensor;
- enabling and disabling built-in and custom rules;
- deleting custom rules;
- displaying rule conditions, severity, hits and last hit.

Built-in detectors retained from the original project are ARP spoofing, new baseline communication, critical ICS operation, new baseline asset, value out of range, honeypot probing and honeypot lateral movement.

Custom match fields are source IP, destination IP, either IP, protocol and source/destination port. Changes are queued by Central and applied by the sensor at its next synchronization interval.
