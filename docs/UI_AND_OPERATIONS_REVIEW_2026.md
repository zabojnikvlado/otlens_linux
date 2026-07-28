# UI and operations review

This update aligns the Central UI and several backend semantics with the features added in the preceding releases.

## Corrected UI behavior

- Topology VLAN and Device category chips size to their checkbox and text instead of stretching across the toolbar.
- Form controls use one shared dark control-room style, including Threat Intelligence source names and Data Management backup names.
- Threat Intelligence Sources, Indicators, and Observed hits use separate, consistently styled panels and independent pagers.
- PCAP analysis always uses protocol auto-detection; the redundant parser checkboxes were removed and the upload controls now share a consistent height.
- Settings contains one effective runtime-configuration view instead of repeating the same values in legacy sections.
- The connection badge has only stable `live` and `offline` states. Refreshes no longer flash `connecting`.
- SMB rows open a detail dialog containing request/response correlation, IDs, encryption/signing state, stream gap/resynchronization metadata, and file/share context when those fields are available.

## Data correctness

- Segmentation asset counts now use distinct MAC address, falling back to IP address, so duplicate topology records do not inflate VLAN totals.
- Incident correlation remains scoped to sensor and asset IP, requires at least two distinct alert types, and now sessionizes alerts with a 30-minute inactivity gap. Unrelated events at opposite ends of the 24-hour lookback are no longer merged.
- A live sensor without a recent metric sample is reported as warning with a clear reason, not as critical. Historical synchronization counters only affect health when an actual last synchronization error is present.

## Centrally managed vulnerability source

The Vulnerabilities tab now supports:

- uploading a CSV snapshot to Central;
- loading a CSV snapshot from an HTTP/HTTPS URL;
- a 20 MB size limit, 15-second timeout, redirect limit, and blocking of loopback/private/link-local destinations;
- immediate in-memory reload and audit logging.

Expected CSV columns remain:

`cve_id,vendor,product,severity,title,published_date,url`

Sensors do not download vulnerability sources.

## Recommended next detection rules

The highest-value future built-in rules require fields beyond the current generic packet-rule builder. Recommended detectors are:

1. OT write operation from an IT workstation or enterprise Purdue level.
2. PLC programming/download or controller mode change.
3. New engineering workstation communicating with multiple controllers.
4. SMB executable/script transfer into an OT zone or administrative share access.
5. Remote administration service first seen on an OT asset (RDP, WinRM, SSH, VNC).
6. DNS tunneling indicators: long labels, high entropy, high unique-subdomain ratio, or unusual query volume.
7. Beaconing/C2 periodicity with low-jitter intervals.
8. Asset identity change: vendor, model, serial, firmware, hostname, or Purdue classification conflict.
9. New inter-VLAN path bypassing the expected firewall/DMZ path.
10. TCP stream integrity anomaly spike: overlap conflicts, gap recovery, parser resynchronization, or evictions.

These should be implemented as typed detectors with protocol and asset context rather than approximated with port-only rules.
