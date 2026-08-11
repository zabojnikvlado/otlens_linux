# Built-in detection rule catalogue (v14)

OTLens built-in rules are **product-managed detector definitions** executed on the sensor (except the reconnaissance-derived identity/firmware rules, which are materialized in Central from approved reconnaissance results). Built-ins cannot be deleted or replaced by a managed rule set.

Operators own the **policy layer** only:

- enabled / disabled
- severity policy (`auto` keeps detector-computed severity; an explicit severity replaces it)
- simulation mode
- suppression (`aggregate`, `interval`, `once`, `every`)
- UTC schedule
- detector-specific numeric parameters exposed in `Parameters`

Product metadata remains upgrade-controlled: detector identity, description, supported protocols, prerequisites and ATT&CK mapping. This prevents a Central reset or an older rule set from replacing the implementation of a built-in detector.

## Identity and L2

| ID | Default | What it detects |
|---|---|---|
| `arp_spoof` | high | Conflicting IP↔MAC identity claims. A repeated claimant is **not** auto-trusted. |
| `builtin.duplicate_ip` | high | Persistent simultaneous claims for one IP by different MACs. |
| `builtin.gateway_mac_changed` | critical | Trusted gateway/router MAC identity changed. |
| `builtin.gratuitous_arp_storm` | medium | Excessive gratuitous ARP activity; VRRP/HSRP virtual-MAC movement is treated conservatively. |
| `builtin.asset_identity_drift` | high | Hostname/vendor/model/serial/OS or other stable identity evidence changes. |
| `builtin.firmware_change` | critical | Reconnaissance profile reports firmware drift on an established asset. |

## OT / ICS command semantics

| ID | Default | What it detects |
|---|---|---|
| `builtin.unauthorized_ot_command` | critical | Command/operate from a source without learned or approved command authority for the target. |
| `builtin.unauthorized_ot_write` | critical | Write/set-point/operate from an unauthorized source, including vector/bool writes without a scalar process value. |
| `builtin.controller_program_change` | critical | Program download, block transfer or online program edit. |
| `builtin.controller_mode_change` | critical | Controller stop/restart/operating-mode change. |
| `builtin.controller_configuration_change` | high | Decoded device/controller configuration change. |
| `builtin.unauthorized_time_change` | high | OT time/clock change from a source without separate time-source authority. |
| `builtin.brute_force_io` | high | Burst of repeated commands/writes against one controller. |
| `builtin.process_sequence_violation` | high | Stateful protocol sequence violation; currently includes DNP3 Operate without a recent Select. |
| `builtin.malformed_ot_burst` | high | Burst of protocol exceptions or protocol-looking frames that fail decoding. Arbitrary TCP fragments are not counted as malformed ICS. |
| `builtin.ot_reporting_loss` | high | Mature OT reporting cadence disappears while the sensor is still observing traffic. |
| `builtin.unexpected_ot_protocol` | high | New OT protocol/service relationship on a known OT asset after learning. |
| `ics_critical_operation` | critical | Legacy compatibility safety-net for future intrinsically high-impact parser semantics that do not yet have a dedicated rule. Routine writes/session lifecycle/time sync are not blanket critical. |

Supported semantic parsers include Modbus/TCP, S7comm, DNP3, IEC 60870-5-104, BACnet/IP, EtherNet/IP, OPC UA and PROFINET DCP. Parsers normalize protocol-specific functions into read/write/command/program/mode/config/time semantics before policy evaluation.

### Relationship authority is split deliberately

OTLens persists three separate relationship sets:

1. **access** — a source may read/query an OT target;
2. **command authority** — a source may write/operate/control it;
3. **time authority** — a source may change its time.

A historian that only reads a PLC during learning therefore does not become an authorized writer. Hard-security/policy traffic quarantines a source→target relationship so another event subscriber cannot silently learn it. Explicit analyst approval is the trust transition for relationship findings.

## Engineering, remote administration and lateral movement

| ID | Default | What it detects |
|---|---|---|
| `builtin.new_engineering_workstation` | high | A new/non-engineering source begins control operations against multiple controllers. |
| `builtin.unexpected_engineering_access` | high | Engineering-class source accesses a controller outside its learned target relationships. |
| `builtin.first_seen_remote_management` | medium | New SSH/Telnet/RPC/SMB/RDP/VNC/WinRM relationship after learning. |
| `builtin.remote_management_into_ot` | high | Remote administration enters an OT asset from an unapproved relationship. |
| `builtin.smb_into_ot` | medium | SMB crosses into an OT asset from a non-OT/unapproved source. |
| `builtin.smb_tool_transfer` | critical | Executable/script transfer or suspicious remote-execution named pipe (for example service-control/PsExec-style activity) toward OT. |
| `builtin.direct_ot_protocol_access` | high | Direct OT protocol access without a learned/approved source→target relationship. |
| `builtin.large_controller_transfer` | high | Large transfer toward an OT controller/service. |
| `lateral_movement` | high/dynamic | Administrative fan-out, sequential pivots and large administrative transfers. |

The six relationship-heavy rules (`first_seen_remote_management`, `remote_management_into_ot`, `direct_ot_protocol_access`, `smb_into_ot`, `unexpected_engineering_access`, `large_controller_transfer`) start in **simulation mode** after an upgrade because sites differ substantially in engineering/management topology. Tune asset roles/zones and review simulation hits before enforcing them.

## Network policy, discovery and Internet/C2

| ID | Default | What it detects |
|---|---|---|
| `external_communication` | medium/dynamic | Internal ↔ public-routable unicast communication. Multicast, broadcast, link-local, loopback, CGNAT, benchmarking/documentation and reserved ranges are excluded. Inbound is distinguished from outbound. |
| `segmentation_violation` | high | Explicit source-zone → destination-zone/protocol policy violation; Purdue max-level-jump is fallback policy. |
| `reconnaissance` | high | TCP SYN/connect scans, UDP scans, ICMP sweeps, broadcast/multicast discovery and OT-protocol discovery. Explicit scanner/NMS/inventory roles use more tolerant thresholds, not a blanket bypass. |
| `c2_beacon` | dynamic | Suspiciously regular external connection timing. |
| `c2_correlated` | dynamic | Correlated C2 evidence. |
| `builtin.dns_tunneling` | high | High entropy/unique labels, TXT ratio and request/response byte asymmetry over a bounded DNS window. |
| `malicious_ip` | critical | Threat-intelligence IP match. |
| `malicious_domain` | critical | Threat-intelligence DNS/domain match. |
| `honeypot_probed` | medium | Traffic reaches a configured deception endpoint. |
| `honeypot_lateral_movement` | critical | A deception endpoint initiates lateral traffic. |

External-communication alert keys group public peers by IPv4 /24 or IPv6 /64 scope, avoiding one alert per CDN address while also avoiding the old problem where approving one Internet destination implicitly suppressed every Internet destination for that asset.

## Baseline, behavior and process values

| ID | Default | What it detects |
|---|---|---|
| `new_communication` | medium | Relationship/service absent from trusted communication baseline. |
| `new_asset` | medium | New asset after baseline learning. |
| `value_out_of_range` | medium | OT process value outside robust learned bounds. |
| `ot_value_anomaly` | dynamic | Rate/toggle/stuck/missing-value behavior deviation. |
| `behavior_finding` | dynamic | NBA finding above alert threshold. |
| `behavior_incident_candidate` | dynamic | Correlated NBA finding above incident threshold. |

Behavioral/baseline rules remain suppressed during learning and are previewed instead. Hard-security/policy rules remain active. Security-signaled relationships are excluded/quarantined from trusted learning.

## Tunable parameters

Selected typed built-ins expose numeric policy parameters in the Rules UI:

| Rule | Parameters (product defaults) |
|---|---|
| Brute Force I/O | `commands_threshold=50`, `window_seconds=10` |
| Malformed OT Burst | `errors_threshold=10`, `window_seconds=60` |
| OT Reporting Loss | `min_samples=10`, `cadence_multiplier=5`, `min_missing_seconds=600`, `max_missing_seconds=21600` |
| New Engineering Workstation | `controller_threshold=3`, `window_hours=24` |
| Large Controller Transfer | `bytes_threshold=10485760`, `window_seconds=300` |
| DNS Tunneling | `min_queries=20`, `window_seconds=600`, `score_threshold=60` |
| Gratuitous ARP Storm | `events_threshold=20`, `window_seconds=60` |

Unknown parameter keys are retained for forward compatibility but have no effect until a detector consumes them.

## Severity policy

`auto` is recommended for detectors that compute severity from risk/context. The built-in's displayed severity is the product default, but it does not flatten a detector-computed critical result. An explicit operator severity override forces the selected value. Resetting the severity policy to `auto` restores detector/default behavior.

## Approval semantics

Approving an alert remains an analyst workflow action. For relationship/identity findings it can additionally represent an explicit trust decision:

- ARP/duplicate/gateway identity approval promotes the observed MAC transition;
- unauthorized OT command/write or unexpected engineering access approval can authorize access + command authority for that source→target relationship;
- direct OT access approval authorizes read/access only;
- unexpected protocol approval authorizes that protocol/service relationship;
- unauthorized time-change approval authorizes the time-source relationship;
- remote-management/SMB relationship approval authorizes that source→target management service.

This is intentionally different from passive learning: security-sensitive relationships are never promoted merely because they repeat.
