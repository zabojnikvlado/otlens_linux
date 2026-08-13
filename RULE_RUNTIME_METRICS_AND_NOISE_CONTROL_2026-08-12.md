# OTLens — Rule runtime metrics and detection noise control

Date: 2026-08-12

## Goal

Replace the ambiguous Detection Rules `Hits` counter with operationally useful runtime metrics and reduce avoidable baseline/reconnaissance noise without weakening explicit analyst trust decisions.

## Detection Rules runtime metrics

The Rules UI now separates:

- **Active** — distinct non-approved findings seen in the last 5 minutes;
- **Last 24h** — occurrence deltas tracked by Central in rolling minute buckets;
- **Retained** — cumulative occurrence counts retained for the rule alert type;
- **Unique** — distinct retained alert/finding identities;
- **Last hit** — most recent occurrence timestamp.

The rule detail dialog also shows **New findings · 24h**.

`HitCount` remains on the API as a compatibility alias for retained occurrences, but the UI no longer labels the value simply as `Hits`.

### Durable 24-hour occurrence tracking

Central migration **v22 — rule runtime occurrence metrics** adds `rule_occurrence_buckets`.

During alert-history upsert Central compares the incoming sensor episode Count with the previously retained Count and writes only the positive delta. This prevents a finding with a lifetime Count of 500 from being counted as 500 new hits merely because it was seen recently.

The migration conservatively seeds the first 24-hour window from existing retained alert history. From deployment onward the counter is driven by exact sensor Count deltas (bucketed to the minute).

Rule occurrence buckets follow alert retention and are cleared by Alerts/Factory reset operations. They are included in core Central snapshots.

## Sensor rule telemetry performance

`detect.Engine.GetRules()` previously scanned the complete alert map once per rule. With tens of thousands of retained alerts this produced an O(rules × alerts) telemetry cost.

It now performs one alert aggregation pass and then maps those totals to rules. This provides sensor-side fallback metrics for:

- retained occurrences;
- unique findings;
- active findings;
- last hit / last-hit IP.

## New Communication noise control

Baseline service classification no longer relies only on the lower of the two ports.

Selection now prefers:

1. TCP SYN/SYN-ACK direction;
2. known TCP/UDP service ports;
3. non-dynamic vs IANA dynamic/private ports;
4. a stable `dynamic` service bucket for unknown high/high UDP pairs.

Common IT and OT services are recognized, including DNS, DHCP, NTP, SNMP, SMB, SSH, HTTP(S), RDP, Modbus, S7, DNP3, IEC-104, OPC UA, EtherNet/IP, BACnet, VXLAN and common discovery services.

Pre-v22 learned/approved baseline keys remain accepted. An upgrade therefore does not invalidate analyst-approved communication. Pending legacy findings remain retained history, while future occurrences use the improved key so noisy dynamic-port keys stop growing.

Routine multicast/broadcast discovery traffic such as mDNS, SSDP, LLMNR, DHCP and WS-Discovery no longer creates generic `New Communication` baseline findings.

## Reconnaissance / discovery noise control

Routine multicast/broadcast discovery services are no longer counted as reconnaissance packet bursts. Generic/unknown multicast or broadcast discovery remains detectable, with the default special-discovery burst threshold increased from 20 to 40 packets per reconnaissance window.

Explicit scanner/NMS/vulnerability/discovery asset roles continue to use the existing 4× thresholds.

OT-specific discovery ports are not part of the routine-discovery suppression list, so OT protocol discovery remains observable.

## Upgrade behavior

- Rebuild/deploy **Sensor + Central/Web UI**.
- No database reset is required.
- Central applies migration v22 automatically.
- Existing alert history and approved baseline decisions are preserved.
- Historical retained occurrence totals remain visible in the new `Retained` column; they are intentionally not rewritten or hidden.
