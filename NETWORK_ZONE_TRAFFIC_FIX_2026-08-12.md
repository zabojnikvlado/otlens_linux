# OTLens — Network / Zone Traffic correctness & performance fix

Date: 2026-08-12

## Findings

The previous Network / Zone Traffic implementation had a correctness defect in VLAN scope handling. `flow_observations` stores one packet/flow VLAN scalar (`vlan_id`). The Analytics CTE copied that same value to both endpoints and then used it as both initiator and responder VLAN. As a result, a cross-VLAN query such as `VLAN 107 ↔ VLAN 222` could not reliably match even when traffic existed.

Category, Zone and Purdue filters also performed their inventory/context classification inside the high-volume flow query. On large histories this meant processing and joining the complete selected flow window before eliminating rows that did not belong to either scope.

## Fix

Network scope membership is now resolved before the flow scan:

- VLAN -> active canonical assets currently assigned to the selected VLAN;
- Zone -> active assets using explicit asset zone, otherwise the configured VLAN name;
- Purdue -> explicit per-asset Purdue override, otherwise configured VLAN Purdue level;
- Device category -> effective current device category, including operator-managed custom categories.

The resolved set uses `(sensor_id, stable asset identity)` so the same MAC observed by two sensors cannot inherit scope membership from the wrong sensor.

The flow query then pushes the resolved identity sets into the raw `flow_observations` scan before enrichment. Historical pre-v17 IP-only flow rows are accepted only through IP binding history overlapping the event timestamp, avoiding unsafe DHCP-reuse attribution.

The per-flow Category/Zone/Purdue/VLAN joins were removed from the analytics hot path. Current inventory is still used for readable peer names.

## Additional fixes

- Right-side-only filters now report the opposite endpoint in Top peers rather than the selected group itself.
- Connection counts across `All sensors` use `(sensor_id, flow_id)` rather than `flow_id` alone.
- Selecting a scope type while leaving its value at `Any` remains a valid unrestricted filter instead of becoming a 400 error.
- Network / Zone Traffic defaults to 6 hours instead of 24 hours for a faster first analysis.
- Migration v19 adds global stable-identity/time indexes and an identity-history lookup index.

## Semantics

VLAN / Zone / Purdue / Category scopes intentionally use the **current canonical inventory and current operator context** to define group membership, then apply that membership to the requested historical flow interval. Historical IP attribution remains event-time aware. A future context-history feature would be required to answer questions such as “what category/zone did this asset have at the exact historical event time” after an operator later changes its category or zone.

## Verification

- All 214 Go files parse successfully with the standard Go parser.
- `app-analytics.js`, `app-core.js`, and `app-operations.js` pass `node --check`.
- Regression tests were added for cross-VLAN identity scope construction, category/zone/VLAN/Purdue matching, `Any` scope semantics, and right-only peer direction.
- Full package tests could not be executed in the provided environment because it has Go 1.23.2 while the project requires Go 1.25 and uncached external modules time out during download.

No database reset is required. Migration v19 is additive.
