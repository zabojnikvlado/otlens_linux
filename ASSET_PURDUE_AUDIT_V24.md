# OTLens v24 — Asset & Purdue/VLAN Integrity Audit

Date: 2026-08-11

## Scope

This audit covers the complete asset and Purdue/VLAN path in the cumulative v24 branch:

- sensor asset discovery, identity, ARP/IP/MAC tracking and persistence;
- asset confirmation, deletion, pruning, baseline learning and reset;
- Central current inventory, historical identity, DHCP/IP reuse and topology;
- Devices / Assets / Asset 360° / recon / vulnerability / risk / contact tracing;
- operator asset context: role, criticality, zone and Purdue override;
- VLAN/Purdue segmentation configuration, sync, persistence and detection;
- IT/OT / Purdue views, attack paths and report/trend inputs;
- import/export and reset/retention interactions relevant to assets.

## Critical and high-severity findings fixed

### 1. Asset identity was not consistently stable across DHCP changes

Central already had MAC information, but several operator-owned states were still keyed by IP. A device changing IP could therefore keep one identity in the inventory while its role/Purdue/security/risk state remained attached to the old IP. Conversely, a different device reusing the old IP could inherit context that belonged to the previous device.

Fixed by introducing a stable identity (`mac:<canonical-mac>` when a valid 48-bit MAC is known, otherwise `ip:<ip>`) and using it for operator-owned state. The current IP is now display/routing state, not the durable owner key.

### 2. Historical topology rows were being used as current asset inventory

`topology_nodes` is a historical ledger. Older DHCP aliases could remain there and be rendered as separate current Purdue/IT-OT assets.

Fixed by adding an explicit `active` state. Every complete sensor topology snapshot now reconciles the current inventory: identities present in the snapshot become active; omitted identities become inactive. Historical identity remains available separately.

### 3. IP reuse could inherit current-state metadata from the previous MAC

When the same IP was later used by another MAC, sticky current-row fields such as OT classification/first-seen could survive the replacement.

Fixed by detecting a MAC change on the same IP and resetting current-occupant metadata while preserving both historical device/IP episodes in `asset_identity_history`.

### 4. Central-managed VLAN/Purdue policy was not authoritative after sensor restart

Segmentation configuration was previously delivered as a one-shot command. The UI/Central could therefore show VLAN 20 = Purdue L1 while a restarted sensor was again detecting with its local YAML policy.

Fixed by making segmentation policy part of every sensor sync response. Central sends a complete managed snapshot when configured and an explicit `managed=false` when it is not. Sensor policy state is persisted and safely restored on restart.

### 5. Fresh Central could leave a sensor using stale persisted Central policy

A `nil`/missing configuration could not distinguish “no update” from “Central no longer manages segmentation”.

Fixed with an explicit managed/unmanaged state. When Central is unmanaged, the sensor returns to its local YAML segmentation configuration.

### 6. Purdue fallback could falsely assign routed L3 endpoints to the local VLAN

The old fallback could use the packet VLAN tag together with `SrcIP`/`DstIP`. On routed traffic this could teach a remote private IP as a member of the local VLAN, producing false Purdue level-jump detections.

Fixed: VLAN membership is learned only when IP↔MAC is confirmed by trusted ARP on that L2 segment. Source and destination membership are learned independently. Purdue fallback compares only already-confirmed VLAN memberships.

### 7. Repeated unmanaged sync could continuously erase locally learned VLAN membership

Because `managed=false` is now intentionally sent on every sync, blindly restoring local policy each time would clear the live IP→VLAN cache every sync.

Fixed: managed→local restoration is idempotent; when the sensor is already unmanaged, the existing local VLAN observation cache is preserved.

### 8. Asset confirm/delete acknowledgement was delivery-based, not state-based

A command could be marked delivered because the sensor downloaded it, even if the desired inventory state had not yet been demonstrated in telemetry.

Fixed: confirm/delete commands remain pending until a complete topology snapshot proves the result (`Confirmed=true` for confirm, MAC absent for delete). Sensor flushes persistence immediately after applying the operation, and commands remain idempotently replayable until confirmed.

## Sensor asset engine fixes

- Asset restore now replaces the in-memory asset map correctly instead of leaving stale map contents.
- `Confirmed` is preserved exactly through restart; unreviewed assets are not silently trusted after restore.
- Delete/prune/clear remove associated ARP-verification and baseline-trust state.
- Learning reset clears baseline/trust classification while retaining inventory.
- ARP provenance is persisted (`IPVerificationKnown`, `IPVerifiedByARP`) so a restart does not make an unverified binding appear authoritative.
- A routed packet cannot replace an ARP-verified IP↔MAC binding; a valid ARP update can.
- MAC addresses are normalized to canonical 48-bit form. Invalid/EUI-64/multicast identifiers are rejected or skipped where appropriate.

## Operator context / Purdue overrides

`asset_context`, `asset_security_status`, and `asset_risk_exceptions` are now owned by stable asset identity rather than the current IP.

Consequences:

- role/criticality/zone/Purdue overrides survive DHCP moves;
- an old IP reused by a different device does not inherit the previous device's operator context;
- orphaned context is preserved for the original identity but is not pushed to a new IP occupant;
- per-asset Purdue override has explicit precedence over discovery classification;
- role-based OT classification recognizes common field/OT roles (PLC, RTU, IED, drive, HMI, SCADA, historian, safety, actuator, sensor, etc.);
- Purdue levels are strictly validated to `{0,1,2,3,3.5,4,5}` and criticality is validated.

The sensor's learned OT model is also kept separate from Central operator context. Pushing a Central role/zone no longer contaminates the persisted learned `otAssets` set.

## VLAN / Purdue configuration validation

Central and local sensor configuration now validate:

- VLAN ID: `0..4094`;
- Purdue level: exactly `0,1,2,3,3.5,4,5`;
- `max_level_jump`: greater than 0 and no more than 5.

Invalid values can no longer wrap through a `uint16` cast or silently enter detection state.

Configured VLANs remain visible even when no current asset is assigned to them. VLAN/Purdue asset lists use the current active canonical inventory rather than the historical topology ledger.

## Devices / Assets / Asset 360°

### Current vs quiet inventory

The previous UI used a 10-minute freshness threshold to call an asset “stale”, even though the sensor intentionally retains quiet assets for much longer. That could make a normal quiet PLC appear stale and could even influence UI risk presentation.

The UI now separates:

- `Current` identity: present in the current retained sensor inventory;
- observation freshness: `recent` vs `quiet` (not seen in the last 10 minutes).

Quiet inventory is no longer treated as a security finding by Asset 360°.

### Asset 360° alert history

Related alert lookup now follows the stable identity's known IP aliases and performs structured IP matching rather than searching only a small global recent-alert slice. This avoids missing older retained alerts associated with a device that changed IP.

### Reconnaissance

Recon history and latest recon profile follow stable IP aliases. A DHCP move therefore does not make the historical recon profile disappear from Asset 360°.

### Vulnerability state

Finding updates derive stable identity from the current IP/MAC rather than trusting a browser-supplied identity, so finding workflow state survives DHCP changes safely.

### Security/contact state

Infected/suspected state is stable-identity owned and is mapped to the current IP only when that identity is currently present. A different device reusing the old IP does not inherit the old security state.

## Asset risk fixes

Asset-risk calculation now operates on the current canonical inventory and follows identity aliases for relevant retained history.

- vulnerability contribution follows stable identity;
- operator OT context influences effective OT classification;
- active high/critical alert matching follows aliases and structured evidence fields;
- external-exposure detection follows aliases and excludes private, loopback, link-local, CGNAT, multicast, unspecified and reserved/documentation ranges;
- prior risk trend can follow the identity across an IP change;
- obsolete current-IP risk rows are removed while risk history is preserved.

## Import / category handling

- Device category vocabulary is aligned between backend and UI.
- Category normalization is case-insensitive and accepts only supported values.
- Bulk asset override import runs in one DB transaction, so a database failure cannot leave a half-applied import.
- Invalid rows are skipped and the UI reports `received / applied / skipped` counts.

## Trends / reports / backups

- New-asset trends use identity history rather than overwrite-prone current IP rows.
- Core Central snapshots include stable identity/operator asset state required to understand the inventory model.
- Identity history is not removed by routine telemetry age retention; it is cleared by explicit relevant reset/sensor-delete operations.

## Reset semantics

- Asset learning reset keeps discovered inventory but clears learned baseline/trust classification.
- Asset inventory reset clears current sensor assets/flows; Central operator policy remains identity-owned and can remain orphaned until the same identity returns or is explicitly removed by the relevant Central reset workflow.
- Full observed-data reset clears Central identity history together with topology/telemetry according to the existing reset semantics.

## Database migration

This patch adds additive/in-place Central migrations:

- v10 — stable asset identity and Purdue consistency;
- v11 — active asset reconciliation and identity-owned operator state.

No full Central reset is required. On upgrade, current active topology is reconstructed from the latest stored sensor topology where possible; the next complete sensor sync authoritatively reconciles it.

## Remaining architectural limitations

These were reviewed and are intentionally documented rather than hidden as “fixed”:

1. **Learned OT behavior remains partly IP-keyed.** Trusted masters/protocol relationships and some learned detector state are not yet fully MAC/stable-identity keyed. DHCP churn can therefore leave stale learned relationships until relearning/reset.
2. **Manual-confirm provenance is not separate from baseline-confirm provenance.** `Confirmed` currently represents both concepts. A future schema should persist “operator confirmed” independently from “learned/known during baseline”.
3. **Multi-NIC devices are separate identities.** A chassis with multiple MACs is currently modeled as multiple assets unless higher-level correlation is added.
4. **ARP conflict protection is deliberately conservative.** An IP that changes MAC is not immediately trusted by the detector until the conflict is validated/relearned; this protects against spoofing but can temporarily delay a legitimate DHCP replacement.
5. **Before authoritative ARP is observed**, routed Ethernet traffic can still give the asset engine an imperfect provisional L3↔L2 association. The persisted ARP-provenance guard prevents it from becoming permanently authoritative after restart.
6. **QinQ/stacked VLAN tags are not modeled completely.** The packet model retains one VLAN ID, so provider/customer tag semantics cannot be represented simultaneously.
7. **Tagged→untagged moves can leave the inventory's last VLAN display behind** until a trusted membership update exists. The live detector's ARP-confirmed membership is intentionally stricter than the display field.
8. **Automatic Purdue fallback is IPv4/ARP-oriented.** IPv6 NDP is not yet used as an authoritative VLAN membership source. Explicit Central zone/Purdue contexts remain available for IPv6 environments.
9. **A DHCP/context remap can lag by one sensor sync interval.** The sensor pulls Central context before uploading the topology snapshot that may reveal its newest IP.
10. **Queued safe reconnaissance targets an IP.** If DHCP changes between queue and execution, the job can still scan the old IP.
11. **Historical flow/contact/attack-path evidence is IP/time based.** If an IP is reused by different devices, very old flow evidence can be ambiguous without an identity-at-event-time join.
12. **Pre-migration history cannot always be reconstructed.** If older v24 code already overwrote an IP row after MAC reuse, the missing previous identity cannot be perfectly recreated from that row alone.
13. **Vulnerability matching remains heuristic** (vendor/product/passive evidence), not exact authenticated firmware inventory.
14. **Asset 360° related alert retrieval is capped** (currently up to 5000 retained matches) to bound interactive queries.

## Deployment recommendation

Rebuild and deploy **Sensor + Central + Web UI** from this cumulative patch. Keep the existing sensor SQLite persistence database and Central PostgreSQL database. Do **not** perform a full reset for the migration.

After deployment, verify:

1. the sensor reconnects and sends a complete topology snapshot;
2. existing operator roles/zones/Purdue overrides still appear on the same MAC identities;
3. a DHCP-moved test asset keeps its context while the old IP does not pass that context to another MAC;
4. the sensor log confirms the expected persistence database path;
5. Central VLAN/Purdue configuration is reflected on the sensor after a sensor restart.
