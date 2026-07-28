# Observed IT→OT Attack Path and Purdue Overlay

This implementation intentionally reports **observed directional paths** from stored `flow_observations`. It does not claim reachability through firewall rules or credentials that were not observed in traffic.

## Data sources

- `topology_nodes`: asset identity, VLAN, OT flag and observed protocols.
- `vlan_config`: VLAN-level Purdue assignment and zone name.
- `asset_context`: per-asset role, criticality, zone, Purdue override, entry/target flags.
- `flow_observations`: initiator/responder, service port, directional counters and time buckets.

Per-asset Purdue overrides take precedence over VLAN mappings. Assets without either are returned as `Unclassified`.

## API

- `GET /v1/sensors/:id/purdue-topology`
- `GET /v1/sensors/:id/itot-paths?source_ip=...&lookback_hours=24&max_hops=4`
- `GET /v1/asset-context?sensor_id=...`
- `PUT /v1/sensors/:id/assets/:ip/context`

Example context update:

```json
{
  "asset_role": "engineering_workstation",
  "criticality": "high",
  "zone": "OT operations",
  "purdue_override": 3,
  "is_attack_path_entry": true,
  "is_attack_path_target": false
}
```

## Scores

- `path_risk_score`: impact-oriented score for the complete path.
- `path_confidence`: strength of the observed evidence and available metadata.

These fields are independent from `deception_score` and `exposure_score`.
