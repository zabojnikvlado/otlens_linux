# Phase 3.6 – Policy & Detection Engine

Phase 3.6 replaces the original single-field custom rule with a structured policy rule evaluated on each parsed packet by the Linux sensor. Central provides management, validation, import/export and synchronization; the sensor remains the enforcement and detection point.

## Rule model

A custom rule contains:

- `name`, `description`, `category`
- `enabled`, `simulation`, `severity`, `priority`, `version`
- one or more condition groups
- `group_operator` (`AND` or `OR`) between groups
- an operator (`AND` or `OR`) inside every group
- actions and suppression settings
- an optional schedule field reserved for subsequent schedule enforcement

Example:

```json
{
  "name": "Unauthorized Modbus access",
  "category": "ics",
  "kind": "custom",
  "enabled": true,
  "severity": "critical",
  "priority": 10,
  "simulation": false,
  "group_operator": "AND",
  "groups": [
    {
      "operator": "AND",
      "conditions": [
        {"field": "protocol", "operator": "eq", "value": "TCP"},
        {"field": "port", "operator": "eq", "value": "502"}
      ]
    },
    {
      "operator": "OR",
      "conditions": [
        {"field": "src_ip", "operator": "eq", "value": "10.10.1.50"},
        {"field": "vlan", "operator": "neq", "value": "20"}
      ]
    }
  ],
  "actions": [{"type": "alert"}, {"type": "siem"}],
  "suppression": {"mode": "interval", "interval_seconds": 600},
  "schedule": "always"
}
```

## Packet fields

The first engine version evaluates these packet fields:

- `src_ip`, `dst_ip`, `either_ip`
- `src_mac`, `dst_mac`
- `protocol`
- `src_port`, `dst_port`, `port`
- `vlan`
- `packet_size`
- `tcp_flags`

The data model reserves categories for ICS, asset and OT-tag rules. Protocol-specific function codes, asset state and tag history require dedicated event evaluators and are not falsely represented as packet fields in this release.

## Operators

- `eq`, `neq`
- `gt`, `gte`, `lt`, `lte`
- `contains`, `starts_with`, `ends_with`
- `between` with `minimum,maximum`
- `in`, `not_in` with comma-separated values
- `regex`

## Suppression

- `aggregate`: reuse the same alert identity and increase its count
- `every`: create a separate alert identity for every occurrence
- `once`: trigger once until the sensor/rule state is reset
- `interval`: trigger no more frequently than `interval_seconds`

## Simulation

A rule in simulation mode is evaluated but does not generate an alert. The sensor increments an in-memory simulation match counter and records the last simulation match, while suppressing alert creation. The UI validation endpoint verifies the rule structure before it is saved. Full historical replay is planned separately because Central currently stores aggregated flows rather than raw packets.

## Built-in detections

Existing built-in detections remain available and can be enabled or disabled:

- ARP Spoofing
- New Communication
- Critical ICS Operation
- New Asset
- Value Out of Range
- Honeypot Probed
- Honeypot Lateral Movement

Built-in rules cannot be deleted.

## Central API

- `GET /v1/rules`
- `POST /v1/sensors/:id/rules`
- `PUT /v1/sensors/:id/rules/:rule`
- `PATCH /v1/sensors/:id/rules/:rule`
- `DELETE /v1/sensors/:id/rules/:rule`
- `POST /v1/sensors/:id/rules/test`
- `GET /v1/rules/export`
- `POST /v1/rules/import`

All modifying calls are included in the Central audit stream and can be exported to SIEM through the Phase 3.5.11 outbox exporter.

## Synchronization

Central queues `rule.add`, `rule.upsert`, `rule.toggle` and `rule.delete` commands. The sensor fetches commands during its configured Central synchronization interval, validates the rule and installs it in the detection engine. The resulting state and hit statistics return in sensor telemetry.

## UI workflow

1. Open **Rules** and select **Add rule**.
2. Choose a target sensor.
3. Set category, severity, priority, simulation and suppression.
4. Add condition groups and choose AND/OR logic.
5. Use **Test rule** for structural validation.
6. Save the rule and wait for the next sensor synchronization cycle.
7. Edit, enable/disable, delete, export or import custom rules from the Rules tab.

## Current limits

The model contains action names for future expansion, but this version executes alert generation; SIEM receives the resulting alert through the existing Central SIEM exporter. Direct script, e-mail, SNMP, MQTT and webhook execution is intentionally not enabled without dedicated secure connectors. Schedule metadata is stored but only `always` is enforced in this version.
