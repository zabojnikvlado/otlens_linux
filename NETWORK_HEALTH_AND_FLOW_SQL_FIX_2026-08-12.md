# OTLens — Network Health + flow telemetry SQL fix

Date: 2026-08-12

## 1. Flow telemetry SQLSTATE 42883

`persistFlowObservations` used a parameterized PostgreSQL `VALUES` table for batch flow ingestion. Casting the derived columns only in the outer SELECT was not sufficient to give the bind parameters an unambiguous type during PostgreSQL parse/type inference. On affected PostgreSQL/pgx paths, `bucket_start` / `bucket_end` could therefore remain `text`, causing:

`operator does not exist: timestamp with time zone <= text (SQLSTATE 42883)`

The batch now casts every placeholder at the point where it enters `VALUES`:

- sensor/flow/IP/protocol fields: `text`
- bucket timestamps: `timestamptz`
- ports/VLAN: `integer`
- packet/byte counters: `bigint`
- OT flag: `boolean`

This removes the ambiguity before the event-time asset-binding lookup is planned.

## 2. Network Health incorrectly reported 100%

The Dashboard hero previously reused the Network Behavior Analytics health score directly. That score intentionally considers only active `behavior_*` findings. Therefore a mature behavior baseline with zero behavior findings reported 100% even when the system had ordinary security alerts and hundreds of open incidents.

The Dashboard Network Health hero now represents composite network posture:

- behavior health when the baseline is mature;
- active alert severity;
- open/high-risk incidents;
- unreviewed alert backlog (bounded contribution);
- offline/stopped/degraded sensors.

A high-risk incident, critical alert, or offline sensor prevents a 100%/healthy posture. Very large unreviewed backlogs also prevent a healthy posture even if the alerts are not active in the five-minute window.

The behavior-specific KPI fields remain behavior-specific: `Behavior alerts`, `Top anomaly`, baseline coverage and learning state are not relabeled or conflated with general alerts.

## 3. Dashboard Healthy banner

The top-right Dashboard banner previously considered sensor status and active alerts but ignored incidents. It now reports:

- Critical: offline sensor, critical active alert, or high-risk open incident;
- Warning: stopped sensor, any open active alert, or any open incident;
- Healthy only when sensors are running and there are no open alerts or incidents.

## Verification

- all Go files parse successfully;
- modified Go files are `gofmt` clean;
- `app-detection.js` and `app-nba.js` pass `node --check`;
- regression test added for explicit typed PostgreSQL VALUES placeholders.

No database migration or sensor change is required. Rebuild/redeploy Central and hard-refresh the Web UI.
