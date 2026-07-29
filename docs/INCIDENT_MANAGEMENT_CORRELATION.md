# Incident Management & Correlation

OTLens Central now persists correlated alert groups as managed incidents instead of presenting only an ephemeral grouping.

## Correlation

Alerts are correlated when at least two distinct alert types affect the same sensor and IP within 24 hours. Central records the contributing alert events, calculates a bounded 0–100 score, and assigns confidence based on evidence diversity.

## Workflow

Incidents support the workflow `new → investigating → contained → resolved → closed`, analyst ownership, summaries, and timestamped comments. Workflow and comment changes are protected by the existing `alert_confirm_approve` capability and are written to the audit log.

## Asset risk

Central calculates a 0–100 asset risk score from recent high/critical alerts, active vulnerability findings, insecure observed protocols, unknown vendor identity, and stale inventory. The score and reasons are shown in the Incident Workbench and exposed at `GET /v1/asset-risk`.

## API

- `GET /v1/incidents`
- `GET /v1/incidents/:id`
- `PATCH /v1/incidents/:id`
- `POST /v1/incidents/:id/comments`
- `GET /v1/asset-risk`

Database schema migration version: **4**.
