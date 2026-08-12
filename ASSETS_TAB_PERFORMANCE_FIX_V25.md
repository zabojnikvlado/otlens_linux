# OTLens v25 — Assets Tab Performance Fix

Date: 2026-08-12

## Symptom

Opening **Assets & Inventory → Assets** could remain on an empty `0 records` table for several seconds even with a modest inventory (for example ~168 assets). The delay was not primarily browser table rendering; the view waited for several unrelated/enrichment APIs and one of those endpoints performed a full risk recomputation during a GET request.

## Root causes fixed

### 1. `/asset-risk` performed work on read

`GET /asset-risk` previously called the full `RecalculateAssetRisk` engine before returning data. The risk engine performs several database lookups per current asset, creating an N+1 query storm when the Assets tab was opened.

The endpoint is now read-only and returns the latest materialized risk state. Risk recalculation remains on the existing write/telemetry paths: after telemetry processing and after analyst risk-exception changes.

### 2. Initial Assets render waited for enrichment APIs

The Assets domain previously waited for all of these requests before rendering inventory:

- `/assets`
- `/asset-security-status`
- `/asset-risk`
- `/behavior-overview`

Only `/assets` is now on the critical first-paint path. Security, risk and behavior data are fetched concurrently in the background with a short cache/TTL and trigger a second render only when available. Until then, enrichment-only cells show an explicit loading state instead of a false result.

### 3. `/assets` loaded the complete telemetry row

The endpoint only needs topology, but previously read/deserialized all `sensor_telemetry` JSONB fields, including unrelated alerts, DNS, SMB, UDP, baselines and rule payloads. It now uses a topology-only query.

### 4. Repeated per-sensor context/VLAN queries

Asset contexts and VLAN metadata were repeatedly queried inside the per-sensor loop. They are now loaded once for the request. A lightweight VLAN metadata query replaces the heavier inventory-oriented VLAN query for this endpoint.

### 5. Historical identity aggregation scaled with all retained history

`AssetIdentityMetadata` previously aggregated the full identity history before joining to the current inventory. It now starts from active, non-conflicted current identities and only aggregates history for those identities.

### 6. Orphan recon profiles were scanned for the current Assets view

Recon profile retrieval is restricted to identities represented by active, non-conflicted topology nodes.

### 7. Frontend per-row linear searches

Security and behavior enrichment used array `.find()` calls for every asset row. The renderer now builds keyed maps once per render, giving O(1) lookups per row. Asset search text is also cached per asset object.

## Database migration v14

The cumulative Central migration adds targeted indexes for current inventory and retained-history lookups:

- active topology inventory by sensor / last-seen;
- active canonical identity;
- asset identity history by identity / last-seen;
- active behavior alert lookup.

Migration name: `asset inventory read performance`.

This is an additive migration. **No full Central reset is required.**

## Expected UI behavior after the fix

1. `/assets` completes and the rows/pager appear immediately.
2. Security/risk/behavior enrichment loads in the background and updates the visible rows when ready.
3. A slow behavior query or a risk refresh no longer keeps the table at `0 records`.
4. `GET /asset-risk` no longer causes a full inventory risk recalculation.

## Deployment

Rebuild/deploy **Central + Web UI**. The cumulative archive also contains the earlier sensor identity/UDP fixes, but this Assets performance patch does not itself require a sensor-side change.

On startup, Central applies migration v14 automatically through the existing schema migration path.

## Validation performed in this workspace

- all modified Go files passed `gofmt`;
- all loaded Central JavaScript files passed `node --check`;
- clean-tree diff was reviewed to confirm only the intended Central/Web files changed.

A full Go test/build could not be completed in this offline workspace because the repository requires Go 1.25 while the locally installed toolchain is Go 1.23.2 and the required Go 1.25 toolchain/dependencies cannot be downloaded here.
