# OTLens — Network / Zone Analytics Result-State Fix

Date: 2026-08-12

## Problem

The Network / Zone Traffic page could finish an Analyze request and then show an empty result area: the loading text disappeared, but no KPI cards, explicit no-data state, or error was rendered. A render exception was especially confusing because `analyticsState` was assigned before all DOM rendering completed, causing the catch path to suppress the visible error.

The common `VLAN / Any ↔ VLAN / Any` selection was also treated as an inventory-scoped query even though both values were unrestricted. That unnecessarily used the topology/asset-override enrichment path for a broad flow query.

## Fix

- Analytics result rendering is transactional: state is committed only after the response has been normalized and all result panels have rendered successfully.
- Every completed request now has exactly one visible outcome: data, `No matching traffic`, or a visible error (including request ID when available).
- Starting a new Analyze request immediately clears stale error/no-data/result content and shows a loading state.
- Changing filters clears stale results and marks the view `Filters changed · click Analyze`.
- Missing JSON arrays/summary/baseline fields are normalized to safe empty defaults instead of causing a renderer exception.
- Inventory scope types with an empty value (`VLAN / Any`, `Zone / Any`, `Purdue / Any`, `Category / Any`) are normalized server-side to unrestricted `Any`.
- `Any ↔ Any` uses a lightweight flow-only CTE and avoids current-topology and asset-override joins. Peer labels use IP addresses in this unrestricted fast path.
- Existing scoped VLAN/Zone/Purdue/Category analytics continue to use stable-identity scope resolution.

## Verification

- `node --check web/central/app-analytics.js`
- all 215 Go files parsed successfully with the standard Go parser
- regression tests added for unrestricted Network/Zone scope normalization and the lightweight Any↔Any query path

A full package test was not available in this environment because external Go modules were not cached and dependency download timed out.

## Deployment

Rebuild/redeploy Central + Web UI. No sensor change, database reset, or migration is required. Hard-refresh the browser after deployment (`Ctrl+F5`).
