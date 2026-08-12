# OTLens — Custom Device Categories & Topology Category Filter

Date: 2026-08-12

## Device classification

Central now maintains a persistent device-category catalogue.

- Existing predefined categories are seeded as built-in and remain protected.
- Operators with the existing asset classification permission can add custom categories.
- Custom categories are immediately available in the per-device category selector and CSV/JSON asset override import.
- Category matching for imports is case-insensitive while the canonical display spelling is preserved.
- Custom category names are trimmed, must be valid UTF-8, may contain normal punctuation (including `/`), may not contain control characters, and are limited to 64 characters.
- Deleting a custom category is transactional. Devices assigned to it keep their optional friendly-name override but their category override is cleared, so they safely return to automatic classification. Built-in categories cannot be deleted.
- Add/delete/set operations remain audited.

New API endpoints:

- `GET /v1/device-categories`
- `POST /v1/device-categories` with `{ "name": "..." }`
- `DELETE /v1/device-categories` with `{ "name": "..." }`

The existing per-device endpoint now accepts both built-in and custom catalogue values:

- `POST /v1/sensors/:id/assets/:mac/category`

## Topology

Topology nodes now carry their effective Device Classification category.

- Manual category override has highest precedence.
- Without an override, the category uses the same automatic classification logic as the Device Classification tab, including Central asset role/Purdue context when it changes effective OT classification.
- The node tooltip shows the category.
- Topology search includes category text.
- A new Category selector filters topology nodes and composes with the existing VLAN filter.
- Edges connected to hidden nodes follow vis-network node visibility naturally.

## Cache correctness

The `/v1/topology` ETag previously depended only on sensor telemetry sequence numbers. That would allow a browser to receive `304 Not Modified` after an operator changed a category even though the topology representation had changed.

The topology fingerprint now also includes a compact hash of operator-owned `asset_overrides` and `asset_context` state, so category/context edits generate a new ETag immediately without requiring new sensor telemetry.

## Persistence and migration

Central migration **v15 — operator-managed device categories** adds `asset_categories` and seeds all existing predefined values as built-in.

The Central operational/core JSON snapshot now includes `asset_categories`.

No database reset is required. Existing `asset_overrides` remain intact.

## Deployment

This change requires rebuilding/redeploying **Central + Web UI only**. The sensor binary and sensor SQLite database are unchanged.

## Validation performed

- `gofmt` on changed Go sources.
- All Go source files parsed successfully with the Go parser.
- All production `web/central/app-*.js` files passed `node --check`.
- A full `go test ./internal/central` could not complete in the supplied environment because it is running Go 1.23.2 and external module downloads (`gin`, `pgx`, `x/crypto`, `zap`) timed out. Run the normal project test/build pipeline with the project's Go 1.25 toolchain before production deployment.
