# Web UI Performance Update

The Central Web UI now uses view-scoped refreshes instead of reloading every API resource after each action.

## Changes

- Each navigation tab declares only the API resources it needs.
- Opening a tab loads that tab's data lazily.
- Recently loaded tabs use a 15-second freshness window.
- Concurrent requests for the same endpoint are deduplicated.
- CRUD actions refresh only the active view through the compatibility refresh entry point.
- SSE events are mapped to affected domains (incidents, alerts, sensors, assets, reports, dashboard) rather than triggering a global reload.
- The recovery poll refreshes only the active tab once per minute.
- Topology keeps its existing ETag handling and is fetched only while the Topology tab is active.

## Deployment

Only Central must be rebuilt and restarted. The sensor protocol and sensor binary are unchanged.
