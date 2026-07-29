# Live Operations Phase 4

This release completes the operational live layer around the existing SSE hub.

## Added

- bounded live event history (`GET /v1/live/history`) for notification replay and operational review;
- authenticated analyst presence (`GET/POST /v1/live/presence`) with automatic expiry;
- collaborative Incident Workbench presence, refreshed every 15 seconds;
- immediate incident workbench refresh when its incident changes;
- persistent in-browser notification center with severity, acknowledgement and navigation;
- topology highlighting for live entity events;
- continued single-stream connection management, replay, keepalive and polling fallback.

Presence records are held in memory and expire after 45 seconds. They contain only user and entity identifiers and are not a durable audit record. Incident edits remain protected by the existing RBAC and audit controls.
