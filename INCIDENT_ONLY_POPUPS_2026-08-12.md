# OTLens — Incident-only live popups

Date: 2026-08-12

## Change

Live toast popups are now shown only for `incident.*` events. New alert events (`alert.created`) and other live events continue to update their normal pages/dashboard state and remain available in the live notification center, but no longer create a popup toast.

The incident toast still opens the Incidents tab when clicked.

## Deployment

Central/Web UI only. No sensor rebuild or database migration is required. Browser cache bust for `app-core.js` was incremented from v32 to v33.
