# Operations and security hardening

This phase audits and extends the existing login and role-based access control implementation instead of replacing it.

## Permission audit

Administrators can inspect the sensitive API endpoint catalog in Settings. The table records the HTTP method, path, required server-side action and audit behaviour. UI visibility is not treated as authorization; the listed endpoints remain guarded by `requireAction` middleware.

## Audit timeline

The Audit view now supports server-side filters for actor, action/path, sensor and success status. Queries are parameterized and limited to 1,000 rows per request.

## Diagnostics bundle

Authorized operators can export a ZIP bundle containing:

- a generation manifest and schema version,
- non-secret runtime configuration,
- sensor operational state,
- the most recent audit entries,
- the permission audit catalog.

The export deliberately excludes passwords, password hashes, session identifiers, management tokens, reconnaissance credentials and packet payloads. Every export creates an explicit audit entry.
