# High-priority security fixes

This release addresses the high-priority findings from the full-project audit.

## Sanitized HTTP errors

Internal and upstream failures no longer return raw Go error text to API clients. Responses contain a generic message and an `X-Request-ID`; the full cause is written to the Central log with the same identifier.

Validation errors that are intentionally safe and actionable remain visible as 4xx responses.

## Browser security headers

Both Central routers apply defense-in-depth headers. The management UI now receives a Content Security Policy, clickjacking protection, MIME sniffing protection, a restrictive referrer policy, permissions restrictions, and cross-origin isolation headers.

The existing vis-network CDN is explicitly allow-listed by the CSP. A future release should vendor that dependency so `script-src` can be reduced to `'self'` only.

## Safer configuration templates

`configs/central.config.example.yaml` is now the production-oriented template:

- TLS is enabled on both listeners.
- The bootstrap password is a non-working change placeholder.
- Comments identify it as the production-safe template.

`configs/central.config.development.example.yaml` is provided separately for isolated local development. It binds listeners to loopback and disables the emergency management token.
