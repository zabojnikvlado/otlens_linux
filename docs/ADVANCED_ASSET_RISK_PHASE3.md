# Advanced Asset Risk Engine — Phase 3

Implemented contextual and adaptive asset risk scoring with business criticality, Purdue/zone context, external exposure, vulnerability severity maturity, bounded category scoring, topology risk propagation, history/trends, analyst exceptions, compensating controls, score overrides, expiry, and prioritized remediation guidance.

## API
- `GET /v1/asset-risk`
- `GET /v1/asset-risk/:sensor/:ip/history`
- `GET /v1/asset-risk/:sensor/:ip/exception`
- `PUT /v1/asset-risk/:sensor/:ip/exception`

Asset 360 includes a Risk tab with component scores, trend history, drivers, recommended remediation and analyst disposition workflow.
