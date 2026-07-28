# Threat intelligence and passive DNS

OTLens now normalizes UDP DNS traffic on port 53 into query/response observations containing client/server IP, query name/type, response code, A/AAAA answers, CNAMEs and TTL.

The sensor-side threat-intelligence store supports:

- static IP/domain indicators from `sensor.config.yaml`;
- local line-oriented IOC files;
- HTTP line-oriented IOC feeds;
- HTTP/local JSON arrays with `type`, `value` and optional `threat_type`.

Matches raise `malicious_ip` or `malicious_domain` alerts. Alert evidence keeps the provider, indicator value/type, threat type and `threat_intel_confidence`; it does not reuse deception, exposure or attack-path scores.

DNS observations are uploaded to Central, retained in `dns_observations`, and available through:

`GET /v1/dns-observations?sensor_id=...&query=...&client_ip=...&limit=500`

Limitations: DNS over HTTPS/TLS is not visible without decryption. TCP DNS is not decoded in this first implementation. Feed authenticity and licensing remain deployment responsibilities; use TLS and trusted internal mirrors for production.
