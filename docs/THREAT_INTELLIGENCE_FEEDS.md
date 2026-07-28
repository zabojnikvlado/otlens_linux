# Threat intelligence feed configuration

Threat intelligence is loaded by each sensor from `detect.threatintel` in `sensor.config.yaml`.
Central displays resulting `malicious_ip` and `malicious_domain` alerts; it does not fetch feeds on behalf of sensors.

Supported sources:

- inline static indicators for small local lists;
- local JSON files for air-gapped definition updates;
- HTTP/HTTPS JSON feeds refreshed on `refreshinterval`.

Example:

```yaml
detect:
  threatintel:
    enabled: true
    refreshinterval: 1h
    httptimeout: 15s
    maxdnsobservations: 5000
    indicators:
      - type: ip
        value: 203.0.113.40
        threat_type: c2
        confidence: 90
        source: internal-soc
    feeds:
      - name: internal-feed
        enabled: true
        url: https://ti.example.local/otlens.json
        file: ""
```

Feed JSON format:

```json
[
  {"type":"ip","value":"203.0.113.40","threat_type":"c2","confidence":90,"source":"internal-soc"},
  {"type":"domain","value":"bad.example","threat_type":"malware","confidence":85,"source":"internal-soc"}
]
```

For an air-gapped sensor, set `file` to a locally updated JSON file and leave `url` empty. Feed transport credentials are intentionally not exposed in the Central Settings UI.
