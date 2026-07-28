# Advanced detections

## OT value anomaly detection

The sensor builds a bounded online profile per decoded numeric Modbus/S7 tag. It raises `ot_value_anomaly` with structured `anomaly_score` and `anomaly_confidence` evidence for:

- statistical deviation from the learned mean/variance;
- excessive rate of change;
- a value that remains unchanged while polling continues;
- missing updates;
- excessive toggling;
- OT write operations.

The implementation uses online statistics and does not retain every raw poll. Existing tag/value-change storage remains unchanged.

## Lateral movement

`lateral_movement` correlates internal administrative traffic over SSH, RPC, NetBIOS, SMB, RDP and WinRM. Signals include:

- administrative fan-out to multiple internal hosts;
- large transfer volume over an administrative service;
- sequential pivot behavior A → B → C.

Evidence uses `lateral_movement_score` and `lateral_movement_confidence`. Large transfer is inferred from packet bytes and does not claim a named file was copied.

## C2 correlation

The existing regular-interval beacon detector now emits `c2_score`, `c2_confidence`, and `c2_signals`, and increases the score when the destination IP matches threat intelligence.

The additional `c2_correlated` DNS detector combines:

- long DNS labels;
- NXDOMAIN bursts;
- many unique subdomains of the same base domain;
- malicious-domain threat-intelligence matches.

DNS-over-HTTPS and DNS-over-TLS remain opaque without decryption. TLS SNI/fingerprint and SMB application metadata are future enrichments, not prerequisites for this MVP.
