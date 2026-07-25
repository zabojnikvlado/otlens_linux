# Phase 3.6.5 — Honeypot score and lateral-movement detection

## Configuration

The Linux sensor assigns a deception score from 0 to 100 to selected asset IP addresses. The global threshold decides which scores represent a honeypot.

```yaml
deception:
  honeypotthreshold: 80
  stations:
    - ip: "10.10.20.250"
      score: 100
    - ip: "10.10.20.251"
      score: 60
```

With this configuration, `10.10.20.250` is a honeypot and `10.10.20.251` is only a scored asset because its score is below 80.

Both the threshold and every station score must be in the range 0–100. Duplicate or empty station IP addresses prevent sensor startup with a clear configuration error.

## Detection semantics

Traffic **to** a honeypot creates the built-in `Honeypot Probed` alert.

Traffic **initiated by** a honeypot creates the built-in `Honeypot Lateral Movement` critical alert. The direction is important: a honeypot acting as source suggests that the decoy may have been compromised and is being used as a pivot.

The built-in rules can be enabled or disabled in the Rules tab:

- Honeypot Probed
- Honeypot Lateral Movement

## Topology

- Honeypot nodes are purple.
- Node details show the score and honeypot classification.
- Communication initiated by a honeypot is rendered as a thick solid red directed edge labelled `POTENTIAL LATERAL MOVEMENT`.
- This red state has priority over OT and inter-VLAN edge styling.

## Assets tab

The Assets table exposes:

- Score
- Classification (`HONEYPOT` or `standard`)

The score is assigned from sensor configuration and recalculated after restart, so removing or changing a station entry updates the asset classification.
