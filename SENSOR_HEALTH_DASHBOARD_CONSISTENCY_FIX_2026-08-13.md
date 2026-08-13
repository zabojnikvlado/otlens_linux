# Sensor health / Dashboard consistency fix — 2026-08-13

## Problem

The Sensors table displayed the latest operational `health_state` from `/v1/sensors/metrics`, while the Dashboard health banner primarily interpreted only the sensor registry `status` (`running`, `stopped`, `offline`). A sensor could therefore be actively capturing (`running`) but operationally `critical` because of packet drops, memory pressure, event-queue pressure, or repeated Central sync failures, while the Dashboard still showed Healthy/green.

The Network Health composite also treated all warning/critical metric states as a small generic warning penalty, so a critical sensor did not force a critical network posture.

## Fix

- Added one shared effective sensor-health model used by Sensors, Dashboard and Network Health.
- Availability precedence: `offline` > metric `critical` > `stopped` > metric `warning` > `healthy`.
- Dashboard Operational warnings counts warning, critical, stopped and offline sensors once each.
- Dashboard health banner becomes Critical when any sensor is operationally critical or offline.
- Dashboard health banner becomes Warning when any sensor is warning or stopped.
- Network Health security posture now distinguishes critical sensors from warning sensors; any critical sensor caps the security health at critical range.
- Immediate Attention includes critical sensors, not just offline sensors.
- Immediate-action list surfaces critical sensors and their health reasons.
- Sensors table health badge uses the same effective state and exposes `health_reasons` as a tooltip.
- Cache-busted `app-detection.js` and `app-nba.js`.

## Important interpretation

`Running sensors` remains a capture/runtime-state metric. A sensor can correctly be counted as Running while simultaneously being operationally Critical. The Dashboard health banner, Network Health and Operational warnings now reflect that operational health independently.

Current Central thresholds in `healthFromSample` are:

- Critical: packet drops >= 5%, memory >= 95%, event queue >= 95%, or >= 3 consecutive Central sync failures.
- Warning: packet drops >= 1%, memory >= 80%, event queue >= 75%, or any Central sync failure.

Therefore memory usage around 91.9% alone is Warning, not Critical. If the Sensors tab shows Critical at that memory level, another critical reason is active (for example repeated sync failures); the updated badge tooltip and Sensor metrics detail expose the reason.

## Deployment

Central / Web UI only. No sensor rebuild, database migration, or reset is required.
