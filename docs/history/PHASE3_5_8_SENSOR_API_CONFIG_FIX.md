# Phase 3.5.8 — Sensor API configuration mapping fix

Fixed Central configuration decoding for the `sensor_api` section.

## Root cause

`CentralConfig.SensorAPI` did not declare `mapstructure:"sensor_api"`. Viper therefore left the field at Go zero values even when YAML contained:

```yaml
sensor_api:
  host: 0.0.0.0
  port: 9443
```

Central consequently logged `sensor API listener: :0` and bound an arbitrary ephemeral port.

## Fix

- Added explicit mapstructure tags to all top-level Central sections.
- Added defensive post-unmarshal defaults:
  - web: `0.0.0.0:8443`
  - sensor API: `0.0.0.0:9443`

Central must now log:

```text
OTLens Central sensor API listener: 0.0.0.0:9443
```
