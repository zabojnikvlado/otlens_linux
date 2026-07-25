# Phase 3.6.7 – Central sensor capture start/stop

The Central **Sensors** tab supports selecting one or more sensors and queuing **Start selected** or **Stop selected** actions.

The action controls the sensor data source (live packet capture or IPFIX collector). It does **not** terminate the OTLens process or its Central synchronization worker. This is required so that a stopped sensor can still receive a later start command.

## Commands

- `sensor.capture.start`
- `sensor.capture.stop`

Commands use the existing PostgreSQL `sensor_commands` queue and are delivered during the next Central synchronization cycle.

## Status

The sensor heartbeat reports `health.capture` as `running` or `stopped`. Central stores this value in the sensor status and displays it in the Sensors table. A sensor that stops heartbeating is still changed to `offline` by the existing offline monitor.

## API

`POST /v1/sensors/actions`

```json
{
  "action": "stop",
  "sensor_ids": ["sensor-01", "sensor-02"]
}
```

Valid actions are `start` and `stop`. The endpoint requires the Central management token.
