# Bulk Discovery Manager

The Assets view supports read-only discovery for multiple selected assets.

## Workflow

1. Select assets using the table checkboxes.
2. Choose **Run discovery**.
3. Select Automatic, Safe TCP, or OT conservative profile.
4. Set per-sensor concurrency, probe rate, and timeout.
5. Approve and start the batch.

The UI groups targets by sensor and discovery profile. This creates one server-side reconnaissance job per sensor/profile pair rather than one job per asset. Automatic mode assigns OT conservative discovery to OT/protocol-identified assets and safe TCP discovery to other assets.

The progress view tracks queued, running, completed, partially completed, and failed jobs. Completed discovery automatically refreshes the asset inventory.

## OT safety

- Maximum UI concurrency: 10 targets per sensor.
- Maximum probe rate: 20 probes per second per sensor.
- OT conservative jobs require explicit approval.
- Discovery remains read-only.
