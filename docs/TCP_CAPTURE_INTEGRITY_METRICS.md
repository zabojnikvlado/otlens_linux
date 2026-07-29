# TCP capture integrity metrics

The Sensor Metrics dialog now presents TCP reassembly integrity counters as rates instead of cumulative totals.

## Chart

- **Gap recoveries/min**: new missing TCP sequence ranges recovered per minute.
- **Overlap conflicts/min**: new overlapping TCP segments whose payload conflicts with already buffered data per minute.

Counter resets, such as after a sensor restart, are treated as zero delta and do not create negative spikes.

## Capture quality badge

The badge compares new gap and overlap integrity events with observed TCP packets in the selected time range:

- Excellent: below 0.01%
- Good: below 0.1%
- Degraded: below 1%
- Poor: 1% or higher

The summary below the chart shows range totals and the calculated ratio. These thresholds are operational guidance rather than a security verdict.
