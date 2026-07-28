# TCP stream engine hardening

This release upgrades TCP stream tracking from basic payload reassembly to a lifecycle-aware, resource-bounded engine suitable for long-running IT/OT monitoring.

## Lifecycle and events

Connections now track observed, SYN-seen, established, half-closed, reset, and closed states. Lifecycle events use explicit names: `stream_open`, `stream_gap`, `stream_truncated`, `stream_close`, `stream_reset`, `stream_timeout`, and `stream_closed`. Events include endpoints, protocol, state, packet counts, byte counts, and buffered bytes.

## Adaptive timeouts

- incomplete SYN connections use `syn_timeout` (default 30s)
- normal idle connections use `idle_timeout`
- known long-lived OT connections use `long_lived_idle_timeout` (default 15m)
- FIN/RST connections use `closed_timeout`

Long-lived recognition covers detected Modbus, S7, DNP3, and OPC UA streams and their standard TCP ports.

## Resource protection

In addition to global connection and buffer limits, the engine enforces `max_connections_per_ip` (default 4096). It retains sharded connection maps, per-direction out-of-order limits, total buffer limits, gap limits, pooled buffers, and oldest-connection eviction.

## Metrics

Sensor metric schema version 5 adds peak active streams, duplicate segments, timeouts, resets, buffer high-water mark, average connection duration, and per-IP limit drops. These values are visible in Sensor metrics and the raw metric detail.

## Detailed reference

For configuration, lifecycle, sequence handling, resource limits, metrics, parser integration and troubleshooting, see [`TCP_STREAMER_MODULE.md`](TCP_STREAMER_MODULE.md).

For the packet, ICS, SMB, DCE/RPC and stream-classification parsers, see [`PROTOCOL_PARSERS_REFERENCE.md`](PROTOCOL_PARSERS_REFERENCE.md).
