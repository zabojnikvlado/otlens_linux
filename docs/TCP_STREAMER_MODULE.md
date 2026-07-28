# TCP streamer module

## Purpose

The TCP streamer in `internal/tcpreassembly` reconstructs ordered, directional application data from parsed TCP packets. It is deliberately protocol-independent. Protocol parsers consume `core.TCPStreamChunk` events instead of handling TCP sequence numbers, retransmissions, gaps, and connection lifecycle themselves.

The module is intended for continuous passive IT/OT monitoring. It is resource-bounded, sharded for concurrency, does not persist raw payloads, and exposes quality metadata so downstream parsers can distinguish clean data from mid-stream or gapped capture.

## Data flow

1. The capture engine publishes a raw frame.
2. `internal/parser` decodes Ethernet/IP/TCP and publishes `core.EventPacketParsed`.
3. The TCP streamer subscribes to parsed packets and accepts TCP packets, including ACK-only packets.
4. Packets are assigned to a canonical bidirectional connection.
5. Each direction is reassembled independently.
6. Contiguous bytes are published as `core.EventTCPStreamData` with a `core.TCPStreamChunk` payload.
7. Lifecycle and quality changes are published as `core.EventTCPStreamLifecycle` with a `core.TCPStreamEvent` payload.
8. Stream-aware parsers such as SMB subscribe to reconstructed chunks.

IPFIX mode cannot reconstruct application data because IPFIX records do not carry the original TCP payload. TCP streaming is therefore useful only with packet capture or PCAP replay.

## Connection identity and direction

A connection ID is built from the sorted endpoint pair `IP:port-IP:port`. Sorting makes packets from both directions resolve to the same connection. The boolean direction returned by the canonicalization step selects either the A-to-B or B-to-A directional state.

Each direction tracks:

- next expected TCP sequence number;
- pending out-of-order segments;
- buffered byte count;
- whether capture started mid-stream;
- whether a gap has occurred;
- gap start time;
- detected application protocol;
- packet and byte counters;
- whether FIN was observed.

## Lifecycle model

The connection state progresses through the following states:

- `observed`: traffic was seen without a complete handshake;
- `syn_seen`: a SYN was observed;
- `established`: a handshake or bidirectional traffic indicates an active connection;
- `half_closed`: FIN was seen in one direction;
- `reset`: RST was seen;
- `closed`: both directions closed or cleanup removed the connection.

Lifecycle events use these event types:

| Event | Meaning |
|---|---|
| `stream_open` | A new connection tracking entry was created. |
| `stream_gap` | Missing sequence space was detected. |
| `stream_truncated` | A configured resource or sequence limit forced truncation. |
| `stream_close` | FIN-based close activity was observed. |
| `stream_reset` | RST terminated the connection. |
| `stream_timeout` | Cleanup removed an idle connection. |
| `stream_closed` | Final removal from the connection table. |

A lifecycle event includes endpoints, connection ID, state, reason, protocol, buffered bytes, and packet/byte totals for both directions.

## Sequence handling

Sequence comparisons use signed 32-bit subtraction, which remains correct across normal TCP sequence-number wraparound.

The streamer handles:

- in-order segments;
- out-of-order segments;
- complete duplicate segments;
- partial retransmissions;
- overlapping segments;
- missing sequence ranges;
- SYN and FIN sequence-number consumption;
- mid-stream capture without an observed SYN.

### In-order data

If a segment starts at the next expected sequence number, its payload is emitted immediately. Buffered segments that now become contiguous are emitted in sequence order.

### Out-of-order data

Future segments are stored in the directional pending map. They remain buffered until the missing sequence range arrives, the gap recovery timeout expires, or a resource limit is hit.

### Retransmissions and duplicates

Bytes entirely before the next expected sequence are treated as retransmitted. A segment that duplicates data already emitted or buffered increments duplicate/retransmission metrics and is not emitted twice.

### Overlap policy

`overlap_policy` controls conflicting overlapping bytes:

- `first_seen` keeps the earliest observed bytes and is the conservative default;
- `last_seen` prefers later bytes and is mainly useful for target-specific evasion validation.

Overlap presence and conflicting bytes are counted separately. Emitted chunks carry `Overlap=true` when overlap affected the reconstructed range.

### Gap recovery

When a sequence gap remains unresolved for `gap_recovery_timeout`, the engine may resume from the lowest buffered sequence number. The resulting chunk carries:

- `Gapped=true`;
- `GapBefore` set to the number of skipped sequence bytes.

Downstream parsers must not assume message boundaries remain valid after a gap. SMB explicitly discards partial framing state and searches for the next plausible NBSS/SMB signature.

## Protocol classification

`internal/streamproto` performs lightweight classification from reconstructed bytes rather than relying only on ports. Current signatures include:

- SMB2/SMB3 and SMB3 encrypted transform;
- TLS records;
- HTTP requests and responses;
- Modbus/TCP MBAP-like framing;
- connection-oriented DCE/RPC.

The detected value is attached to `TCPStreamChunk.Protocol`. Unknown data is reported as `unknown`. Classification is a hint and does not replace strict validation inside the protocol parser.

## Adaptive timeouts

The engine selects a timeout based on connection state and protocol:

| Condition | Timeout |
|---|---|
| SYN observed but connection not established | `syn_timeout`, default 30 s |
| Normal active/idle connection | `idle_timeout`, default 2 min |
| Known long-lived OT protocol or standard OT TCP port | `long_lived_idle_timeout`, default 15 min |
| FIN/RST/closed connection | `closed_timeout`, default 15 s |

Long-lived treatment currently covers Modbus/TCP, S7comm, DNP3, OPC UA and their standard ports. This prevents normal low-frequency OT sessions from being repeatedly destroyed and recreated.

## Resource protection

The streamer is designed to fail boundedly under scans, floods, asymmetric capture, or adversarial traffic.

### Limits

- maximum global connections;
- maximum connections involving one IP address;
- maximum buffered bytes per direction;
- maximum total buffered bytes;
- maximum pending out-of-order segments per direction;
- maximum allowed sequence gap;
- maximum retained pooled-buffer capacity.

When limits are reached, the engine drops a segment, truncates a direction, or evicts the oldest connection in the affected shard. It never permits unbounded growth.

### Sharding

Connections are distributed across `shard_count` maps using an FNV-style hash of the canonical connection ID. Each shard has its own mutex and buffered-byte count, reducing lock contention on busy sensors.

### Buffer pool

Segment byte slices are copied into a `sync.Pool`. Very large buffers are not returned to the pool, preventing a temporary large packet from permanently inflating pooled memory.

## Configuration

Example sensor configuration:

```yaml
capture:
  tcp_reassembly:
    enabled: true
    max_connections: 50000
    max_connections_per_ip: 4096
    max_buffer_per_direction: 4194304
    max_total_buffer: 536870912
    idle_timeout: 2m
    syn_timeout: 30s
    long_lived_idle_timeout: 15m
    closed_timeout: 15s
    max_out_of_order_segments: 256
    max_sequence_gap: 16777216
    gap_recovery_timeout: 2s
    shard_count: 32
    overlap_policy: first_seen
```

Operational guidance:

- Reduce `max_connections` and `max_total_buffer` on small edge sensors.
- Keep `first_seen` unless testing a known target TCP overlap behavior.
- Increase `long_lived_idle_timeout` for very low-frequency polling networks.
- Avoid setting `gap_recovery_timeout` too low on heavily reordered networks.
- Treat a rising `max_connections_per_ip_drops` value as either a scan/flood signal or an undersized limit.

## Stream chunk contract

`core.TCPStreamChunk` contains:

| Field | Description |
|---|---|
| `ConnectionID` | Canonical bidirectional connection key. |
| `SrcIP`, `DstIP`, `SrcPort`, `DstPort` | Direction of the emitted bytes. |
| `Timestamp` | Timestamp associated with the emitted range. |
| `Data` | Contiguous application bytes. Consumers must not retain or mutate it indefinitely. |
| `Midstream` | Capture began without seeing the start of this direction. |
| `Gapped` | At least one missing sequence range affected the direction. |
| `GapBefore` | Number of skipped sequence bytes directly before this chunk. |
| `Overlap` | Overlapping data affected this chunk. |
| `Protocol` | Lightweight stream classification hint. |

Parser authors should preserve quality fields in their own observations where relevant. A parser must tolerate arbitrary chunk boundaries and must maintain its own application framing buffer.

## Metrics

`core.TCPReassemblyStats` exposes a lock-free snapshot. Important fields:

| Metric | Interpretation |
|---|---|
| `active_connections` | Connections currently retained. |
| `connections_opened_total` | All tracking entries created since startup. |
| `connections_closed_total` | All entries removed since startup. |
| `segments_seen` / `bytes_seen` | TCP input accepted by the streamer. |
| `chunks_emitted` / `bytes_emitted` | Contiguous application output. |
| `out_of_order_segments` | Future segments buffered. |
| `retransmitted_bytes` | Bytes already observed. |
| `duplicate_segments` | Fully duplicate segments. |
| `overlap_segments` / `overlap_conflicts` | Overlap frequency and conflicting overlap content. |
| `gap_recoveries` | Timed resumptions across missing bytes. |
| `evicted_connections` | Connections removed because of capacity pressure. |
| `dropped_segments` | Segments rejected by configured limits. |
| `timed_out_connections` | Idle/SYN connections removed by cleanup. |
| `reset_connections` | Connections terminated by RST. |
| `peak_active_connections` | High-water mark for active streams. |
| `buffered_bytes_high_water` | High-water mark for pending TCP data. |
| `average_connection_duration_ms` | Mean duration of removed connections. |
| `max_connections_per_ip_drops` | New streams rejected by the per-IP limit. |

A zero value is not automatically an error. For example, overlap conflicts, gap recoveries and buffered bytes should normally be zero on a clean network. To verify that the module is receiving traffic, first inspect `running`, `segments_seen`, `bytes_seen`, and `connections_opened_total`.

## Parser integration pattern

A stream parser should:

1. subscribe to `core.EventTCPStreamData`;
2. validate `chunk.Protocol`, ports, and its own signature;
3. keep a bounded per-direction application buffer;
4. append every chunk and extract zero or more complete messages;
5. preserve incomplete trailing bytes;
6. reset or resynchronize on `GapBefore > 0`;
7. cap parser buffers independently of streamer limits;
8. publish normalized metadata, not raw bulk payloads;
9. clear state when lifecycle close/reset/timeout events are consumed, where implemented.

SMB is the reference implementation for this pattern.

## Security and privacy properties

- The streamer reconstructs payload in memory only.
- It does not persist full TCP payloads.
- Downstream parsers should emit small normalized metadata records.
- Resource limits protect the sensor from memory exhaustion.
- Overlap/gap flags expose reduced-confidence decoding instead of silently presenting uncertain data as complete.

## Troubleshooting

### Traffic rate is non-zero but active streams remain zero

Check that capture mode is packet/pcap, TCP traffic exists, reassembly is enabled, and `segments_seen` increases. UDP, ARP and ICMP traffic do not create TCP streams.

### Segments increase but chunks remain zero

The traffic may consist only of ACKs, encrypted handshakes without application payload, severe gaps, or segments rejected by limits. Inspect dropped, out-of-order, buffered and gap metrics.

### Buffered bytes continuously rise

This usually means asymmetric capture or persistent packet loss. Verify SPAN/TAP directionality and inspect `out_of_order_segments`, `gap_recoveries`, and `dropped_segments`.

### Many evictions or per-IP drops

The configured limits are being reached. Determine whether this is expected scan traffic, a denial-of-service condition, or a legitimate high-connection server before increasing limits.

### Parser output is missing after a gap

The parser may need protocol-specific resynchronization. SMB already supports NBSS resync. Other future stream parsers must define a safe framing recovery strategy.

## Tests

`internal/tcpreassembly/engine_test.go` covers core behavior including:

- in-order and out-of-order reconstruction;
- retransmissions and overlaps;
- gap recovery;
- ACK-only connection tracking;
- SYN timeout and reset lifecycle;
- duplicate segments;
- per-IP connection limits;
- metrics and resource accounting.

The PCAP replay utility can be used for regression captures:

```bash
go run ./cmd/tools/tcp-replay -pcap sample.pcap
```

It reports stream, gap, overlap, retransmission and buffer counters without persisting packet payloads.

## Hardening v2 additions

The current implementation also supports explicit mid-stream classification, asymmetric-capture events, confidence-scored protocol classification, and three related sensor metrics. See [TCP streamer and parser hardening v2](TCP_STREAMER_PARSER_HARDENING_V2.md) for the implementation contract and operational interpretation.
