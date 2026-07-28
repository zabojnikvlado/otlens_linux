# TCP streamer and parser hardening v2

## Scope

This release extends the TCP stream engine and OT parser layer with safer mid-stream handling, asymmetric-capture visibility, confidence-based protocol classification, parser isolation, parser diagnostics, stricter framing validation, and fuzz-test entry points.

## Mid-stream synchronization

A sensor often starts after a TCP session already exists, or sees traffic after packet loss. A connection whose first observed packet is not a SYN is now explicitly classified as `midstream`.

For each direction, the first observed application sequence becomes the synchronization anchor. The engine does not invent bytes before that anchor. Later lower sequence numbers are treated as retransmission/overlap according to the configured overlap policy; later higher sequence numbers enter the bounded out-of-order queue.

`TCPStreamChunk.Midstream` is now accurate: a normal connection first observed with SYN is no longer incorrectly marked as mid-stream.

New metric:

- `midstream_connections`: total connections first observed without SYN.

## Asymmetric capture

The engine records whether packets have been observed in both canonical directions. A stream that remains one-directional for at least five seconds emits:

- lifecycle event: `stream_asymmetric`
- reason: `one_direction_only`

Chunks also carry `Asymmetric=true` while both directions have not yet been observed.

New metric:

- `asymmetric_connections`: streams reported as one-direction-only.

This is diagnostic rather than an error. SPAN configuration, routing asymmetry, host firewalls, packet loss, and unidirectional telemetry can all produce this condition.

## Confidence-based stream classification

`internal/streamproto` now exposes:

```go
type Result struct {
    Protocol   string
    Confidence uint8
    Reason     string
}

func DetectResult(data []byte) Result
```

The original `Detect([]byte) string` API remains available for compatibility.

Classifiers validate protocol framing instead of relying only on a short magic value. Implemented signatures include SMB2/3, TLS, HTTP, Modbus/TCP, DCE/RPC, DNP3, and IEC-104.

Each emitted `TCPStreamChunk` includes:

- `Protocol`
- `ProtocolConfidence` from 0 to 100
- `Asymmetric`

A direction retains the strongest classification observed so far. Low-confidence classified chunks are counted in `low_confidence_chunks`.

## Parser isolation

The ICS engine executes each parser behind a panic boundary. A malformed packet that triggers a parser panic is isolated to that parser invocation and does not terminate the packet-processing goroutine.

A panic produces an error log containing the parser name. Raw payload contents are not logged.

## Parser diagnostics

The ICS engine tracks, per parser:

- candidate packets
- successfully parsed packets
- rejected candidate packets
- recovered panics
- total parsing time
- average parsing time in microseconds

`Engine.Stats()` returns a snapshot. The engine publishes the snapshot every 30 seconds as `parser.diagnostics`.

A candidate is a packet matching the parser transport and configured port. A rejected candidate is therefore useful for identifying malformed traffic, non-standard protocol use on a well-known port, truncation, or parser coverage gaps.

## Framing hardening

### Modbus/TCP

The parser now validates the MBAP length field:

- minimum is Unit ID plus function code
- maximum is 254 bytes
- declared ADU length must fit in the captured application payload

The normalized details now include:

- `transaction_id`
- `declared_length`

This reduces false positives and prevents truncated frames from being interpreted as complete Modbus messages.

### DNP3

The parser now validates the minimum link-layer length and records:

- link length
- link control byte
- direction-from-master bit
- primary-message bit
- source and destination link addresses
- application function and security relevance

### IEC 60870-5-104

For I-format ASDUs with sufficient data, the parser now records:

- type ID
- variable structure qualifier
- cause of transmission
- test flag
- negative-confirmation flag
- originator address
- common address

The existing security-relevant command marking remains in place.

## Metrics schema

Sensor metric schema version is now `6`.

New TCP reassembly fields:

```text
midstream_connections
asymmetric_connections
low_confidence_chunks
```

They are shown in the Central Sensor metrics KPI panel and are also available in the raw metric detail.

## Fuzzing

Fuzz entry points were added for:

- stream protocol classification
- Modbus/TCP
- DNP3
- IEC-104

Example:

```bash
go test -fuzz=FuzzDetectResultNeverPanics ./internal/streamproto
go test -fuzz=FuzzModbusParserNeverPanics ./internal/ics
```

Run fuzzing in a controlled CI worker with an explicit time budget, for example `-fuzztime=60s`.

## Operational interpretation

A high `midstream_connections` count usually means the sensor was restarted, capture started late, or the observation point sees only part of the session lifecycle.

A high `asymmetric_connections` count usually indicates SPAN/TAP visibility issues or asymmetric routing. It may also be expected on deliberately unidirectional links.

A rising `low_confidence_chunks` value means the classifier has partial evidence but not enough complete framing. Compare it with gap recoveries, dropped segments, and asymmetric streams before treating it as a parser defect.

Parser `rejected` counters rising on a single protocol can indicate malformed traffic, encrypted or vendor-specific framing, non-standard ports incorrectly mapped to that parser, or capture truncation.
