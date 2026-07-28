# Advanced TCP stream engine

This iteration extends the generic TCP stream layer without moving protocol logic into it.

## Implemented

- wrap-safe sequence comparisons;
- configurable `first_seen` and `last_seen` overlap policies;
- overlap conflict and retransmission accounting;
- timed gap recovery with `GapBefore` metadata;
- SMB NBSS resynchronization after capture gaps;
- sharded connection maps to reduce lock contention;
- bounded reusable segment buffers via `sync.Pool`;
- protocol classification from stream bytes, including SMB on non-standard ports;
- periodic `tcp.reassembly.stats` events and a public `Stats()` snapshot;
- SMB request/response correlation by MessageID and SessionID;
- TreeID-to-share and FileID-to-path tracking;
- SMB named-pipe WRITE handoff to a minimal DCE/RPC parser;
- PCAP replay utility at `cmd/tools/tcp-replay`;
- regression tests for gaps, overlaps, retransmissions, protocol detection and DCE/RPC metadata.

## New sensor settings

```yaml
capture:
  tcp_reassembly:
    gap_recovery_timeout: 2s
    shard_count: 32
    overlap_policy: first_seen
```

`first_seen` is the conservative default. `last_seen` is useful when validating target-specific overlap behavior and evasion test captures.

## Stream quality

Consumers now receive:

- `Gapped`;
- `GapBefore`;
- `Overlap`;
- detected `Protocol`.

SMB observations additionally expose `stream_gapped`, `stream_resynced`, request matching and FileID metadata.

## Replay

```bash
go run ./cmd/tools/tcp-replay -pcap sample.pcap
```

The utility prints packet, stream, gap, overlap, retransmission and buffer counters. It does not persist payloads.
