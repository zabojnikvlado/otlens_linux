# TCP stream reassembly

OTLens now includes a protocol-independent TCP reassembly module in `internal/tcpreassembly`.
It consumes parsed TCP packets and publishes contiguous `core.TCPStreamChunk` events. The
module handles retransmissions, overlaps by trimming already emitted bytes, out-of-order
segments, FIN/RST lifecycle, idle cleanup, connection eviction, and configurable memory and
sequence-gap limits.

The SMB engine consumes these stream chunks and performs NetBIOS Session Service framing
before invoking the existing SMB2/SMB3 record parser. Consequently an SMB message may span
multiple TCP segments without losing its share, file, pipe, command, or byte-count metadata.
When reassembly is disabled, SMB retains the former packet-level parser as a fallback.

Configuration is under `capture.tcp_reassembly` in the sensor YAML. Reassembly is only
available in `pcap` capture mode; IPFIX contains no TCP payload. SMB3 encrypted transform
records remain opaque even after reassembly.

Stream quality fields expose whether capture began midstream or a stream became gapped.
Limits intentionally truncate a stream rather than allowing unbounded sensor memory use.

A detailed module-level reference is available in [`TCP_STREAMER_MODULE.md`](TCP_STREAMER_MODULE.md). Parser behavior and limitations are documented in [`PROTOCOL_PARSERS_REFERENCE.md`](PROTOCOL_PARSERS_REFERENCE.md).
