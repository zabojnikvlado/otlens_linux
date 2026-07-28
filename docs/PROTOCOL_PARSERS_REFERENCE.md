# Protocol parsers reference

## Architecture

OTLens uses several parser layers:

1. **Packet parsers** in `internal/parser` decode Ethernet, ARP, IPv4, IPv6, TCP and UDP into `core.Packet`.
2. **TCP stream classification** in `internal/streamproto` identifies likely application protocols from reconstructed bytes.
3. **OT/ICS parsers** in `internal/ics` decode protocol-specific metadata into a normalized `ics.Message`.
4. **SMB parser** in `internal/smb` consumes reconstructed TCP streams and emits SMB observations.
5. **DCE/RPC parser** in `internal/dcerpc` receives SMB named-pipe payload fragments and emits minimal RPC metadata.

Parsers intentionally emit structured metadata instead of retaining complete payloads.

## Packet parser layer

### Ethernet

File: `internal/parser/ethernet.go`

Decodes source and destination MAC addresses and the Ethernet type. It establishes the L2 identity used by asset inventory and topology. Unsupported L2 payloads remain available only as generic packet metadata.

### ARP

File: `internal/parser/arp.go`

Decodes ARP operation, sender/target IP, and sender/target MAC addresses. Typical uses include asset discovery, IP-to-MAC history, duplicate IP analysis and ARP-spoofing detection.

Supported operation labels include request and reply; unknown operation values are retained as a numeric/derived label.

### IPv4

File: `internal/parser/ipv4.go`

Decodes source/destination IP, TTL, protocol, identification, fragmentation flags and application handoff metadata. Fragment reassembly is not performed by this module. A fragmented transport payload may therefore be unavailable to upper-layer parsers unless capture/library decoding already provides it.

### IPv6

File: `internal/parser/ipv6.go`

Decodes IPv6 source/destination addresses, next-header information, hop limit and payload handoff. Extension-header and IPv6 fragment behavior depends on what the packet decoding library exposes; application parsers should not assume every fragmented IPv6 flow is complete.

### TCP

File: `internal/parser/tcp.go`

Decodes ports, sequence/acknowledgment numbers, TCP flags, window and application payload. The packet is then consumed by flow analysis and, when enabled, `internal/tcpreassembly`.

TCP application parsers should prefer reconstructed stream chunks whenever they require complete messages spanning multiple segments. Packet-level payload is retained as a fallback for modules that do not yet support streams.

### UDP

File: `internal/parser/udp.go`

Decodes ports and UDP payload. Datagram boundaries are preserved, so UDP protocol parsers such as BACnet/IP can parse one datagram directly without TCP-style reassembly.

## Normalized ICS message

All OT protocol parsers emit `ics.Message`:

| Field | Meaning |
|---|---|
| `Timestamp` | Packet timestamp. |
| `FromAnalysis` | True for imported/offline analysis traffic. |
| `SrcIP`, `DstIP`, `SrcPort`, `DstPort` | Network endpoints. |
| `Protocol` | Normalized protocol name. |
| `FunctionCode`, `FunctionName` | Primary operation identifier. |
| `IsException` | Protocol exception/error response. |
| `IsResponse` | Response direction where detectable. |
| `UnitID` | Modbus unit/slave ID when applicable. |
| `Details` | Small protocol-specific scalar metadata map. Raw bulk payload is not stored. |

The ICS engine currently selects most parsers by configured standard port and transport. Consequently, protocols running on non-standard ports may not be recognized by the packet-level ICS engine even when the generic stream classifier produces a hint.

## Modbus/TCP parser

File: `internal/ics/modbus.go`  
Default port: TCP/502

### Validation and framing

The parser validates the Modbus Application Protocol header, including transaction context, protocol identifier, length and unit ID. It extracts the function code and marks exception responses when the high bit is set.

### Decoded operations

The function-name map covers common read/write and diagnostic operations, including coils, discrete inputs, holding/input registers, single/multiple writes and combined read/write functions.

Depending on the function, `Details` may include:

- transaction ID;
- protocol ID;
- address/reference;
- quantity;
- byte count;
- decoded register values;
- decoded bit values;
- exception code;
- response/request interpretation.

### Limitations

- Parsing is packet-based, so a Modbus ADU split across TCP segments may be missed by the current ICS parser.
- Multiple ADUs coalesced into one TCP payload may not all be emitted unless explicitly handled by the function.
- Protocol detection on non-standard ports is only a hint at the streamer layer and is not yet wired into the ICS parser.
- Encrypted or tunneled Modbus cannot be decoded.

## S7comm parser

File: `internal/ics/s7comm.go`  
Default port: TCP/102

### Validation and framing

The parser recognizes the TPKT/COTP/S7comm structure and decodes the S7 header. It identifies ROSCTR message classes and common function codes.

### Extracted metadata

Potential fields include:

- ROSCTR type;
- protocol data unit reference;
- parameter and data lengths;
- function name/code;
- item count;
- first item area/address/DB number;
- transport size;
- first value where safely decodable;
- error class/code for responses.

Critical write/control functions are marked through the function catalog and can feed detection logic.

### Limitations

- Packet-level parsing may miss messages split across TCP segments.
- Only selected parameter/item layouts are decoded.
- Optimized data blocks, symbolic addressing and encrypted/tunneled variants are outside the current parser.

## EtherNet/IP parser

File: `internal/ics/ethernetip.go`  
Default port: TCP/44818

### Extracted metadata

The parser decodes the encapsulation header and common commands:

- NOP;
- ListServices;
- ListIdentity;
- ListInterfaces;
- RegisterSession;
- UnregisterSession;
- SendRRData;
- SendUnitData.

Details may include command, encapsulation length, session handle, status, sender context/options and response direction.

### Limitations

- CIP service/path decoding inside SendRRData and SendUnitData is intentionally limited.
- Implicit I/O over UDP and fragmented/coalesced TCP records are not comprehensively reconstructed here.

## DNP3 parser

File: `internal/ics/dnp3.go`  
Default port: TCP/20000

### Validation and metadata

The parser recognizes the DNP3 link-layer start bytes and extracts link/application indicators where available. Function names cover reads, writes, select/operate sequences, direct operate, freeze, restart, application control and solicited/unsolicited responses.

Details may include:

- link length/control;
- source and destination DNP addresses;
- application control/function;
- response/request indication;
- selected function name.

### Limitations

- CRC validation and full multi-fragment transport/application reassembly are not comprehensive.
- Object group/variation and point-value decoding are intentionally limited.
- Secure Authentication payloads are not deeply decoded.

## OPC UA binary parser

File: `internal/ics/opcua.go`  
Default port: TCP/4840

### Recognized message types

- `HEL` — Hello;
- `ACK` — Acknowledge;
- `ERR` — Error;
- `RHE` — ReverseHello;
- `OPN` — OpenSecureChannel;
- `CLO` — CloseSecureChannel;
- `MSG` — SecureMessage.

The parser extracts the message type, chunk/finality marker, total message size and selected header metadata when available.

### Limitations

- Secure-channel payloads are normally encrypted/signed and remain opaque.
- Full service-node decoding, chunk reassembly and certificate inspection are not implemented in this packet parser.
- TCP segmentation can hide incomplete OPC UA messages.

## BACnet/IP parser

File: `internal/ics/bacnet.go`  
Default port: UDP/47808

### Recognized services

Confirmed services include ReadProperty, ReadPropertyMultiple, WriteProperty, WritePropertyMultiple, SubscribeCOV, DeviceCommunicationControl, ReinitializeDevice and ReadRange.

Unconfirmed services include I-Am, Who-Is, Who-Has, TimeSynchronization and unconfirmed COV notification.

### Extracted metadata

The parser validates BVLC/NPDU/APDU structure sufficiently to identify:

- BVLC function and length;
- APDU type;
- invoke ID where present;
- confirmed or unconfirmed service choice;
- request/response semantics;
- selected service name.

### Limitations

- BACnet/IP only; BACnet MS/TP is not parsed from Ethernet packet capture.
- Full object/property/value decoding and segmentation reassembly are not implemented.
- BBMD forwarded-NPDU cases may expose only limited metadata.

## IEC 60870-5-104 parser

File: `internal/ics/iec104.go`  
Default port: TCP/2404

### Validation and metadata

The parser recognizes the `0x68` APDU start, APDU length, I/S/U frame forms and common ASDU type identifiers.

Known type names include single/double points, measured values, commands, set-points, interrogation, clock synchronization, reset process and test commands.

Details may include:

- APDU format;
- send/receive sequence counters;
- type identification;
- variable structure qualifier;
- cause of transmission;
- common address;
- response/request classification.

### Limitations

- Full information-object decoding and multi-object traversal are limited.
- TCP segmentation/coalescing is not comprehensively handled by the packet-level parser.
- Security extensions or encrypted tunnels remain opaque.

## PROFINET DCP parser

File: `internal/ics/profinet.go`  
Transport: raw Ethernet

The parser identifies PROFINET Discovery and Configuration Protocol using its EtherType/frame structure rather than an IP port. It extracts DCP service and service type, transaction/XID and selected option/suboption metadata where present.

Typical visibility includes identify and configuration operations used to discover or rename PROFINET devices.

Limitations include partial block decoding, no cyclic PROFINET I/O decoding and no reconstruction of vendor-specific block semantics.

## SMB2/SMB3 parser

Files: `internal/smb/engine.go`, `internal/smb/model.go`  
Typical port: TCP/445, but stream signature detection also supports non-standard ports.

### Input modes

With TCP reassembly enabled, SMB subscribes to `core.EventTCPStreamData`. It keeps a bounded per-direction NBSS buffer and extracts complete Session Service records. Without reassembly, it falls back to packet-level parsing on TCP/445.

### Framing and gap recovery

SMB records use a 4-byte NBSS header. A single TCP chunk may contain part of one record or several records. The parser retains incomplete trailing bytes and emits every complete record.

After a TCP gap, the parser discards unsafe partial framing and searches for the next plausible NBSS header followed by an SMB2 (`FE SMB`) or SMB3 encrypted-transform (`FD SMB`) signature. Observations expose `stream_gapped` and `stream_resynced`.

### SMB metadata

The parser extracts:

- command and status;
- request/response direction;
- MessageID, SessionID and TreeID;
- persistent and volatile FileID;
- dialect where available;
- share name;
- file/path name;
- named pipe;
- byte count;
- encryption marker;
- admin-share, executable and script classifications.

### Correlation state

Requests are correlated with responses by client/server, SessionID and MessageID. Successful TREE_CONNECT and CREATE responses update:

- TreeID to share-name mapping;
- FileID to file-path mapping.

This allows later READ/WRITE/CLOSE activity to retain useful share and file context.

### SMB3 encryption

Records beginning with the SMB3 encrypted transform signature are marked `is_encrypted=true`. Command, share, path and named-pipe details inside encrypted content cannot be decoded.

### Limits

- Observation history is capped at 5,000 entries in memory.
- Per-direction stream framing buffer is capped at 8 MiB.
- SMB1 is not a primary target of this parser.
- Compression and all SMB3 transform internals are not deeply decoded.
- Capture gaps can cause lost request/response correlation even after framing resynchronizes.

## DCE/RPC parser

File: `internal/dcerpc/engine.go`

DCE/RPC input is handed off by SMB when a WRITE targets a recognized named pipe. The parser validates connection-oriented DCE/RPC version 5 headers and emits:

- named pipe;
- packet type;
- call ID;
- operation number for request PDUs;
- fragment length;
- first/last fragment flags;
- interface hint derived from the pipe name.

Pipe hints currently include:

| Pipe | Hint |
|---|---|
| `svcctl` | service control manager |
| `samr` | security account manager |
| `lsarpc` | local security authority |
| `winreg` | remote registry |
| `atsvc` | task scheduler |

The parser intentionally does not retain RPC payloads and does not perform full interface UUID bind tracking or NDR argument decoding. Its purpose is behavioral metadata for lateral-movement and remote-administration detections.

## Generic stream classifier

File: `internal/streamproto/detect.go`

The classifier performs lightweight signature checks for SMB, TLS, HTTP, Modbus/TCP and DCE/RPC. It is designed to:

- classify protocols on non-standard ports;
- help select adaptive stream timeouts;
- route likely stream data to a parser;
- avoid expensive deep inspection in the generic TCP layer.

A classifier result is not authoritative. Every protocol parser must still validate lengths, magic values and internal structure before emitting an observation.

## Parser quality and confidence

Parser consumers should account for these conditions:

- `FromAnalysis=true`: data came from offline analysis rather than live capture;
- `Midstream=true`: TCP capture began after the connection started;
- `Gapped=true` or `GapBefore>0`: bytes were missing;
- `Overlap=true`: overlapping TCP bytes affected reconstruction;
- encrypted protocol markers: only outer metadata is trustworthy;
- packet-level TCP parser: a message may be incomplete or contain multiple coalesced records.

Detections should avoid treating a partially decoded or gapped observation as equivalent to a fully validated transaction unless the specific rule is designed for that uncertainty.

## Adding a parser

For a UDP or self-contained packet protocol:

1. implement a parser that validates transport, port/signature and minimum lengths;
2. decode only bounded scalar metadata;
3. return `false` on malformed/incomplete input;
4. register it in the appropriate engine;
5. add malformed, truncated, request and response tests.

For a TCP stream protocol:

1. subscribe to `core.EventTCPStreamData`;
2. use a bounded buffer per connection direction;
3. handle arbitrary chunk boundaries and multiple messages per chunk;
4. define safe resynchronization after `GapBefore>0`;
5. optionally add a `streamproto` signature;
6. clear parser state on close/reset/timeout where applicable;
7. emit normalized metadata only;
8. add regression tests for segmentation, coalescing, retransmission, gaps and mid-stream capture.

## Testing checklist

Each parser should have tests for:

- minimum valid request;
- minimum valid response;
- malformed length fields;
- truncated header/body;
- unknown function/service code;
- non-standard port behavior where supported;
- multiple messages in one stream chunk;
- one message split across several chunks;
- gap/resynchronization behavior;
- encrypted/opaque variants;
- bounded memory and observation retention.

## Parser runtime diagnostics and isolation

OT parser invocations are isolated by a panic boundary and measured per parser. Candidate, parsed, rejected, panic, and parse-duration counters are published as `parser.diagnostics`. Modbus/TCP now enforces MBAP length consistency; DNP3 exposes link control metadata; IEC-104 exposes ASDU cause and addressing metadata. See [TCP streamer and parser hardening v2](TCP_STREAMER_PARSER_HARDENING_V2.md).
