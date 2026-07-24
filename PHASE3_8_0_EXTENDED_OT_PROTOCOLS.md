# Phase 3.8.0 – Extended OT protocol decoding

OTLens now uses a parser registry and supports these passive decoders:

- Modbus/TCP (502/TCP)
- Siemens S7comm (102/TCP)
- EtherNet/IP encapsulation and selected CIP service hints (44818/TCP)
- DNP3 link/application functions (20000/TCP)
- OPC UA UA-TCP message framing (4840/TCP)
- BACnet/IP BVLC/NPDU/APDU service identification (47808/UDP)
- IEC 60870-5-104 APDU/ASDU type identification (2404/TCP)
- PROFINET DCP Layer-2 discovery/control frames (EtherType 0x8892)

## Security events

High-impact operations are normalized with `security_relevant=true` and feed the existing Critical ICS Operation rule. This includes DNP3 control/restart/configuration functions, BACnet writes/device control, IEC-104 commands/clock sync/process reset, EtherNet/IP write-like CIP service hints, OPC UA secure-channel lifecycle events, and PROFINET DCP Set.

## Configuration

```yaml
ics:
  modbusport: 502
  s7port: 102
  ethernetipport: 44818
  dnp3port: 20000
  opcuaport: 4840
  bacnetport: 47808
  iec104port: 2404
```

PROFINET DCP is detected by EtherType and has no TCP/UDP port. Parsing is passive; OTLens does not transmit discovery requests.

## Scope

This release performs safe protocol identification and high-value operation extraction. It does not yet implement TCP stream reassembly, encrypted OPC UA payload decryption, complete CIP path decoding, or full object/value decoding for every protocol variant. Truncated or malformed packets are rejected without panics.
