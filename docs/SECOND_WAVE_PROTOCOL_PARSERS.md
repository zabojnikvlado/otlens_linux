# Second-wave protocol metadata parsers

OTLens now passively recognizes and records security-relevant metadata for:

- Kerberos (UDP/TCP 88): message type and conservative realm extraction.
- DCE/RPC: connection-oriented v5 PDU type, call ID, fragment metadata and the first bind interface UUID when available.
- NFS (UDP/TCP 2049): ONC RPC call/reply metadata, NFS version and common v2/v3/v4 procedure names.
- Microsoft SQL Server TDS (TCP 1433): packet type, status flags, packet length and pre-login/login/RPC/batch classification.
- DTLS: record version, epoch, sequence and common handshake types.
- OpenVPN (UDP/TCP 1194): opcode and key ID classification. Encrypted payload is not retained.
- BitTorrent: TCP peer handshake metadata and UDP tracker connect/announce/scrape/error metadata.

## Privacy and safety

The parsers retain normalized metadata only. Raw application payloads, passwords, Kerberos tickets, SQL statements, NFS file contents and VPN data are not stored by this feature.

## Limitations

These are passive metadata parsers rather than complete protocol implementations. They intentionally tolerate partial TCP chunks but cannot always correlate requests and responses across missing packets. Encrypted application content remains unavailable. Dynamic DCE/RPC endpoints are recognized by the DCE/RPC v5 PDU signature; NFS and MSSQL are primarily selected by their standard service ports.

All observations use the existing `protocol_observations` telemetry and Central API:

```text
GET /v1/protocol-observations?sensor_id=&protocol=&ip=&limit=500
```
