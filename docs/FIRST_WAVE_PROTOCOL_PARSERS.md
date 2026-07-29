# First-wave protocol metadata parsers

OTLens now passively extracts security-relevant metadata for:

- HTTP requests and responses
- TLS records and ClientHello SNI/ALPN
- DHCP discovery/offer/request/ack metadata
- NTP version, mode and stratum
- SNMP version, community and PDU class
- FTP commands without retaining passwords
- SMTP commands and STARTTLS/authentication presence
- IMAP operations and authentication presence
- POP3 operations and authentication presence
- SSH protocol banners
- SIP requests, responses and call metadata

The parsers use UDP packet payloads and the existing generic TCP reassembly engine. Raw application payloads and password values are not retained. Observations are synchronized to Central and stored in `protocol_observations`.

API:

```text
GET /v1/protocol-observations?sensor_id=&protocol=&ip=&limit=500
```

The implementation is metadata-oriented. It does not decrypt TLS/SSH traffic, reconstruct transferred files or implement every protocol extension/version.
