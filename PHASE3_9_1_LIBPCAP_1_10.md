# Phase 3.9.1 — libpcap 1.10 requirement and sensor diagnostics

OTLens Linux sensors using live packet capture now require **libpcap 1.10.0 or newer**.
The sensor reads the runtime library version directly through `pcap_lib_version()` before the capture engine is initialized.

## Startup behaviour

For `capture.mode: pcap` the sensor:

1. reads the linked runtime libpcap version;
2. writes the complete version string to the structured log;
3. rejects versions older than 1.10.0 with a clear fatal error;
4. continues normally with any compatible 1.10.x or newer release.

IPFIX-only sensors do not require libpcap at runtime and report `not used`.

Example startup log:

```text
Packet capture backend backend=libpcap version="libpcap version 1.10.4" minimum_supported=1.10.0
```

## Central diagnostics

The heartbeat now reports:

- OTLens version;
- Go runtime version;
- libpcap runtime version;
- gopacket version;
- capture backend;
- interface;
- snap length;
- promiscuous mode.

The Sensors table in Windows Central displays these fields. PostgreSQL is migrated automatically using `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` statements.

## Linux packages

Install the runtime and development packages before building or running a PCAP sensor. Distribution package names vary. Typical Debian/Ubuntu installation:

```bash
sudo apt update
sudo apt install libpcap0.8 libpcap-dev
```

Verify that the installed package provides libpcap 1.10.0 or newer. OTLens performs the authoritative runtime check at startup.

## Compatibility

This change does not alter offline PCAP/PCAPNG parsing through `pcapgo`, OT protocol decoding, telemetry, or IPFIX collection. It only establishes a supported minimum version for live capture through libpcap.
