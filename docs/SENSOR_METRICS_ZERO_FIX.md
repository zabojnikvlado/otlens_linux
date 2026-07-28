# Sensor metrics zero-value fix

The sensor popup previously calculated capture rate from TCP reassembly counters. This made packet and throughput rates zero for non-TCP traffic and did not represent the capture engine.

The sensor now counts live `packet.captured` events and bytes directly. PCAP analysis events are excluded. Heartbeats also include sensor uptime, Go/OTLens versions, and capture configuration.

Both binaries must be updated: Central stores/displays metrics, while the sensor produces them. Rebuilding only `otlens-central` leaves an older sensor sending an empty metrics object.
