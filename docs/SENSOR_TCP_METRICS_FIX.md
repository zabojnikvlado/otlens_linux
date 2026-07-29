# Sensor TCP metrics fix

The TCP reassembly metrics now track every parsed TCP segment, including ACK-only packets.

Added metrics:

- reassembly enabled/running state
- TCP packets per second and TCP share of captured packets
- active connections
- connections opened and closed totals
- segments and bytes seen
- chunks and bytes emitted
- existing buffering, overlap, gap, eviction, and drop counters

The sensor metrics payload schema version is 4. The Central sensor metrics dialog exposes these counters and includes the complete TCP reassembly snapshot in the details section.
