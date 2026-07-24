package topology

import "time"

// Node is one asset in the network graph, enriched with the OT/IT
// classification a visualization needs to color/group it correctly.
type Node struct {
	ID string // MAC address — same identity asset.Engine uses

	IP       string
	MAC      string
	Hostname string
	Vendor   string // from internal/oui, "" if unknown

	// IsOT is true if this device has been observed speaking a
	// recognized OT/ICS protocol (Modbus, S7comm) — see Classify.
	// A device that only ever appears as an IT/office endpoint
	// (browsing, DNS, etc.) will be false.
	IsOT      bool
	Protocols []string // distinct OT protocols observed for this device, if any

	// Confirmed is false only for a device discovered after baseline
	// learning completed that wasn't part of the learned set — see
	// asset.Asset's doc comment. The dashboard renders these in red
	// until confirmed via POST /assets/:mac/confirm.
	Confirmed bool

	// Score is the device's configured risk weight — see
	// asset.Asset.Score and config.Deception. Score >= the configured
	// honeypotthreshold marks a deliberate decoy/honeypot station;
	// the dashboard renders these in a distinct color from the red
	// "unconfirmed" state above, since a designated honeypot being
	// talked to/from is a different kind of finding than "wasn't in
	// the learned baseline."
	Score int

	// VLANID — see asset.Asset.VLANID. 0 means untagged. Drives the
	// Topology tab's VLAN filter (client-side — the frontend groups
	// nodes/edges by whatever distinct VLAN IDs actually show up in
	// a given response, rather than this needing a separate "list of
	// known VLANs" endpoint).
	VLANID uint16

	FirstSeen time.Time
	LastSeen  time.Time

	PacketCount uint64
}

// Edge is one asset-to-asset conversation, aggregated across every
// flow.Flow seen between that pair of hosts (see Build). A busy pair
// of endpoints can have dozens or hundreds of distinct 5-tuple flows
// (different ephemeral ports each time a connection is reopened);
// rendering one graph edge per flow rather than per host pair is
// what made the Topology view unusable on larger networks — the
// visualization's node count stays proportional to asset count, but
// its edge count was proportional to flow count, which grows far
// faster. Aggregating here keeps the graph's edge count proportional
// to the number of host pairs that actually talked, which is what a
// topology map should show in the first place.
type Edge struct {
	// ID is derived from the (sensor-local) host pair, not from any
	// single underlying Flow.ID — see Build's edgeKey.
	ID string

	SrcIP string
	DstIP string

	// Protocol lists the distinct L4 protocols observed between this
	// pair (e.g. "TCP" or "TCP, UDP"), combined from every flow
	// folded into this edge — see flow.Flow.Protocol.
	Protocol string

	// FlowCount is how many distinct flow.Flow records were folded
	// into this edge. 1 means the pair only ever talked over a
	// single 5-tuple; higher values are normal for busy IT/OT pairs
	// and are surfaced in the UI tooltip rather than as separate
	// edges.
	FlowCount int

	// IsOT marks an edge where at least one of its constituent flows
	// runs over a recognized OT/ICS port (502/Modbus, 102/S7comm) on
	// either side, regardless of whether the ics parser successfully
	// decoded an application message — useful for visually
	// highlighting OT conversations even when a device is talking
	// to/from a non-standard port variant.
	IsOT bool

	// FromHoneypot is true when at least one flow folded into this
	// edge was initiated by a configured deception station (see
	// Node.Score/config.Deception) as its source — the honeypot
	// itself initiating a conversation, not just being talked to.
	// Note SrcIP/DstIP above are a fixed (sorted) pair for this
	// aggregated edge and don't necessarily identify which side was
	// the honeypot; this flag is what matters. This is exactly what
	// internal/detect's AlertHoneypotLateralMovement fires on; the
	// dashboard renders these edges distinctly (thicker, red) so a
	// compromise pivoting out from a decoy is visually obvious in
	// the graph, not just buried in the Alerts tab.
	FromHoneypot bool

	// VLANID — see Node.VLANID/flow.Flow.VLANID.
	VLANID uint16

	Packets uint64
	Bytes   uint64

	FirstSeen time.Time
	LastSeen  time.Time
}

// Graph is the full node+edge network topology for visualization.
type Graph struct {
	Nodes []Node
	Edges []Edge

	// HoneypotThreshold — see config.Deception.HoneypotThreshold.
	// Included so the frontend can interpret Node.Score without
	// hardcoding a threshold that might not match the actual
	// configured value.
	HoneypotThreshold int
}
