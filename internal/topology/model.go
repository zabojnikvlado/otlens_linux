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

// Edge is one asset-to-asset conversation, derived from flow.Flow.
type Edge struct {
	ID string // same as the underlying Flow's ID

	SrcIP string
	DstIP string

	Protocol string // L4 protocol, e.g. "TCP"/"UDP" — see flow.Flow.Protocol

	// IsOT marks an edge that runs over a recognized OT/ICS port
	// (502/Modbus, 102/S7comm) on either side, regardless of whether
	// the ics parser successfully decoded an application message —
	// useful for visually highlighting OT conversations even when a
	// device is talking to/from a non-standard port variant.
	IsOT bool

	// FromHoneypot is true when SrcIP is a configured deception
	// station (see Node.Score/config.Deception) — the honeypot itself
	// initiating this conversation, not just being talked to. This is
	// exactly what internal/detect's AlertHoneypotLateralMovement
	// fires on; the dashboard renders these edges distinctly (thicker,
	// red) so a compromise pivoting out from a decoy is visually
	// obvious in the graph, not just buried in the Alerts tab.
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
