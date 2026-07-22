// Package asset discovers and tracks devices seen on the network.
// It learns purely from packet metadata (Ethernet/IP addresses) with
// no active scanning — see engine.go's Update/Start.
package asset

import "time"

// Asset is one discovered network device, keyed internally by MAC
// address (see Engine.assets) since IP addresses can change (DHCP)
// but the MAC is comparatively stable for the lifetime of a NIC.
type Asset struct {
	// ID mirrors MAC; kept as a separate field so JSON consumers
	// have a conventional "ID" key without needing to know it's a
	// MAC address specifically.
	ID string

	// IP is the most recently observed address for this device —
	// updated on every sighting, not just the first, so a DHCP
	// renewal doesn't leave this stale. See engine.go's Update.
	IP string

	MAC string

	// Hostname is learned passively from mDNS/DHCP traffic (see
	// internal/hostname) when available; empty otherwise. There's no
	// DNS server to actively resolve against on most OT networks, so
	// this is the only source.
	Hostname string

	FirstSeen time.Time
	LastSeen  time.Time

	PacketCount uint64

	// Confirmed is false only for a device discovered after baseline
	// learning completed that wasn't part of the learned device set
	// — see engine.go's baseline-tracking watch. Every asset created
	// during (or before) baseline learning defaults to true, since
	// there's nothing to compare against yet. An operator confirms a
	// flagged device via POST /assets/:mac/confirm; internal/topology
	// renders unconfirmed devices in red until then.
	Confirmed bool

	// FromAnalysis is true only for a device that has been seen
	// exclusively through a manually-analyzed pcap file (see
	// capture.Engine.AnalyzeFile), never through live capture/IPFIX.
	// Exempts the record from age-based retention pruning — see
	// persist.Snapshotter's prune() — since the file's own historical
	// timestamps can legitimately predate the retention window. Any
	// live sighting of the same device clears this permanently (see
	// engine.go's Update): once confirmed live, it's ordinary data
	// again, not a protected historical snapshot.
	FromAnalysis bool

	// Score is the configured risk weight for this device's current
	// IP — see config.Deception, matched against
	// config.Deception.Stations. Defaults to 1 (normal station).
	// Score >= config.Deception.HoneypotThreshold marks a deliberate
	// decoy/honeypot — see internal/detect's honeypot.go for the
	// lateral-movement detection this enables, and topology.Node for
	// how it's rendered (a distinct color from the red "unconfirmed"
	// state above, since a honeypot being talked to/from is a
	// different kind of finding than "device wasn't in the learned
	// baseline"). Recomputed on every IP update, not just once at
	// asset creation — see engine.go's Update — since a device's IP
	// (and therefore whether it currently matches a configured
	// station) can change over its lifetime (DHCP renewal etc.).
	Score int

	// VLANID is the 802.1Q VLAN tag most recently observed for this
	// device — 0 means untagged (no VLAN tag seen, or the network
	// genuinely doesn't use VLANs). Drives the Topology tab's VLAN
	// filter — see topology.Node.VLANID.
	VLANID uint16
}
