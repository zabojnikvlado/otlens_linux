// Package topology combines asset/flow/tag data from three
// independent engines into a single node+edge graph (Graph, model.go)
// for network visualization, and provides the OT/IT classification
// (Classify) that both the graph and the plain /assets endpoint use
// to mark a device as OT. Computed fresh on every call from each
// engine's current snapshot — see Build's doc comment for why this
// isn't its own stateful engine.
package topology

import (
	"github.com/zabojnikvlado/otlens/internal/asset"
	"github.com/zabojnikvlado/otlens/internal/flow"
	"github.com/zabojnikvlado/otlens/internal/oui"
	"github.com/zabojnikvlado/otlens/internal/store"
)

// Build combines the independently-tracked asset/flow/tag data into
// a single node+edge graph for visualization. This is deliberately
// computed on demand from each engine's current snapshot rather than
// maintained as its own stateful engine — assets/flows/tags already
// are the source of truth and are cheap to re-aggregate on each API
// request; keeping a fourth copy of this data in sync would be
// needless complexity for what is, today, a read-only view.
//
// modbusPort/s7Port must be whatever the ics.Engine was actually
// configured with (see ics.Engine.ModbusPort/S7Port) — passed in
// rather than referencing ics.PortModbus/PortS7Comm directly, so
// that changing the configured port doesn't leave this OT
// classification silently checking the old default.
//
// honeypotThreshold is config.Deception.HoneypotThreshold, passed
// straight through to Graph.HoneypotThreshold — the frontend uses it
// to decide which nodes count as a honeypot (Node.Score >= this) for
// coloring. Edge.FromHoneypot itself comes from flow.Flow.
// HoneypotInitiated directly (computed upstream, per-packet, in
// flow.Engine — see that field's doc comment for why this can't be
// derived here from Node.Score the way it first looked like it
// could).
func Build(
	assets []*asset.Asset,
	flows []*flow.Flow,
	tags []*store.Tag,
	modbusPort uint16,
	s7Port uint16,
	honeypotThreshold int,
) Graph {

	isOT, protocols := Classify(tags)

	nodes := make([]Node, 0, len(assets))

	for _, a := range assets {

		nodes = append(
			nodes,
			Node{
				ID: a.MAC,

				IP:       a.IP,
				MAC:      a.MAC,
				Hostname: a.Hostname,
				Vendor:   oui.Lookup(a.MAC),

				IsOT:      isOT[a.IP],
				Protocols: protocols[a.IP],

				Confirmed: a.Confirmed,
				Score:     a.Score,
				VLANID:    a.VLANID,

				FirstSeen: a.FirstSeen,
				LastSeen:  a.LastSeen,

				PacketCount: a.PacketCount,
			},
		)

	}

	edges := make([]Edge, 0, len(flows))

	for _, f := range flows {

		edges = append(
			edges,
			Edge{
				ID: f.ID,

				SrcIP: f.SrcIP,
				DstIP: f.DstIP,

				Protocol: f.Protocol,

				IsOT: isICSPort(f.SrcPort, modbusPort, s7Port) || isICSPort(f.DstPort, modbusPort, s7Port),

				// f.HoneypotInitiated, not scoreByIP[f.SrcIP] — a flow
				// folds both directions of a conversation together,
				// so f.SrcIP only reflects whichever packet happened
				// to create the record first, not "did the honeypot
				// ever send anything on this pair." See
				// flow.Flow.HoneypotInitiated's doc comment.
				FromHoneypot: f.HoneypotInitiated,
				VLANID:      f.VLANID,

				Packets: f.Packets,
				Bytes:   f.Bytes,

				FirstSeen: f.FirstSeen,
				LastSeen:  f.LastSeen,
			},
		)

	}

	return Graph{
		Nodes: nodes,
		Edges: edges,

		HoneypotThreshold: honeypotThreshold,
	}
}

// Classify derives, per device IP, whether it has been observed
// speaking a recognized OT/ICS protocol and which ones. Exported
// separately from Build so other views (e.g. the /assets endpoint)
// can enrich their own response with the same classification without
// needing a full topology graph.
func Classify(tags []*store.Tag) (isOT map[string]bool, protocols map[string][]string) {

	isOT = make(map[string]bool)

	protocolSet := make(map[string]map[string]bool)

	for _, t := range tags {

		isOT[t.DeviceIP] = true

		if protocolSet[t.DeviceIP] == nil {
			protocolSet[t.DeviceIP] = make(map[string]bool)
		}

		protocolSet[t.DeviceIP][t.Protocol] = true
	}

	protocols = make(map[string][]string)

	for ip, set := range protocolSet {

		list := make([]string, 0, len(set))

		for protocol := range set {
			list = append(list, protocol)
		}

		protocols[ip] = list
	}

	return isOT, protocols
}

// isICSPort reports whether a port is a configured OT/ICS protocol
// port, used to flag an Edge as OT traffic even in cases where the
// ics parser itself didn't produce a decoded Message for it (e.g.
// non-standard payload on the standard port).
func isICSPort(port, modbusPort, s7Port uint16) bool {

	return port == modbusPort || port == s7Port
}
