// Package topology combines asset/flow/tag data from three
// independent engines into a single node+edge graph (Graph, model.go)
// for network visualization, and provides the OT/IT classification
// (Classify) that both the graph and the plain /assets endpoint use
// to mark a device as OT. Computed fresh on every call from each
// engine's current snapshot — see Build's doc comment for why this
// isn't its own stateful engine.
package topology

import (
	"sort"
	"strings"

	"github.com/zabojnikvlado/otlens_linux/internal/asset"
	"github.com/zabojnikvlado/otlens_linux/internal/flow"
	"github.com/zabojnikvlado/otlens_linux/internal/oui"
	"github.com/zabojnikvlado/otlens_linux/internal/store"
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

	edges := buildEdges(flows, modbusPort, s7Port)

	return Graph{
		Nodes: nodes,
		Edges: edges,

		HoneypotThreshold: honeypotThreshold,
	}
}

// buildEdges folds every flow.Flow between a given pair of hosts
// into a single Edge — see Edge's doc comment for why per-flow edges
// don't scale to a real network's Topology view. Grouping is by
// unordered IP pair only (not by port/protocol), so an OT
// conversation and unrelated IT traffic between the same two hosts
// share one edge; IsOT/FromHoneypot are true for that edge as soon
// as any one of its constituent flows qualifies, since that's the
// signal the visualization needs to highlight, not an exhaustive
// per-flow breakdown (which remains available via /tags and the
// underlying flow data if ever needed).
func buildEdges(flows []*flow.Flow, modbusPort, s7Port uint16) []Edge {

	type accum struct {
		edge      Edge
		protocols map[string]bool
	}

	byPair := make(map[string]*accum)
	order := make([]string, 0)

	for _, f := range flows {

		srcIP, dstIP := f.SrcIP, f.DstIP
		if srcIP > dstIP {
			srcIP, dstIP = dstIP, srcIP
		}
		key := srcIP + "|" + dstIP

		a, ok := byPair[key]
		if !ok {
			a = &accum{
				edge: Edge{
					ID:    key,
					SrcIP: srcIP,
					DstIP: dstIP,

					VLANID: f.VLANID,

					FirstSeen: f.FirstSeen,
					LastSeen:  f.LastSeen,
				},
				protocols: make(map[string]bool),
			}
			byPair[key] = a
			order = append(order, key)
		}

		a.protocols[f.Protocol] = true
		a.edge.FlowCount++

		if isICSPort(f.SrcPort, modbusPort, s7Port) || isICSPort(f.DstPort, modbusPort, s7Port) {
			a.edge.IsOT = true
		}

		// f.HoneypotInitiated, not scoreByIP[f.SrcIP] — a flow folds
		// both directions of a conversation together, so f.SrcIP only
		// reflects whichever packet happened to create the record
		// first, not "did the honeypot ever send anything on this
		// pair." See flow.Flow.HoneypotInitiated's doc comment. Once
		// true for any flow in the pair, stays true for the edge.
		if f.HoneypotInitiated {
			a.edge.FromHoneypot = true
		}

		a.edge.Packets += f.Packets
		a.edge.Bytes += f.Bytes

		if f.FirstSeen.Before(a.edge.FirstSeen) {
			a.edge.FirstSeen = f.FirstSeen
		}
		if f.LastSeen.After(a.edge.LastSeen) {
			a.edge.LastSeen = f.LastSeen
		}
	}

	edges := make([]Edge, 0, len(order))
	for _, key := range order {

		a := byPair[key]

		protocols := make([]string, 0, len(a.protocols))
		for p := range a.protocols {
			protocols = append(protocols, p)
		}
		sort.Strings(protocols)
		a.edge.Protocol = strings.Join(protocols, ", ")

		edges = append(edges, a.edge)
	}

	return edges
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
