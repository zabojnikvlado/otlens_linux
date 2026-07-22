// Package parser decodes a raw captured frame (core.RawFrame) into a
// structured core.Packet, one file per layer (ethernet.go, ipv4.go,
// ipv6.go, tcp.go, udp.go, arp.go) — each with its own parseX
// function following the same "does this layer exist? fill in what
// it says" pattern. Parse (parser.go) is the single dispatcher that
// runs them all in order; engine.go is just the event-bus plumbing
// around it.
package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/zabojnikvlado/otlens/internal/core"
)

// Parse decodes a raw Ethernet frame into a core.Packet, filling in
// whichever layers are present (Ethernet, IPv4/IPv6, TCP/UDP, ARP).
// PacketType reflects the L3 protocol (Ethernet/IPv4/IPv6/ARP);
// L4Protocol reflects the transport (TCP/UDP/ARP) — parsers must not
// overwrite PacketType with L4 info, or the L3 identity is lost.
func Parse(frame core.RawFrame) core.Packet {

	pkt := gopacket.NewPacket(
		frame.Data,
		layers.LayerTypeEthernet,
		gopacket.Default,
	)

	packet := core.Packet{
		Length:    len(frame.Data),
		Timestamp:    frame.Timestamp,
		FromAnalysis: frame.FromAnalysis,
	}

	parseEthernet(pkt, &packet)
	parseIPv4(pkt, &packet)
	parseIPv6(pkt, &packet)
	parseTCP(pkt, &packet)
	parseUDP(pkt, &packet)
	parseARP(pkt, &packet)

	return packet
}
