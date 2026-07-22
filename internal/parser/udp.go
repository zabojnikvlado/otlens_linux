package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/zabojnikvlado/otlens/internal/core"
)

// parseUDP extracts UDP layer fields into packet.
// It returns true if a UDP layer was present.
func parseUDP(pkt gopacket.Packet, packet *core.Packet) bool {

	layer := pkt.Layer(layers.LayerTypeUDP)

	if layer == nil {
		return false
	}

	udp := layer.(*layers.UDP)

	// Note: PacketType is intentionally left untouched here — it
	// represents the L3 protocol (Ethernet/IPv4/IPv6/ARP) set by the
	// earlier parsers, while L4Protocol below already identifies
	// this as UDP. Overwriting it would lose whether the packet was
	// IPv4 or IPv6.
	packet.SrcPort = uint16(udp.SrcPort)
	packet.DstPort = uint16(udp.DstPort)

	packet.L4Protocol = "UDP"
	packet.UDPLength = udp.Length

	if len(udp.Payload) > 0 {
		packet.AppPayload = udp.Payload
	}

	return true
}
