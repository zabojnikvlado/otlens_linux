package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/zabojnikvlado/otlens/internal/core"
)

// parseIPv6 extracts IPv6 layer fields into packet.
// It returns true if an IPv6 layer was present.
func parseIPv6(pkt gopacket.Packet, packet *core.Packet) bool {

	layer := pkt.Layer(layers.LayerTypeIPv6)

	if layer == nil {
		return false
	}

	ip := layer.(*layers.IPv6)

	packet.PacketType = "IPv6"
	packet.SrcIP = ip.SrcIP.String()
	packet.DstIP = ip.DstIP.String()

	packet.TTL = ip.HopLimit
	packet.IPProtocol = ip.NextHeader.String()

	return true
}
