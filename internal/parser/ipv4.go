package parser

import (
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/zabojnikvlado/otlens/internal/core"
)

// parseIPv4 extracts IPv4 layer fields into packet.
// It returns true if an IPv4 layer was present.
func parseIPv4(pkt gopacket.Packet, packet *core.Packet) bool {

	layer := pkt.Layer(layers.LayerTypeIPv4)

	if layer == nil {
		return false
	}

	ip := layer.(*layers.IPv4)

	packet.PacketType = "IPv4"
	packet.SrcIP = ip.SrcIP.String()
	packet.DstIP = ip.DstIP.String()

	packet.TTL = ip.TTL
	packet.IPProtocol = ip.Protocol.String()
	packet.IPHeaderLength = int(ip.IHL) * 4
	packet.IPFlags = ipv4FlagsString(ip.Flags)

	return true
}

// ipv4FlagsString renders the IPv4 fragmentation flags (DF/MF) as a
// short comma-separated string, e.g. "DF" or "MF" or "" when unset.
func ipv4FlagsString(flags layers.IPv4Flag) string {

	var set []string

	if flags&layers.IPv4DontFragment != 0 {
		set = append(set, "DF")
	}

	if flags&layers.IPv4MoreFragments != 0 {
		set = append(set, "MF")
	}

	return strings.Join(set, ",")
}
