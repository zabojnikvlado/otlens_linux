package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// parseEthernet extracts Ethernet layer fields into packet.
// It returns true if an Ethernet layer was present.
func parseEthernet(pkt gopacket.Packet, packet *core.Packet) bool {

	layer := pkt.Layer(layers.LayerTypeEthernet)

	if layer == nil {
		return false
	}

	eth := layer.(*layers.Ethernet)

	packet.PacketType = "Ethernet"
	packet.SrcMAC = eth.SrcMAC.String()
	packet.DstMAC = eth.DstMAC.String()

	packet.EtherType = eth.EthernetType.String()

	// Preserve Layer-2 payload for protocols such as PROFINET DCP.
	// TCP/UDP parsers overwrite AppPayload later with application data.
	if len(eth.Payload) > 0 {
		packet.AppPayload = eth.Payload
		packet.L4Protocol = "Ethernet"
	}

	if vlanLayer := pkt.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {

		vlan := vlanLayer.(*layers.Dot1Q)

		packet.VLANID = vlan.VLANIdentifier

		if len(vlan.Payload) > 0 {
			packet.AppPayload = vlan.Payload
		}
	}

	return true
}
