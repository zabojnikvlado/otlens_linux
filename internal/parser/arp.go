package parser

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// parseARP extracts ARP layer fields into packet, including the
// operation type and the claimed MAC/IP mapping. This is the raw
// material for ARP spoofing detection later (same IP claimed by
// different MACs over time).
// It returns true if an ARP layer was present.
func parseARP(pkt gopacket.Packet, packet *core.Packet) bool {

	layer := pkt.Layer(layers.LayerTypeARP)

	if layer == nil {
		return false
	}

	arp := layer.(*layers.ARP)

	packet.PacketType = "ARP"
	packet.L4Protocol = "ARP"

	packet.ARPOperation = arpOperationString(arp.Operation)
	packet.ARPSrcMAC = net.HardwareAddr(arp.SourceHwAddress).String()
	packet.ARPSrcIP = net.IP(arp.SourceProtAddress).String()
	packet.ARPDstMAC = net.HardwareAddr(arp.DstHwAddress).String()
	packet.ARPDstIP = net.IP(arp.DstProtAddress).String()

	return true
}

// arpOperationString renders the numeric ARP opcode as a readable
// string, e.g. "Request" or "Reply".
func arpOperationString(op uint16) string {

	switch op {

	case layers.ARPRequest:
		return "Request"

	case layers.ARPReply:
		return "Reply"

	default:
		return fmt.Sprintf("Unknown(%d)", op)
	}
}
