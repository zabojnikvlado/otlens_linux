package parser

import (
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// parseTCP extracts TCP layer fields into packet.
// It returns true if a TCP layer was present.
func parseTCP(pkt gopacket.Packet, packet *core.Packet) bool {

	layer := pkt.Layer(layers.LayerTypeTCP)

	if layer == nil {
		return false
	}

	tcp := layer.(*layers.TCP)

	packet.SrcPort = uint16(tcp.SrcPort)
	packet.DstPort = uint16(tcp.DstPort)

	packet.L4Protocol = "TCP"

	packet.TCPSeq = tcp.Seq
	packet.TCPAck = tcp.Ack
	packet.TCPWindow = tcp.Window
	packet.TCPFlags = tcpFlagsString(tcp)

	if len(tcp.Payload) > 0 {
		packet.AppPayload = tcp.Payload
	}

	return true
}

// tcpFlagsString renders the set TCP control flags as a short
// comma-separated string, e.g. "SYN" or "SYN,ACK" or "RST".
// Useful for spotting scans (bare SYN/FIN/NULL/XMAS) and other
// anomalous flag combinations.
func tcpFlagsString(tcp *layers.TCP) string {

	var set []string

	if tcp.SYN {
		set = append(set, "SYN")
	}

	if tcp.ACK {
		set = append(set, "ACK")
	}

	if tcp.FIN {
		set = append(set, "FIN")
	}

	if tcp.RST {
		set = append(set, "RST")
	}

	if tcp.PSH {
		set = append(set, "PSH")
	}

	if tcp.URG {
		set = append(set, "URG")
	}

	if tcp.ECE {
		set = append(set, "ECE")
	}

	if tcp.CWR {
		set = append(set, "CWR")
	}

	if tcp.NS {
		set = append(set, "NS")
	}

	return strings.Join(set, ",")
}
