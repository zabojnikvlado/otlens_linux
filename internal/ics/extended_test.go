package ics

import (
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"testing"
	"time"
)

func packet(proto string, src, dst uint16, payload []byte) core.Packet {
	return core.Packet{Timestamp: time.Now(), L4Protocol: proto, SrcPort: src, DstPort: dst, AppPayload: payload}
}

func TestExtendedProtocolParsers(t *testing.T) {
	cases := []struct {
		name   string
		parse  func(core.Packet) (Message, bool)
		packet core.Packet
	}{
		{"EtherNetIP", parseEtherNetIP, packet("TCP", 1234, PortEtherNetIP, append([]byte{0x65, 0, 0, 0, 1, 0, 0, 0}, make([]byte, 16)...))},
		{"DNP3", parseDNP3, packet("TCP", 1234, PortDNP3, []byte{5, 100, 5, 0, 1, 0, 2, 0, 0, 0, 0, 0, 4})},
		{"OPCUA", parseOPCUA, packet("TCP", 1234, PortOPCUA, []byte{'H', 'E', 'L', 'F', 8, 0, 0, 0})},
		{"BACnet", parseBACnet, packet("UDP", 1234, PortBACnet, []byte{0x81, 0x0b, 0, 8, 1, 0, 0x10, 12})},
		{"IEC104", parseIEC104, packet("TCP", 1234, PortIEC104, []byte{0x68, 5, 0, 0, 0, 0, 45})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, ok := tc.parse(tc.packet)
			if !ok {
				t.Fatalf("parser rejected valid fixture")
			}
			if msg.Protocol == "" || msg.FunctionName == "" {
				t.Fatalf("incomplete message: %#v", msg)
			}
		})
	}
}
