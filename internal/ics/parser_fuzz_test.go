package ics

import (
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"testing"
	"time"
)

func fuzzPacket(data []byte, port uint16) core.Packet {
	return core.Packet{Timestamp: time.Unix(0, 0), L4Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: port, AppPayload: data}
}
func FuzzModbusParserNeverPanics(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseModbus(fuzzPacket(data, PortModbus), PortModbus) })
}
func FuzzDNP3ParserNeverPanics(f *testing.F) {
	f.Add([]byte{5, 100, 5, 0, 1, 0, 2, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseDNP3(fuzzPacket(data, PortDNP3)) })
}
func FuzzIEC104ParserNeverPanics(f *testing.F) {
	f.Add([]byte{0x68, 4, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseIEC104(fuzzPacket(data, PortIEC104)) })
}
