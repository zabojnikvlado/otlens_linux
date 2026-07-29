package protocolobs

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

func correlationContext(id string, direction udpconversation.Direction) udpconversation.ParseContext {
	return udpconversation.ParseContext{ConversationID: id, Direction: direction}
}

func TestDHCPSequenceAndMetadata(t *testing.T) {
	c := NewCorrelator(time.Second)
	now := time.Unix(100_000, 0)
	client := correlationContext("dhcp-conversation", udpconversation.DirectionAToB)
	server := correlationContext("dhcp-conversation", udpconversation.DirectionBToA)
	var result []any
	for index, kind := range []byte{1, 2, 3, 5} {
		context := client
		if kind == 2 || kind == 5 {
			context = server
		}
		result = c.Observe(core.Packet{
			Timestamp:  now.Add(time.Duration(index) * time.Millisecond),
			SrcPort:    map[bool]uint16{true: 67, false: 68}[context.Direction == udpconversation.DirectionBToA],
			DstPort:    map[bool]uint16{true: 68, false: 67}[context.Direction == udpconversation.DirectionBToA],
			AppPayload: dhcpPacket(42, kind),
		}, context)
	}
	if len(result) != 1 {
		t.Fatalf("missing DHCP exchange: %#v", result)
	}
	exchange := result[0].(DHCPExchange)
	if exchange.AssignedIP != "192.0.2.20" || exchange.LeaseTime != time.Hour ||
		exchange.Gateway != "192.0.2.1" || len(exchange.DNSServers) != 2 ||
		exchange.Hostname != "plc-one" || exchange.VendorClass != "vendor-x" ||
		exchange.Incomplete || exchange.Invalid {
		t.Fatalf("unexpected DHCP exchange: %#v", exchange)
	}
}

func TestDHCPIncompleteWrongParallelDuplicateAndMalformed(t *testing.T) {
	c := NewCorrelator(100 * time.Millisecond)
	now := time.Unix(110_000, 0)
	client := correlationContext("dhcp", udpconversation.DirectionAToB)
	server := correlationContext("dhcp", udpconversation.DirectionBToA)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 68, DstPort: 67, AppPayload: dhcpPacket(1, 1)}, client)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 68, DstPort: 67, AppPayload: dhcpPacket(2, 1)}, client)
	if got := c.Observe(core.Packet{Timestamp: now.Add(time.Millisecond), SrcPort: 67, DstPort: 68, AppPayload: dhcpPacket(99, 5)}, server); len(got) != 1 || !got[0].(DHCPExchange).Invalid {
		t.Fatalf("wrong ID ACK should be invalid: %#v", got)
	}
	if got := c.Observe(core.Packet{Timestamp: now, SrcPort: 68, DstPort: 67, AppPayload: []byte{1, 2}}, client); got != nil {
		t.Fatalf("malformed DHCP produced exchange: %#v", got)
	}
	expired := c.Expire(now.Add(time.Second))
	if len(expired) != 2 {
		t.Fatalf("parallel incomplete DHCP sessions = %d", len(expired))
	}
	if got := c.Observe(core.Packet{Timestamp: now.Add(2 * time.Second), SrcPort: 67, DstPort: 68, AppPayload: dhcpPacket(99, 5)}, server); len(got) != 1 || !got[0].(DHCPExchange).Invalid {
		t.Fatalf("duplicate ACK not identified: %#v", got)
	}
}

func dhcpPacket(xid uint32, messageType byte) []byte {
	data := make([]byte, 240)
	data[0], data[1], data[2] = 1, 1, 6
	binary.BigEndian.PutUint32(data[4:8], xid)
	copy(data[16:20], []byte{192, 0, 2, 20})
	copy(data[28:34], []byte{0, 1, 2, 3, 4, 5})
	binary.BigEndian.PutUint32(data[236:240], 0x63825363)
	data = append(data, 53, 1, messageType, 51, 4, 0, 0, 0x0e, 0x10)
	data = append(data, 3, 4, 192, 0, 2, 1, 6, 8, 1, 1, 1, 1, 8, 8, 8, 8)
	data = append(data, 12, 7)
	data = append(data, "plc-one"...)
	data = append(data, 60, 8)
	data = append(data, "vendor-x"...)
	return append(data, 255)
}

func TestNTPPairingOffsetKoDAndEdgeCases(t *testing.T) {
	c := NewCorrelator(100 * time.Millisecond)
	now := time.Unix(120_000, 0)
	client := correlationContext("ntp", udpconversation.DirectionAToB)
	server := correlationContext("ntp", udpconversation.DirectionBToA)
	transmit := ntpTimestamp(now)
	c.Observe(core.Packet{Timestamp: now, SrcPort: 40000, DstPort: 123, AppPayload: ntpWirePacket(3, 0, 0, 0, transmit)}, client)
	response := ntpWirePacket(4, 2, transmit, ntpTimestamp(now.Add(2*time.Millisecond)), ntpTimestamp(now.Add(3*time.Millisecond)))
	got := c.Observe(core.Packet{Timestamp: now.Add(10 * time.Millisecond), SrcPort: 123, DstPort: 40000, AppPayload: response}, server)
	x := got[0].(NTPExchange)
	offsetError := x.ClockOffset - (-2500 * time.Microsecond)
	if offsetError < 0 {
		offsetError = -offsetError
	}
	if x.RTT != 10*time.Millisecond || x.ServerStratum != 2 || !x.OffsetValid || offsetError > time.Nanosecond {
		t.Fatalf("unexpected NTP exchange: %#v", x)
	}
	if duplicate := c.Observe(core.Packet{Timestamp: now.Add(11 * time.Millisecond), SrcPort: 123, DstPort: 40000, AppPayload: response}, server); duplicate != nil {
		t.Fatalf("duplicate response paired: %#v", duplicate)
	}
	if wrong := c.Observe(core.Packet{Timestamp: now, SrcPort: 123, DstPort: 40000, AppPayload: ntpWirePacket(4, 2, transmit+1, 0, 0)}, server); wrong != nil {
		t.Fatalf("wrong timestamp paired: %#v", wrong)
	}
	for i := 0; i < 2; i++ {
		ts := transmit + uint64(i+10)
		c.Observe(core.Packet{Timestamp: now, SrcPort: 40000, DstPort: 123, AppPayload: ntpWirePacket(3, 0, 0, 0, ts)}, client)
	}
	if malformed := c.Observe(core.Packet{SrcPort: 123, DstPort: 1, AppPayload: []byte{1}}, server); malformed != nil {
		t.Fatalf("malformed NTP paired: %#v", malformed)
	}
	if expired := c.Expire(now.Add(time.Second)); len(expired) != 2 {
		t.Fatalf("NTP timeouts = %d", len(expired))
	}

	kodTransmit := transmit + 100
	c.Observe(core.Packet{Timestamp: now.Add(2 * time.Second), SrcPort: 40000, DstPort: 123, AppPayload: ntpWirePacket(3, 0, 0, 0, kodTransmit)}, client)
	kod := ntpWirePacket(4, 0, kodTransmit, 0, 0)
	copy(kod[12:16], "RATE")
	kodResult := c.Observe(core.Packet{Timestamp: now.Add(2*time.Second + time.Millisecond), SrcPort: 123, DstPort: 40000, AppPayload: kod}, server)
	if kodResult[0].(NTPExchange).KoD != "RATE" {
		t.Fatalf("KoD not decoded: %#v", kodResult)
	}
}

func ntpWirePacket(mode, stratum byte, originate, receive, transmit uint64) []byte {
	data := make([]byte, 48)
	data[0] = 0x20 | mode
	data[1] = stratum
	binary.BigEndian.PutUint64(data[24:32], originate)
	binary.BigEndian.PutUint64(data[32:40], receive)
	binary.BigEndian.PutUint64(data[40:48], transmit)
	return data
}

func ntpTimestamp(value time.Time) uint64 {
	seconds := uint64(value.Unix() + ntpEpochOffset)
	fraction := uint64(float64(value.Nanosecond()) / 1e9 * 4294967296.0)
	return seconds<<32 | fraction
}

func TestSNMPOperationsPairingAndEdgeCases(t *testing.T) {
	for pdu, operation := range map[byte]string{0xa0: "get", 0xa1: "get_next", 0xa3: "set", 0xa5: "get_bulk"} {
		c := NewCorrelator(time.Second)
		now := time.Unix(130_000, 0)
		client := correlationContext("snmp", udpconversation.DirectionAToB)
		server := correlationContext("snmp", udpconversation.DirectionBToA)
		c.Observe(core.Packet{Timestamp: now, SrcPort: 40000, DstPort: 161, AppPayload: snmpPacket(1, pdu, 55, 0, 2)}, client)
		got := c.Observe(core.Packet{Timestamp: now.Add(12 * time.Millisecond), SrcPort: 161, DstPort: 40000, AppPayload: snmpPacket(1, 0xa2, 55, 5, 3)}, server)
		x := got[0].(SNMPExchange)
		if x.Operation != operation || x.ResponseTime != 12*time.Millisecond || x.ErrorStatus != 5 || x.Varbinds != 3 {
			t.Fatalf("%s exchange: %#v", operation, x)
		}
		if duplicate := c.Observe(core.Packet{Timestamp: now, SrcPort: 161, DstPort: 40000, AppPayload: snmpPacket(1, 0xa2, 55, 0, 1)}, server); duplicate != nil {
			t.Fatalf("duplicate SNMP response paired: %#v", duplicate)
		}
	}

	c := NewCorrelator(100 * time.Millisecond)
	now := time.Unix(140_000, 0)
	client := correlationContext("snmp", udpconversation.DirectionAToB)
	server := correlationContext("snmp", udpconversation.DirectionBToA)
	for _, id := range []int64{1, 2} {
		c.Observe(core.Packet{Timestamp: now, SrcPort: 1, DstPort: 161, AppPayload: snmpPacket(1, 0xa0, id, 0, 1)}, client)
	}
	if wrong := c.Observe(core.Packet{Timestamp: now, SrcPort: 161, DstPort: 1, AppPayload: snmpPacket(1, 0xa2, 99, 0, 1)}, server); wrong != nil {
		t.Fatalf("wrong SNMP ID paired: %#v", wrong)
	}
	if malformed := c.Observe(core.Packet{SrcPort: 161, DstPort: 1, AppPayload: []byte{0x30, 10}}, server); malformed != nil {
		t.Fatalf("malformed SNMP paired: %#v", malformed)
	}
	if expired := c.Expire(now.Add(time.Second)); len(expired) != 2 {
		t.Fatalf("parallel SNMP timeouts = %d", len(expired))
	}
}

func snmpPacket(version int, pdu byte, requestID, errorStatus int64, varbinds int) []byte {
	var list []byte
	for i := 0; i < varbinds; i++ {
		list = append(list, 0x30, 0)
	}
	pduBody := append(berInteger(requestID), berInteger(errorStatus)...)
	pduBody = append(pduBody, berInteger(0)...)
	pduBody = append(pduBody, berTLV(0x30, list)...)
	body := append(berInteger(int64(version)), berTLV(0x04, []byte("public"))...)
	body = append(body, berTLV(pdu, pduBody)...)
	return berTLV(0x30, body)
}

func berInteger(value int64) []byte {
	if value == 0 {
		return []byte{0x02, 1, 0}
	}
	var bytes [8]byte
	index := len(bytes)
	for value > 0 {
		index--
		bytes[index] = byte(value)
		value >>= 8
	}
	return berTLV(0x02, bytes[index:])
}

func berTLV(tag byte, value []byte) []byte {
	result := []byte{tag, byte(len(value))}
	return append(result, value...)
}
