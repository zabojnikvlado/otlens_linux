package dns

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

func TestEnginePairsDNSWireQueryAndResponse(t *testing.T) {
	bus := core.NewEventBus()
	conversations := udpconversation.New(bus, udpconversation.ManagerConfig{
		MaxActive:                 10,
		MaxPacketsPerConversation: 10,
		IdleTimeout:               time.Minute,
	})
	engine := New(bus, 10)
	conversations.Start()
	defer conversations.Stop()
	engine.Start()
	defer engine.Stop()
	output := bus.Subscribe(core.EventDNSExchange)

	now := time.Now()
	queryPacket := core.Packet{
		Timestamp: now, L4Protocol: "UDP",
		SrcIP: "192.0.2.10", SrcPort: 40000, DstIP: "192.0.2.53", DstPort: 53,
		AppPayload: dnsWireMessage(0x1234, false, 1),
	}
	responsePacket := core.Packet{
		Timestamp: now.Add(15 * time.Millisecond), L4Protocol: "UDP",
		SrcIP: "192.0.2.53", SrcPort: 53, DstIP: "192.0.2.10", DstPort: 40000,
		AppPayload: dnsWireMessage(0x1234, true, 1),
	}
	bus.Publish(core.Event{Type: core.EventPacketParsed, Timestamp: now, Data: queryPacket})
	bus.Publish(core.Event{Type: core.EventPacketParsed, Timestamp: responsePacket.Timestamp, Data: responsePacket})

	select {
	case event := <-output:
		exchange, ok := event.Data.(DNSExchange)
		if !ok {
			t.Fatalf("unexpected event data: %T", event.Data)
		}
		if exchange.TransactionID != 0x1234 || exchange.QueryName != "example.test" ||
			exchange.QueryType != 1 || exchange.Answers != 1 ||
			exchange.RTT != 15*time.Millisecond || exchange.ConversationID == "" {
			t.Fatalf("unexpected exchange: %#v", exchange)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DNS exchange")
	}
}

func dnsWireMessage(transactionID uint16, isResponse bool, queryType uint16) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], transactionID)
	flags := uint16(0x0100)
	if isResponse {
		flags = 0x8180
	}
	binary.BigEndian.PutUint16(message[2:4], flags)
	binary.BigEndian.PutUint16(message[4:6], 1)
	if isResponse {
		binary.BigEndian.PutUint16(message[6:8], 1)
	}
	message = append(message,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		4, 't', 'e', 's', 't',
		0,
	)
	var value [4]byte
	binary.BigEndian.PutUint16(value[0:2], queryType)
	binary.BigEndian.PutUint16(value[2:4], 1)
	message = append(message, value[:]...)
	if !isResponse {
		return message
	}
	message = append(message,
		0xc0, 0x0c,
		0x00, byte(queryType),
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		192, 0, 2, 100,
	)
	return message
}
