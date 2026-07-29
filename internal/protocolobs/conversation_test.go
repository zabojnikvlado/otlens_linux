package protocolobs

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

func ntpPacket(srcIP string, srcPort uint16, dstIP string, dstPort uint16, timestamp time.Time) core.Packet {
	payload := make([]byte, 48)
	payload[0] = 0x23
	return core.Packet{
		Timestamp: timestamp, L4Protocol: "UDP",
		SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort,
		Length: 76, AppPayload: payload,
	}
}

func TestUDPParserWorksWithoutConversationContext(t *testing.T) {
	observations := parseUDP(ntpPacket("192.0.2.10", 40000, "192.0.2.20", 123, time.Now()))
	if len(observations) != 1 || observations[0].Protocol != "ntp" {
		t.Fatalf("UDP parser regression: %#v", observations)
	}
	if observations[0].ConversationID != "" || observations[0].Direction != "" || observations[0].RTTMillis != 0 {
		t.Fatalf("unexpected context on context-free parse: %#v", observations[0])
	}
}

func TestUDPRequestAndResponseShareConversationID(t *testing.T) {
	bus := core.NewEventBus()
	conversations := udpconversation.New(bus, udpconversation.ManagerConfig{
		MaxActive:                 10,
		MaxPacketsPerConversation: 10,
		IdleTimeout:               time.Minute,
	})
	protocols := New(bus)
	conversations.Start()
	defer conversations.Stop()
	protocols.Start()
	output := bus.Subscribe(core.EventProtocolObservation)

	now := time.Now()
	request := ntpPacket("192.0.2.10", 40000, "192.0.2.20", 123, now)
	response := ntpPacket("192.0.2.20", 123, "192.0.2.10", 40000, now.Add(25*time.Millisecond))
	bus.Publish(core.Event{Type: core.EventPacketParsed, Timestamp: now, Data: request})
	bus.Publish(core.Event{Type: core.EventPacketParsed, Timestamp: response.Timestamp, Data: response})

	first := waitForObservation(t, output)
	second := waitForObservation(t, output)
	if first.ConversationID == "" || first.ConversationID != second.ConversationID {
		t.Fatalf("conversation IDs differ: %q and %q", first.ConversationID, second.ConversationID)
	}
	if first.Direction == second.Direction {
		t.Fatalf("request and response directions are equal: %q", first.Direction)
	}
	if second.RTTMillis != 25 {
		t.Fatalf("response RTTMillis = %v, want 25", second.RTTMillis)
	}
}

func TestTCPProtocolPipelineRemainsUnchanged(t *testing.T) {
	bus := core.NewEventBus()
	engine := New(bus)
	engine.Start()
	output := bus.Subscribe(core.EventProtocolObservation)
	now := time.Now()
	bus.Publish(core.Event{
		Type:      core.EventTCPStreamData,
		Timestamp: now,
		Data: core.TCPStreamChunk{
			Timestamp: now,
			SrcIP:     "198.51.100.1",
			DstIP:     "198.51.100.2",
			SrcPort:   50000,
			DstPort:   80,
			Data:      []byte("GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		},
	})

	observation := waitForObservation(t, output)
	if observation.Protocol != "http" || observation.Transport != "tcp" {
		t.Fatalf("unexpected TCP observation: %#v", observation)
	}
	if observation.ConversationID != "" || observation.Direction != "" || observation.RTTMillis != 0 {
		t.Fatalf("TCP observation unexpectedly changed: %#v", observation)
	}
}

func waitForObservation(t *testing.T, output <-chan core.Event) Observation {
	t.Helper()
	select {
	case event := <-output:
		observation, ok := event.Data.(Observation)
		if !ok {
			t.Fatalf("unexpected event data: %T", event.Data)
		}
		return observation
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for protocol observation")
		return Observation{}
	}
}
