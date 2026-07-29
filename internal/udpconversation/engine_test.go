package udpconversation

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func TestEngineConsumesOnlyUDPPackets(t *testing.T) {
	bus := core.NewEventBus()
	engine := New(bus, ManagerConfig{MaxActive: 10, MaxPacketsPerConversation: 10})
	engine.Start()
	defer engine.Stop()

	now := time.Now()
	bus.Publish(core.Event{
		Type: core.EventPacketParsed,
		Data: udpPacket("10.0.0.1", 1, "10.0.0.2", 2, 10, now),
	})
	tcp := udpPacket("10.0.0.3", 3, "10.0.0.4", 4, 10, now)
	tcp.L4Protocol = "TCP"
	bus.Publish(core.Event{Type: core.EventPacketParsed, Data: tcp})

	deadline := time.Now().Add(time.Second)
	for engine.Stats().TotalPackets != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := engine.Stats()
	if stats.Active != 1 || stats.TotalPackets != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestDisabledEngineStillForwardsPacketWithoutTracking(t *testing.T) {
	bus := core.NewEventBus()
	engine := New(bus, ManagerConfig{Disabled: true})
	engine.Start()
	defer engine.Stop()
	output := bus.Subscribe(core.EventUDPConversationPacket)
	packet := udpPacket("10.0.0.1", 1, "10.0.0.2", 53, 10, time.Now())
	bus.Publish(core.Event{Type: core.EventPacketParsed, Data: packet})
	select {
	case event := <-output:
		contextual := event.Data.(ContextualPacket)
		if contextual.Packet.SrcIP != packet.SrcIP || contextual.Context.ConversationID != "" {
			t.Fatalf("unexpected disabled forwarding: %#v", contextual)
		}
	case <-time.After(time.Second):
		t.Fatal("disabled engine stopped the UDP parser pipeline")
	}
	if engine.Stats().Active != 0 {
		t.Fatalf("disabled engine tracked conversations: %#v", engine.Stats())
	}
}
