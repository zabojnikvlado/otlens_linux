package udpconversation

import (
	"sync"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func udpPacket(src string, srcPort uint16, dst string, dstPort uint16, size int, timestamp time.Time) core.Packet {
	return core.Packet{
		SrcIP: src, SrcPort: srcPort,
		DstIP: dst, DstPort: dstPort,
		L4Protocol: "UDP", Length: size, Timestamp: timestamp,
		AppPayload: []byte("payload must not be retained"),
	}
}

func TestObserveTracksBothDirectionsAndStats(t *testing.T) {
	manager := NewManagerWithConfig(ManagerConfig{
		MaxActive:                 10,
		MaxPacketsPerConversation: 10,
		IdleTimeout:               time.Minute,
	})
	now := time.Unix(1_000, 0)

	first, ok := manager.Observe(udpPacket("10.0.0.1", 1000, "10.0.0.2", 2000, 100, now))
	if !ok || first.DirectionA != 1 || first.DirectionB != 0 {
		t.Fatalf("unexpected first observation: %#v, accepted=%v", first, ok)
	}
	second, ok := manager.Observe(udpPacket("10.0.0.2", 2000, "10.0.0.1", 1000, 60, now.Add(time.Second)))
	if !ok {
		t.Fatal("reverse packet was dropped")
	}
	if second.Packets != 2 || second.Bytes != 160 ||
		second.DirectionA != 1 || second.DirectionB != 1 ||
		second.DirectionABytes != 100 || second.DirectionBBytes != 60 {
		t.Fatalf("unexpected counters: %#v", second)
	}
	if second.LastSeenAt != now.Add(time.Second) {
		t.Fatalf("LastSeenAt = %v", second.LastSeenAt)
	}

	stats := manager.Stats()
	if stats.Active != 1 || stats.Created != 1 || stats.Updated != 1 ||
		stats.TotalPackets != 2 || stats.TotalBytes != 160 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestObserveEvictsLeastRecentlySeen(t *testing.T) {
	manager := NewManagerWithConfig(ManagerConfig{
		MaxActive:                 2,
		MaxPacketsPerConversation: 10,
	})
	now := time.Unix(2_000, 0)
	first := udpPacket("10.0.0.1", 1, "10.0.0.2", 2, 10, now)
	second := udpPacket("10.0.0.3", 3, "10.0.0.4", 4, 10, now.Add(time.Second))
	third := udpPacket("10.0.0.5", 5, "10.0.0.6", 6, 10, now.Add(3*time.Second))

	manager.Observe(first)
	manager.Observe(second)
	// Refresh the first conversation so the second becomes the LRU entry.
	first.Timestamp = now.Add(2 * time.Second)
	manager.Observe(first)
	manager.Observe(third)

	if _, exists := manager.Get(NewKey(second.SrcIP, second.SrcPort, second.DstIP, second.DstPort)); exists {
		t.Fatal("least-recently-seen conversation was not evicted")
	}
	if _, exists := manager.Get(NewKey(first.SrcIP, first.SrcPort, first.DstIP, first.DstPort)); !exists {
		t.Fatal("recently refreshed conversation was evicted")
	}
	stats := manager.Stats()
	if stats.Active != 2 || stats.Created != 3 || stats.Updated != 1 || stats.Evicted != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestPacketLimitDropsWithoutRetainingPayload(t *testing.T) {
	manager := NewManagerWithConfig(ManagerConfig{
		MaxActive:                 1,
		MaxPacketsPerConversation: 2,
	})
	now := time.Unix(3_000, 0)
	packet := udpPacket("192.0.2.1", 53, "192.0.2.2", 1234, 42, now)

	manager.Observe(packet)
	packet.Timestamp = now.Add(time.Second)
	manager.Observe(packet)
	packet.Timestamp = now.Add(2 * time.Second)
	conversation, ok := manager.Observe(packet)

	if ok {
		t.Fatal("packet over the per-conversation limit was accepted")
	}
	if conversation.Packets != 2 || conversation.Bytes != 84 {
		t.Fatalf("dropped packet changed counters: %#v", conversation)
	}
	if manager.Stats().Dropped != 1 {
		t.Fatalf("Dropped = %d", manager.Stats().Dropped)
	}
}

func TestExpireUpdatesStats(t *testing.T) {
	manager := NewManagerWithConfig(ManagerConfig{
		MaxActive:                 2,
		MaxPacketsPerConversation: 10,
		IdleTimeout:               time.Minute,
	})
	now := time.Unix(4_000, 0)
	manager.Observe(udpPacket("10.1.0.1", 1, "10.1.0.2", 2, 1, now))

	if expired := manager.ExpireIdle(now.Add(time.Minute + time.Nanosecond)); expired != 1 {
		t.Fatalf("expired = %d", expired)
	}
	stats := manager.Stats()
	if stats.Active != 0 || stats.Expired != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestSnapshotsCannotMutateManagerState(t *testing.T) {
	manager := NewManager(1)
	packet := udpPacket("203.0.113.1", 1, "203.0.113.2", 2, 5, time.Now())
	snapshot, _ := manager.Observe(packet)
	snapshot.Packets = 999

	stored, _ := manager.Get(NewKey(packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort))
	if stored.Packets != 1 {
		t.Fatalf("external snapshot mutated manager state: %#v", stored)
	}
}

func TestHighConversationCountRemainsBounded(t *testing.T) {
	manager := NewManagerWithConfig(ManagerConfig{MaxActive: 1000, MaxPacketsPerConversation: 10})
	now := time.Now()
	for index := 0; index < 10_000; index++ {
		manager.Observe(udpPacket("10.0.0.1", uint16(index), "10.0.0.2", 53, 64, now.Add(time.Duration(index))))
	}
	stats := manager.Stats()
	if stats.Active != 1000 || stats.Evicted != 9000 {
		t.Fatalf("manager not bounded: %#v", stats)
	}
}

func TestTelemetry(t *testing.T) {
	manager := NewManagerWithConfig(ManagerConfig{MaxActive: 10, MaxPacketsPerConversation: 10})
	now := time.Now()
	manager.Observe(udpPacket("10.0.0.1", 1000, "10.0.0.2", 53, 64, now))
	telemetry := manager.Telemetry(now.Add(time.Second), 2, 3, 12.5)
	if telemetry.UDPConversationsActive != 1 || telemetry.UDPPacketsTotal != 1 ||
		telemetry.UDPBytesTotal != 64 || telemetry.UDPUnmatchedResponsesTotal != 2 ||
		telemetry.UDPRequestTimeoutsTotal != 3 || telemetry.UDPAverageDuration != 1000 ||
		telemetry.UDPAverageRTT != 12.5 {
		t.Fatalf("unexpected telemetry: %#v", telemetry)
	}
}

func BenchmarkObserve(b *testing.B) {
	manager := NewManagerWithConfig(ManagerConfig{MaxActive: 100_000, MaxPacketsPerConversation: 100_000})
	now := time.Now()
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		manager.Observe(udpPacket("10.0.0.1", uint16(index%65535), "10.0.0.2", 53, 64, now))
	}
}

func BenchmarkObserveAtCapacity(b *testing.B) {
	manager := NewManagerWithConfig(ManagerConfig{MaxActive: 10_000, MaxPacketsPerConversation: 100_000})
	now := time.Now()
	for index := 0; index < 10_000; index++ {
		manager.Observe(udpPacket("10.0.0.1", uint16(index), "10.0.0.2", 53, 64, now))
	}
	b.ResetTimer()
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		manager.Observe(udpPacket("10.1.0.1", uint16(index%65535), "10.1.0.2", 53, 64, now.Add(time.Duration(index))))
	}
}

func TestConcurrentObserveStatsAndExpire(t *testing.T) {
	manager := NewManagerWithConfig(ManagerConfig{MaxActive: 500, MaxPacketsPerConversation: 1000, IdleTimeout: time.Second})
	now := time.Now()
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for index := 0; index < 1000; index++ {
				manager.Observe(udpPacket("10.0.0.1", uint16(worker*1000+index), "10.0.0.2", 53, 64, now))
				_ = manager.Stats()
				_ = manager.Conversations()
			}
		}(worker)
	}
	workers.Wait()
	if manager.Stats().Active > 500 {
		t.Fatalf("concurrent manager exceeded limit: %#v", manager.Stats())
	}
	manager.Expire(now.Add(2*time.Second), time.Second)
	if manager.Stats().Active != 0 {
		t.Fatalf("concurrent conversations did not expire: %#v", manager.Stats())
	}
}
