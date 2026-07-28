package tcpreassembly

import (
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"testing"
	"time"
)

func pkt(seq uint32, payload string) core.Packet {
	return core.Packet{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 445, L4Protocol: "TCP", TCPSeq: seq, AppPayload: []byte(payload), Timestamp: time.Now()}
}
func TestOutOfOrderAndRetransmission(t *testing.T) {
	b := core.NewEventBus()
	e := New(b, Config{Enabled: true})
	ch := b.Subscribe(core.EventTCPStreamData)
	e.Push(pkt(100, "abc"))
	e.Push(pkt(106, "ghi"))
	e.Push(pkt(103, "def"))
	e.Push(pkt(100, "abc"))
	got := ""
	for i := 0; i < 3; i++ {
		select {
		case ev := <-ch:
			got += string(ev.Data.(core.TCPStreamChunk).Data)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
	if got != "abcdefghi" {
		t.Fatalf("got %q", got)
	}
}
func TestSplitData(t *testing.T) {
	b := core.NewEventBus()
	e := New(b, Config{Enabled: true})
	ch := b.Subscribe(core.EventTCPStreamData)
	e.Push(pkt(1, "hello "))
	e.Push(pkt(7, "world"))
	got := ""
	for i := 0; i < 2; i++ {
		got += string((<-ch).Data.(core.TCPStreamChunk).Data)
	}
	if got != "hello world" {
		t.Fatal(got)
	}
}

func TestGapRecoveryEmitsLaterData(t *testing.T) {
	bus := core.NewEventBus()
	e := New(bus, Config{Enabled: true, GapRecoveryTimeout: time.Millisecond, ShardCount: 2})
	ch := bus.Subscribe(core.EventTCPStreamData)
	now := time.Now()
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1111, DstPort: 445, TCPSeq: 100, AppPayload: []byte("abc"), Timestamp: now})
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1111, DstPort: 445, TCPSeq: 106, AppPayload: []byte("ghi"), Timestamp: now})
	<-ch
	e.cleanup(now.Add(time.Second))
	got := (<-ch).Data.(core.TCPStreamChunk)
	if string(got.Data) != "ghi" || got.GapBefore != 3 || !got.Gapped {
		t.Fatalf("unexpected gap recovery: %+v", got)
	}
}

func TestOverlapPolicyLastSeen(t *testing.T) {
	bus := core.NewEventBus()
	e := New(bus, Config{Enabled: true, OverlapPolicy: "last_seen", ShardCount: 1})
	now := time.Now()
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2, TCPSeq: 100, AppPayload: []byte("a"), Timestamp: now})
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2, TCPSeq: 104, AppPayload: []byte("old"), Timestamp: now})
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2, TCPSeq: 104, AppPayload: []byte("new"), Timestamp: now})
	if e.Stats().OverlapConflicts == 0 {
		t.Fatal("expected overlap conflict metric")
	}
}

func TestACKOnlyPacketCreatesTrackedConnection(t *testing.T) {
	bus := core.NewEventBus()
	e := New(bus, Config{Enabled: true, ShardCount: 1})
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 22, TCPSeq: 100, TCPFlags: "ACK", Timestamp: time.Now()})
	stats := e.Stats()
	if stats.SegmentsSeen != 1 || stats.ActiveConnections != 1 || stats.ConnectionsOpened != 1 {
		t.Fatalf("ACK-only TCP packet was not tracked: %+v", stats)
	}
}

func TestClosedConnectionCounters(t *testing.T) {
	bus := core.NewEventBus()
	e := New(bus, Config{Enabled: true, ShardCount: 1, ClosedTimeout: time.Millisecond})
	now := time.Now()
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 22, TCPSeq: 100, TCPFlags: "FIN,ACK", Timestamp: now})
	e.cleanup(now.Add(time.Second))
	stats := e.Stats()
	if stats.ActiveConnections != 0 || stats.ConnectionsOpened != 1 || stats.ConnectionsClosed != 1 {
		t.Fatalf("unexpected connection counters: %+v", stats)
	}
}

func TestPerIPConnectionLimit(t *testing.T) {
	bus := core.NewEventBus()
	e := New(bus, Config{Enabled: true, ShardCount: 1, MaxConnectionsPerIP: 1})
	now := time.Now()
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 22, TCPSeq: 1, TCPFlags: "SYN", Timestamp: now})
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.3", SrcPort: 1001, DstPort: 22, TCPSeq: 1, TCPFlags: "SYN", Timestamp: now})
	stats := e.Stats()
	if stats.ActiveConnections != 1 || stats.MaxConnectionsPerIPDrops != 1 {
		t.Fatalf("per-IP limit not enforced: %+v", stats)
	}
}

func TestSynTimeoutAndPeakMetrics(t *testing.T) {
	bus := core.NewEventBus()
	e := New(bus, Config{Enabled: true, ShardCount: 1, SynTimeout: time.Millisecond})
	now := time.Now()
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 22, TCPSeq: 1, TCPFlags: "SYN", Timestamp: now})
	e.cleanup(now.Add(time.Second))
	stats := e.Stats()
	if stats.ActiveConnections != 0 || stats.TimedOutConnections != 1 || stats.PeakActiveConnections != 1 {
		t.Fatalf("unexpected timeout/peak metrics: %+v", stats)
	}
}

func TestResetAndDuplicateMetrics(t *testing.T) {
	bus := core.NewEventBus()
	e := New(bus, Config{Enabled: true, ShardCount: 1, ClosedTimeout: time.Millisecond})
	now := time.Now()
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 22, TCPSeq: 100, TCPFlags: "ACK", AppPayload: []byte("abc"), Timestamp: now})
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 22, TCPSeq: 100, TCPFlags: "ACK", AppPayload: []byte("abc"), Timestamp: now})
	e.Push(core.Packet{L4Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 22, TCPSeq: 103, TCPFlags: "RST,ACK", Timestamp: now})
	e.cleanup(now.Add(time.Second))
	stats := e.Stats()
	if stats.DuplicateSegments != 1 || stats.ResetConnections != 1 || stats.ConnectionsClosed != 1 {
		t.Fatalf("unexpected reset/duplicate metrics: %+v", stats)
	}
}
