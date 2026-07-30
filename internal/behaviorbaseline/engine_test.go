package behaviorbaseline

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/protocolobs"
)

func TestEngineLearnsDirectionalTimeBucketProfiles(t *testing.T) {
	bus := core.NewEventBus()
	engine := New(bus, Config{Enabled: true, SensorID: "sensor-a", LearningDuration: time.Minute, BucketDuration: time.Hour, MaxProfiles: 100})
	engine.Start()
	defer engine.Stop()

	at := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	bus.Publish(core.Event{Type: core.EventPacketParsed, Data: core.Packet{Timestamp: at, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 55000, DstPort: 53, L4Protocol: "UDP", Length: 100}})
	bus.Publish(core.Event{Type: core.EventPacketParsed, Data: core.Packet{Timestamp: at.Add(time.Second), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 55000, DstPort: 53, L4Protocol: "UDP", Length: 140}})
	waitProfiles(t, engine, 1)

	snapshot := engine.Snapshot(at.Add(2 * time.Second))
	profile := snapshot.Profiles[0]
	if profile.Key.ServicePort != 53 || profile.Packets != 2 || profile.Bytes != 240 {
		t.Fatalf("unexpected profile: %#v", profile)
	}
	if profile.PacketBytes.Mean != 120 || profile.InterArrival.Mean != 1000 {
		t.Fatalf("unexpected online statistics: %#v", profile)
	}
}

func TestEngineLearnsApplicationMetadataWithoutPayload(t *testing.T) {
	bus := core.NewEventBus()
	engine := New(bus, Config{Enabled: true, SensorID: "sensor-a", MaxProfiles: 100})
	engine.Start()
	defer engine.Stop()
	at := time.Now()
	bus.Publish(core.Event{Type: core.EventProtocolObservation, Data: protocolobs.Observation{Timestamp: at, Protocol: "dns", Transport: "udp", SrcIP: "a", DstIP: "b", SrcPort: 50000, DstPort: 53, Operation: "query", RTTMillis: 5}})
	waitProfiles(t, engine, 1)
	profile := engine.Snapshot(at).Profiles[0]
	if profile.Key.Scope != ScopeApplication || profile.Operations["query"] != 1 || profile.RTTMillis.Mean != 5 {
		t.Fatalf("unexpected application profile: %#v", profile)
	}
}

func TestAssetProfilesUseMACIdentityAndTrackBothDirections(t *testing.T) {
	bus := core.NewEventBus()
	engine := New(bus, Config{Enabled: true, SensorID: "sensor-a", LearningDuration: time.Hour, MaxProfiles: 100})
	engine.Start()
	defer engine.Stop()
	at := time.Now()
	bus.Publish(core.Event{Type: core.EventPacketParsed, Data: core.Packet{Timestamp: at, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcMAC: "AA:BB:CC:00:00:01", DstMAC: "AA:BB:CC:00:00:02", SrcPort: 50000, DstPort: 53, L4Protocol: "UDP", Length: 100}})
	waitAssetProfiles(t, engine, 2)
	bus.Publish(core.Event{Type: core.EventPacketParsed, Data: core.Packet{Timestamp: at.Add(time.Second), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcMAC: "AA:BB:CC:00:00:02", DstMAC: "AA:BB:CC:00:00:01", SrcPort: 53, DstPort: 50000, L4Protocol: "UDP", Length: 200}})
	bus.Publish(core.Event{Type: core.EventProtocolObservation, Data: protocolobs.Observation{Timestamp: at.Add(2 * time.Second), SensorID: "sensor-a", Protocol: "dns", Transport: "udp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 53, Operation: "query", RTTMillis: 4}})
	deadline := time.Now().Add(time.Second)
	var profile AssetBehaviorProfile
	for time.Now().Before(deadline) {
		for _, candidate := range engine.Snapshot(at).AssetProfiles {
			if candidate.Key.AssetID == "mac:aa:bb:cc:00:00:01" {
				profile = candidate
			}
		}
		if profile.Inbound.Packets == 1 && profile.Outbound.Packets == 1 && profile.Protocols["dns"].Events == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if profile.Key.AssetID != "mac:aa:bb:cc:00:00:01" || profile.Inbound.Bytes != 200 || profile.Outbound.Bytes != 100 {
		t.Fatalf("unexpected directional asset profile: %#v", profile)
	}
	if profile.Peers["mac:aa:bb:cc:00:00:02"].Inbound.Packets != 1 || profile.Peers["mac:aa:bb:cc:00:00:02"].Outbound.Packets != 1 {
		t.Fatalf("peer directions were not learned: %#v", profile.Peers)
	}
	if profile.RTTMillis.Mean != 4 || profile.Operations["query"] != 1 {
		t.Fatalf("application metadata was not joined to MAC identity: %#v", profile)
	}
	detached, ok := engine.AssetProfile(profile.Key)
	if !ok {
		t.Fatal("asset profile lookup failed")
	}
	detached.IPs["mutated"] = 1
	fresh, _ := engine.AssetProfile(profile.Key)
	if fresh.IPs["mutated"] != 0 {
		t.Fatal("asset profile lookup exposed mutable engine state")
	}
}

func TestEngineBoundedEvictionAndRestore(t *testing.T) {
	engine := New(nil, Config{Enabled: true, MaxProfiles: 64})
	at := time.Now()
	for i := 0; i < 200; i++ {
		engine.observe(sample{key: Key{SensorID: "s", Scope: ScopeNetwork, SrcIP: string(rune(i + 1)), DstIP: "b"}, at: at.Add(time.Duration(i) * time.Second), packet: true})
	}
	snapshot := engine.Snapshot(at)
	if len(snapshot.Profiles) > 64 || snapshot.Evicted == 0 {
		t.Fatalf("baseline is not bounded: profiles=%d evicted=%d", len(snapshot.Profiles), snapshot.Evicted)
	}
	restored := New(nil, Config{Enabled: true, MaxProfiles: 64})
	if err := restored.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	if restored.Status(at).Profiles != uint64(len(snapshot.Profiles)) {
		t.Fatal("profile count was not restored")
	}
}

func TestMonitoringDoesNotPoisonLearnedBaseline(t *testing.T) {
	engine := New(nil, Config{Enabled: true, LearningDuration: time.Minute, MaxProfiles: 100})
	at := time.Now()
	key := Key{SensorID: "s", Scope: ScopeNetwork, SrcIP: "a", DstIP: "b"}
	engine.observe(sample{key: key, at: at, bytes: 100, packet: true})
	engine.observe(sample{key: key, at: at.Add(2 * time.Minute), bytes: 10_000, packet: true})
	snapshot := engine.Snapshot(at.Add(2 * time.Minute))
	if snapshot.Profiles[0].Packets != 1 || snapshot.Profiles[0].Bytes != 100 {
		t.Fatalf("monitoring sample changed trusted baseline: %#v", snapshot.Profiles[0])
	}
	if snapshot.Dropped != 1 {
		t.Fatalf("dropped = %d, want 1", snapshot.Dropped)
	}
}

func waitProfiles(t *testing.T, engine *Engine, count uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if engine.Status(time.Now()).Profiles >= count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("profiles did not reach %d", count)
}

func waitAssetProfiles(t *testing.T, engine *Engine, count uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if engine.Status(time.Now()).AssetProfiles >= count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("asset profiles did not reach %d", count)
}

func BenchmarkObserveExistingProfile(b *testing.B) {
	engine := New(nil, Config{Enabled: true, LearningDuration: 24 * time.Hour, MaxProfiles: 100_000})
	at := time.Now()
	value := sample{key: Key{SensorID: "s", Scope: ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Transport: "udp", Protocol: "udp", ServicePort: 53}, srcAsset: "mac:00:00:00:00:00:01", dstAsset: "mac:00:00:00:00:00:02", at: at, bytes: 128, packet: true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		value.at = at.Add(time.Duration(i) * time.Microsecond)
		engine.observe(value)
	}
}
