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

func TestCandidateBaselineRequiresEvidenceAndManualPromotion(t *testing.T) {
	engine := New(nil, Config{Enabled: true, SensorID: "s", LearningDuration: time.Second, MaxLearningMultiplier: 2, MinAssetSamples: 1, MinAssetAge: time.Millisecond, CandidateMinSamples: 2, CandidateMinDays: 1, MaxProfiles: 100})
	at := time.Now().UTC()
	trusted := sample{key: Key{SensorID: "s", Scope: ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Transport: "udp", Protocol: "udp", ServicePort: 53}, srcAsset: "mac:a", dstAsset: "mac:b", at: at, packet: true}
	engine.observe(trusted)
	candidate := sample{key: Key{SensorID: "s", Scope: ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "10.0.0.3", Transport: "tcp", Protocol: "tcp", ServicePort: 443}, srcAsset: "mac:a", dstAsset: "mac:c", at: at.Add(3 * time.Second), packet: true}
	engine.observe(candidate)
	rows := engine.Candidates(0)
	if len(rows) != 1 || rows[0].ReadyForPromotion {
		t.Fatalf("candidate should exist but need more evidence: %#v", rows)
	}
	if err := engine.PromoteCandidate(rows[0].ID); err == nil {
		t.Fatal("candidate promoted before minimum evidence")
	}
	candidate.at = candidate.at.Add(time.Second)
	engine.observe(candidate)
	rows = engine.Candidates(0)
	if len(rows) != 1 || !rows[0].ReadyForPromotion {
		t.Fatalf("candidate should be ready for review: %#v", rows)
	}
	if err := engine.PromoteCandidate(rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if len(engine.Candidates(0)) != 0 || !engine.hasTrustedKey(candidate.key) {
		t.Fatal("manual promotion did not move candidate into trusted baseline")
	}
	if err := engine.PromoteCandidate(rows[0].ID); err != nil {
		t.Fatalf("promotion command should be idempotent until Central confirms it: %v", err)
	}
	status := engine.Status(time.Now().UTC())
	if len(status.PromotedCandidates) != 1 || status.PromotedCandidates[0] != rows[0].ID {
		t.Fatalf("promotion acknowledgement missing from telemetry status: %#v", status.PromotedCandidates)
	}
	snapshot := engine.Snapshot(time.Now().UTC())
	restored := New(nil, Config{Enabled: true, SensorID: "s", LearningDuration: time.Second, MaxLearningMultiplier: 2, MinAssetSamples: 1, MinAssetAge: time.Millisecond, CandidateMinSamples: 2, CandidateMinDays: 1, MaxProfiles: 100})
	if err := restored.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := restored.PromoteCandidate(rows[0].ID); err != nil {
		t.Fatalf("persisted promotion acknowledgement was not idempotent after restore: %v", err)
	}
}

func TestSecurityExclusionQuarantinesCandidateAndTrustedPeer(t *testing.T) {
	engine := New(nil, Config{Enabled: true, SensorID: "s", LearningDuration: time.Hour, MinAssetSamples: 1, MinAssetAge: time.Millisecond, CandidateMinSamples: 1, CandidateMinDays: 1, MaxProfiles: 100})
	at := time.Now().UTC()
	value := sample{key: Key{SensorID: "s", Scope: ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Transport: "tcp", Protocol: "tcp", ServicePort: 502, Context: "production"}, srcAsset: "ip:10.0.0.1", dstAsset: "ip:10.0.0.2", at: at, packet: true}
	engine.observe(value)
	if !engine.hasTrustedKey(value.key) {
		t.Fatal("precondition: trusted flow was not learned")
	}
	engine.ApplyLearningExclusion(core.LearningExclusion{SrcIP: value.key.SrcIP, DstIP: value.key.DstIP, Protocol: value.key.Protocol, ServicePort: value.key.ServicePort, Reason: "critical ICS operation", Until: at.Add(time.Hour)})
	if engine.hasTrustedKey(value.key) {
		t.Fatal("security violating flow remained in trusted baseline")
	}
	for _, profile := range engine.Snapshot(at).AssetProfiles {
		if profile.Key.AssetID == "ip:10.0.0.1" {
			if _, ok := profile.Peers["ip:10.0.0.2"]; ok {
				t.Fatal("security violating peer relationship remained in asset baseline")
			}
		}
	}
}

func TestTimeModelUsesIntraDayBucketAcrossWeekdays(t *testing.T) {
	engine := New(nil, Config{Enabled: true, BucketDuration: time.Hour})
	monday := time.Date(2026, 8, 10, 9, 15, 0, 0, time.UTC)
	tuesday := monday.Add(24 * time.Hour)
	mondayKey := engine.keyWithService(monday, ScopeNetwork, "10.0.0.1", "10.0.0.2", "tcp", "tcp", 502)
	tuesdayKey := engine.keyWithService(tuesday, ScopeNetwork, "10.0.0.1", "10.0.0.2", "tcp", "tcp", 502)
	if mondayKey.TimeBucket != tuesdayKey.TimeBucket {
		t.Fatalf("same hour on adjacent weekdays must use the same intra-day bucket: monday=%d tuesday=%d", mondayKey.TimeBucket, tuesdayKey.TimeBucket)
	}
	if mondayKey.DayClass != "weekday" || tuesdayKey.DayClass != "weekday" || mondayKey.Shift != "day" || tuesdayKey.Shift != "day" {
		t.Fatalf("unexpected hierarchical time context: monday=%#v tuesday=%#v", mondayKey, tuesdayKey)
	}
}

func TestMaintenanceWindowIsSeparateFromProductionBaseline(t *testing.T) {
	engine := New(nil, Config{Enabled: true, BucketDuration: time.Hour, MaintenanceWindows: []string{"weekday@02:00-04:00"}})
	maintenance := engine.keyWithService(time.Date(2026, 8, 10, 3, 0, 0, 0, time.UTC), ScopeNetwork, "10.0.0.1", "10.0.0.2", "tcp", "tcp", 502)
	production := engine.keyWithService(time.Date(2026, 8, 10, 5, 0, 0, 0, time.UTC), ScopeNetwork, "10.0.0.1", "10.0.0.2", "tcp", "tcp", 502)
	if maintenance.Context != "maintenance" {
		t.Fatalf("maintenance observation got context %q", maintenance.Context)
	}
	if production.Context != "production" {
		t.Fatalf("production observation got context %q", production.Context)
	}
}

func TestPublicInternetRelationshipIsShadowCandidateUntilManualPromotion(t *testing.T) {
	engine := New(nil, Config{Enabled: true, SensorID: "s", LearningDuration: time.Hour, CandidateMinSamples: 2, CandidateMinDays: 1, MaxProfiles: 100})
	at := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)
	value := sample{key: engine.keyWithService(at, ScopeNetwork, "10.0.0.1", "8.8.8.8", "udp", "udp", 53), srcAsset: "ip:10.0.0.1", dstAsset: "ip:8.8.8.8", at: at, packet: true}
	engine.observe(value)
	if engine.hasTrustedKey(value.key) {
		t.Fatal("public Internet relationship was silently trusted during learning")
	}
	rows := engine.Candidates(0)
	if len(rows) != 1 || !rows[0].Eligible || rows[0].Reason != publicInternetReviewReason || rows[0].ReadyForPromotion {
		t.Fatalf("expected review-only shadow candidate, got %#v", rows)
	}
	value.at = value.at.Add(time.Second)
	value.key = engine.keyWithService(value.at, ScopeNetwork, "10.0.0.1", "8.8.8.8", "udp", "udp", 53)
	engine.observe(value)
	rows = engine.Candidates(0)
	if len(rows) != 1 || !rows[0].ReadyForPromotion {
		t.Fatalf("review-only candidate did not accumulate promotion evidence: %#v", rows)
	}
	if err := engine.PromoteCandidate(rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if !engine.hasTrustedKey(value.key) {
		t.Fatal("explicitly promoted Internet relationship is not in trusted baseline")
	}
}
