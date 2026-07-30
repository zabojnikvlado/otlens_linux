package nba

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/behaviorbaseline"
	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func TestEnginePublishesAndDeduplicatesAnomalies(t *testing.T) {
	now := time.Now()
	snapshot := baselineFixture()
	snapshot.LearningStarted = now.Add(-2 * time.Minute)
	baseline := behaviorbaseline.New(nil, behaviorbaseline.Config{Enabled: true, LearningDuration: time.Minute, MaxProfiles: 100, MaxAssetProfiles: 100})
	if err := baseline.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	bus := core.NewEventBus()
	events := bus.Subscribe(core.EventBehaviorAnomaly)
	engine := New(bus, baseline, Config{Enabled: true, MinScore: 40, MaxAnomalies: 2, Cooldown: time.Minute})
	key := behaviorbaseline.Key{SensorID: "s", Scope: behaviorbaseline.ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Transport: "tcp", Protocol: "tcp", ServicePort: 443, TimeBucket: 10}
	input := Input{At: now, Key: key, SrcAssetID: "mac:a", DstAssetID: "ip:8.8.8.8", PacketBytes: 1000}
	engine.evaluate(input)
	engine.evaluate(input)
	if len(engine.GetAnomalies()) != 1 {
		t.Fatalf("deduplication failed: %#v", engine.GetAnomalies())
	}
	telemetry := engine.Telemetry()
	if telemetry.AnomaliesTotal != 1 || telemetry.DeduplicatedTotal != 1 || telemetry.EvaluatedTotal != 2 {
		t.Fatalf("unexpected telemetry: %#v", telemetry)
	}
	restored := New(bus, baseline, Config{Enabled: true, MinScore: 40, MaxAnomalies: 2, Cooldown: time.Minute})
	if err := restored.Restore(engine.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if len(restored.GetAnomalies()) != 1 || restored.Telemetry().AnomaliesTotal != 1 {
		t.Fatalf("anomaly state was not restored: %#v", restored.Snapshot())
	}
	select {
	case event := <-events:
		if _, ok := event.Data.(Anomaly); !ok {
			t.Fatalf("unexpected event payload %T", event.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("anomaly event was not published")
	}
}
