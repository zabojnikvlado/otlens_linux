package nba

import (
	"math"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func correlatedAssessment(id string, at time.Time, kind Kind, score float64) RiskAssessment {
	anomaly := Anomaly{ID: id, Timestamp: at, SensorID: "s", AssetID: "mac:a", PeerID: "ip:8.8.8.8", Score: score, Confidence: .8, Reasons: []Reason{{Kind: kind}}}
	return RiskAssessment{AnomalyID: id, Timestamp: at, SensorID: "s", AssetID: "mac:a", AnomalyScore: score, RiskMultiplier: 1, RiskScore: score, Anomaly: anomaly}
}

func TestCorrelationCombinesScoresAndPromotesCandidates(t *testing.T) {
	engine := NewCorrelationEngine(nil, CorrelationConfig{Enabled: true, Window: 15 * time.Minute, ExpireAfter: 30 * time.Minute})
	now := time.Now()
	first := engine.Observe(correlatedAssessment("one", now, KindNewPeer, 60))
	if first == nil || first.State != FindingOpen || first.AlertCandidate {
		t.Fatalf("unexpected first finding: %#v", first)
	}
	second := engine.Observe(correlatedAssessment("two", now.Add(time.Minute), KindNewProtocol, 60))
	if second == nil || second.State != FindingUpdated || math.Abs(second.Score-84) > .001 || !second.AlertCandidate || second.IncidentCandidate {
		t.Fatalf("unexpected correlated finding: %#v", second)
	}
	if !containsString(second.Reasons, "correlation:new_peer_and_protocol") {
		t.Fatalf("missing correlation explanation: %#v", second.Reasons)
	}
	third := engine.Observe(correlatedAssessment("three", now.Add(2*time.Minute), KindNewPort, 60))
	if third == nil || !third.IncidentCandidate || third.Severity != "critical" {
		t.Fatalf("finding was not promoted to incident candidate: %#v", third)
	}
	telemetry := engine.Telemetry()
	if telemetry.FindingsCreated != 1 || telemetry.FindingsUpdated != 2 || telemetry.AlertCandidates != 1 || telemetry.IncidentCandidates != 1 {
		t.Fatalf("unexpected telemetry: %#v", telemetry)
	}
}

func TestCorrelationDeduplicatesExpiresAndRestores(t *testing.T) {
	engine := NewCorrelationEngine(nil, CorrelationConfig{Enabled: true, Window: time.Minute, ExpireAfter: 2 * time.Minute, MaxFindings: 2})
	now := time.Now()
	assessment := correlatedAssessment("one", now, KindNewPeer, 60)
	if engine.Observe(assessment) == nil || engine.Observe(assessment) != nil {
		t.Fatal("assessment deduplication failed")
	}
	if engine.Expire(now.Add(3*time.Minute)) != 1 || len(engine.GetFindings(false)) != 0 {
		t.Fatalf("finding did not expire: %#v", engine.GetFindings(true))
	}
	restored := NewCorrelationEngine(nil, CorrelationConfig{Enabled: true, MaxFindings: 2})
	if err := restored.Restore(engine.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if len(restored.GetFindings(true)) != 1 || restored.Telemetry().FindingsExpired != 1 {
		t.Fatalf("correlation state was not restored: %#v", restored.Snapshot())
	}
}

func TestCorrelationPublishesFindingEvent(t *testing.T) {
	bus := core.NewEventBus()
	output := bus.Subscribe(core.EventBehaviorFinding)
	engine := NewCorrelationEngine(bus, CorrelationConfig{Enabled: true})
	now := time.Now()
	engine.Observe(correlatedAssessment("one", now, KindNewPeer, 60))
	select {
	case event := <-output:
		if finding, ok := event.Data.(Finding); !ok || finding.ID == "" {
			t.Fatalf("unexpected finding event: %#v", event.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("finding event was not published")
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
