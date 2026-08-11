package detect

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/nba"
)

func TestBehaviorFindingPromotesExistingAlert(t *testing.T) {
	now := time.Now()
	engine := &Engine{baselineMode: BaselineModeMonitoring, alerts: map[string]*Alert{"nba|f": {ID: "nba|f", Status: AlertStatusNew}}}
	finding := nba.Finding{
		ID: "f", AssetID: "mac:a", PeerID: "ip:8.8.8.8", FirstSeen: now.Add(-time.Minute), LastSeen: now,
		Score: 92, Confidence: .8, Severity: "critical", AlertCandidate: true, IncidentCandidate: true, AssessmentCount: 3,
		Reasons: []string{"new_peer"}, Assessments: []nba.RiskAssessment{{Anomaly: nba.Anomaly{SrcIP: "10.0.0.1"}}},
	}
	engine.handleBehaviorFinding(finding)
	alert := engine.alerts["nba|f"]
	if alert.Type != AlertBehaviorIncident || alert.Severity != "critical" || alert.IP != "10.0.0.1" || alert.Count != 1 || alert.Synced {
		t.Fatalf("unexpected behavior alert: %#v", alert)
	}
	if alert.Evidence["incident_candidate"] != true || alert.Evidence["risk_score"] != float64(92) {
		t.Fatalf("missing structured evidence: %#v", alert.Evidence)
	}
}

func TestApprovedBehaviorFindingIsNotUpdated(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	engine := &Engine{baselineMode: BaselineModeMonitoring, alerts: map[string]*Alert{"nba|f": {ID: "nba|f", Status: AlertStatusApproved, LastSeen: old, Count: 1}}}
	engine.handleBehaviorFinding(nba.Finding{ID: "f", LastSeen: time.Now(), AlertCandidate: true, AssessmentCount: 2})
	if alert := engine.alerts["nba|f"]; alert.LastSeen != old || alert.Count != 1 {
		t.Fatalf("approved finding was updated: %#v", alert)
	}
}

func TestBehaviorFindingSuppressedDuringLearning(t *testing.T) {
	engine := &Engine{baselineEnabled: true, baselineMode: BaselineModeLearning, alerts: make(map[string]*Alert)}
	engine.handleBehaviorFinding(nba.Finding{ID: "f", LastSeen: time.Now(), AlertCandidate: true, AssessmentCount: 1})
	if len(engine.alerts) != 0 {
		t.Fatalf("behavior finding raised during learning: %#v", engine.alerts)
	}
}
