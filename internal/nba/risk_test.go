package nba

import (
	"math"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func TestAssessRiskExplainsContextMultipliers(t *testing.T) {
	level := 1
	anomaly := Anomaly{ID: "a", Timestamp: time.Now(), SensorID: "s", AssetID: "mac:a", Score: 60, Confidence: 1}
	assessment := AssessRisk(anomaly, RiskContext{AssetCriticality: 100, PurdueLevel: &level, ExternalDestination: true})
	if assessment.RiskMultiplier != 2.25 || assessment.RiskScore != 100 {
		t.Fatalf("unexpected assessment: %#v", assessment)
	}
	if len(assessment.Factors) != 3 {
		t.Fatalf("expected three explainable factors: %#v", assessment.Factors)
	}
}

func TestAssessRiskReducesApprovedMaintenanceActivity(t *testing.T) {
	anomaly := Anomaly{ID: "a", Timestamp: time.Now(), Score: 80, Confidence: .1}
	assessment := AssessRisk(anomaly, RiskContext{MaintenanceWindow: true, ApprovedPeer: true})
	if math.Abs(assessment.RiskMultiplier-.105) > .0001 || math.Abs(assessment.RiskScore-8.4) > .0001 {
		t.Fatalf("unexpected reduction: %#v", assessment)
	}
}

func TestRiskEnginePublishesBoundedAssessments(t *testing.T) {
	bus := core.NewEventBus()
	output := bus.Subscribe(core.EventBehaviorRisk)
	engine := NewRiskEngine(bus, func(Anomaly) RiskContext { return RiskContext{ExternalDestination: true} }, RiskConfig{Enabled: true, MaxAssessments: 1})
	engine.Start()
	defer engine.Stop()
	now := time.Now()
	bus.Publish(core.Event{Type: core.EventBehaviorAnomaly, Data: Anomaly{ID: "one", Timestamp: now, Score: 50, Confidence: 1}})
	select {
	case event := <-output:
		assessment, ok := event.Data.(RiskAssessment)
		if !ok || assessment.RiskScore != 60 {
			t.Fatalf("unexpected risk event: %#v", event.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("risk event was not published")
	}
	bus.Publish(core.Event{Type: core.EventBehaviorAnomaly, Data: Anomaly{ID: "two", Timestamp: now, Score: 50, Confidence: 1}})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		items := engine.GetAssessments()
		if len(items) == 1 && items[0].AnomalyID == "two" {
			telemetry := engine.Telemetry()
			if telemetry.AssessmentsTotal != 2 || telemetry.ElevatedTotal != 2 {
				t.Fatalf("unexpected risk telemetry: %#v", telemetry)
			}
			restored := NewRiskEngine(bus, nil, RiskConfig{Enabled: true, MaxAssessments: 1})
			if err := restored.Restore(engine.Snapshot()); err != nil {
				t.Fatal(err)
			}
			if len(restored.GetAssessments()) != 1 || restored.Telemetry().AssessmentsTotal != 2 {
				t.Fatalf("risk state was not restored: %#v", restored.Snapshot())
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("assessment retention was not bounded")
}
