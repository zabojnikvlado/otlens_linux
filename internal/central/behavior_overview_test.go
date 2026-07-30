package central

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

func TestBuildBehaviorOverview(t *testing.T) {
	baseline := json.RawMessage(`{"behavior":{"enabled":true,"mode":"monitoring","profiles":842,"asset_profiles":8}}`)
	now := time.Now()
	alerts := []AlertHistoryEntry{
		{SensorID: "s1", IP: "10.0.0.15", Type: "behavior_finding", Status: "new", LastSeen: now, Evidence: map[string]interface{}{"risk_score": 82.0, "confidence": .9, "reasons": []interface{}{"new peer"}}},
		{SensorID: "s1", IP: "10.0.0.20", Type: "behavior_finding", Status: "approved", Evidence: map[string]interface{}{"risk_score": 99.0}},
	}
	got := buildBehaviorOverview(alerts, []management.TelemetrySnapshot{{SensorID: "s1", Baseline: baseline}}, 10)
	if !got.LearningComplete || got.ActiveBaselines != 842 || got.Coverage != 80 {
		t.Fatalf("unexpected baseline overview: %+v", got)
	}
	if got.BehaviorAlerts != 1 || got.AffectedAssets != 1 || got.TopAnomaly == nil || got.TopAnomaly.AssetIP != "10.0.0.15" {
		t.Fatalf("unexpected findings overview: %+v", got)
	}
	if math.Abs(got.NetworkHealth-18) > .001 || got.State != "critical" {
		t.Fatalf("unexpected network health: %+v", got)
	}
}

func TestBuildBehaviorOverviewLearningIsNotHealthy(t *testing.T) {
	baseline := json.RawMessage(`{"behavior":{"enabled":true,"mode":"learning","profiles":3,"asset_profiles":1}}`)
	got := buildBehaviorOverview(nil, []management.TelemetrySnapshot{{Baseline: baseline}}, 4)
	if got.State != "learning" || got.LearningComplete {
		t.Fatalf("learning baseline reported as ready: %+v", got)
	}
}
