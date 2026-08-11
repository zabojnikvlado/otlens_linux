package nba

import (
	"testing"
	"time"
)

func TestResetEvaluatorCachePreservesAnomalyHistory(t *testing.T) {
	engine := &Engine{
		evaluator:         &Evaluator{},
		previewEvaluator:  &Evaluator{},
		evaluatorRevision: 7,
		evaluatorBuiltAt:  time.Now(),
		previewBuiltAt:    time.Now(),
		anomalies:         []Anomaly{{ID: "keep-me"}},
		last:              map[string]time.Time{"keep-me": time.Now()},
		telemetry: Telemetry{
			AnomaliesTotal:        1,
			PreviewEvaluatedTotal: 12,
			PreviewAnomaliesTotal: 3,
			PreviewTopScore:       88,
			PreviewTopReason:      "preview",
		},
	}

	engine.ResetEvaluatorCache()
	if engine.evaluator != nil || engine.previewEvaluator != nil || engine.evaluatorRevision != 0 || !engine.evaluatorBuiltAt.IsZero() || !engine.previewBuiltAt.IsZero() {
		t.Fatal("evaluator cache was not fully cleared")
	}
	if len(engine.anomalies) != 1 || engine.anomalies[0].ID != "keep-me" || engine.telemetry.AnomaliesTotal != 1 {
		t.Fatal("anomaly history was modified by cache reset")
	}
	if engine.telemetry.PreviewEvaluatedTotal != 0 || engine.telemetry.PreviewAnomaliesTotal != 0 || engine.telemetry.PreviewTopScore != 0 || engine.telemetry.PreviewTopReason != "" {
		t.Fatal("preview telemetry was not cleared with the preview evaluator")
	}
}
