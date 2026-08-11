package store

import (
	"testing"
	"time"
)

func TestRobustBaselineResistsSingleLearningOutlier(t *testing.T) {
	tag := &Tag{}
	at := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		value := 50.0 + float64((i%5)-2)*0.1
		updateRobustBaseline(tag, value, at.Add(time.Duration(i)*time.Second))
	}
	// A single commissioning/noise outlier must not permanently expand the
	// robust production range the way raw min/max would.
	updateRobustBaseline(tag, 10_000, at.Add(101*time.Second))
	finalizeRobustBaseline(tag)
	low, high, ok := robustBaselineBounds(tag)
	if !ok {
		t.Fatal("expected mature robust baseline")
	}
	if low >= 50 || high <= 50 || high > 60 {
		t.Fatalf("unexpected robust bounds after one outlier: low=%f high=%f median=%f mad=%f", low, high, tag.BaselineMedian, tag.BaselineMAD)
	}
}

func TestRobustBaselineLearnsRateOfChange(t *testing.T) {
	tag := &Tag{}
	at := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 40; i++ {
		updateRobustBaseline(tag, float64(i), at.Add(time.Duration(i)*time.Second))
	}
	if tag.BaselineTypicalRate < .9 || tag.BaselineTypicalRate > 1.1 {
		t.Fatalf("typical learned rate=%f, want about 1 unit/s", tag.BaselineTypicalRate)
	}
}
