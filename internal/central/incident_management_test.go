package central

import "testing"

func TestCorrelationScoreIsBoundedAndSeverityWeighted(t *testing.T) {
	low := correlationScore("low", 2, 2)
	critical := correlationScore("critical", 2, 2)
	if critical <= low {
		t.Fatalf("critical score %d should exceed low score %d", critical, low)
	}
	if got := correlationScore("critical", 100, 20); got != 100 {
		t.Fatalf("score must be capped at 100, got %d", got)
	}
}

func TestRiskLevelBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{{0, "low"}, {25, "medium"}, {50, "high"}, {75, "critical"}, {100, "critical"}}
	for _, tc := range cases {
		if got := riskLevel(tc.score); got != tc.want {
			t.Fatalf("riskLevel(%d)=%q want %q", tc.score, got, tc.want)
		}
	}
}

func TestContainsAllCorrelationTypes(t *testing.T) {
	if !containsAll([]string{"Threat_Intel", "lateral_movement"}, []string{"threat_intel"}) {
		t.Fatal("required type should match case-insensitively")
	}
	if containsAll([]string{"threat_intel"}, []string{"threat_intel", "lateral_movement"}) {
		t.Fatal("missing required type should not match")
	}
}

func TestSequenceMatches(t *testing.T) {
	got := sequenceMatches([]string{"reconnaissance", "new_service", "ot_value_anomaly"}, []string{"reconnaissance", "ot_value_anomaly"})
	if !got {
		t.Fatal("ordered sequence with intermediate events should match")
	}
	if sequenceMatches([]string{"ot_value_anomaly", "reconnaissance"}, []string{"reconnaissance", "ot_value_anomaly"}) {
		t.Fatal("reversed event sequence must not match")
	}
}
