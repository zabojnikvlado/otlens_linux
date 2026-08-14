package central

import (
	"encoding/json"
	"testing"
)

func TestParseBaselinePromotionCandidate(t *testing.T) {
	raw := json.RawMessage(`{"behavior":{"candidates":[{"id":"candidate|s|network|10.0.0.1|10.0.0.2|tcp|445|10|weekday|production","eligible":true,"ready_for_promotion":true,"observations":42,"distinct_days":4}],"promoted_candidates":["already"]}}`)
	id := "candidate|s|network|10.0.0.1|10.0.0.2|tcp|445|10|weekday|production"
	got := parseBaselinePromotionCandidate(raw, id)
	if !got.Found || !got.Eligible || !got.Ready || got.Observations != 42 || got.DistinctDays != 4 || got.Promoted {
		t.Fatalf("unexpected candidate state: %+v", got)
	}
	promoted := parseBaselinePromotionCandidate(raw, "already")
	if !promoted.Promoted || promoted.Found {
		t.Fatalf("unexpected promoted state: %+v", promoted)
	}
	missing := parseBaselinePromotionCandidate(raw, "missing")
	if missing.Found || missing.Promoted {
		t.Fatalf("unexpected missing state: %+v", missing)
	}
}
