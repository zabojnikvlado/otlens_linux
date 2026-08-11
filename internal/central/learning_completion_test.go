package central

import (
	"encoding/json"
	"testing"
)

func TestLearningCompletionConfirmed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "both monitoring", raw: `{"enabled":true,"mode":"monitoring","behavior":{"enabled":true,"mode":"monitoring"}}`, want: true},
		{name: "behavior disabled", raw: `{"enabled":true,"mode":"monitoring","behavior":{"enabled":false,"mode":"learning"}}`, want: true},
		{name: "legacy disabled", raw: `{"enabled":false,"mode":"learning","behavior":{"enabled":true,"mode":"monitoring"}}`, want: true},
		{name: "legacy still learning", raw: `{"enabled":true,"mode":"learning","behavior":{"enabled":true,"mode":"monitoring"}}`, want: false},
		{name: "behavior still learning", raw: `{"enabled":true,"mode":"monitoring","behavior":{"enabled":true,"mode":"learning"}}`, want: false},
		{name: "no enabled baseline", raw: `{"enabled":false,"mode":"monitoring","behavior":{"enabled":false,"mode":"monitoring"}}`, want: false},
		{name: "invalid", raw: `{`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := learningCompletionConfirmed(json.RawMessage(tt.raw)); got != tt.want {
				t.Fatalf("learningCompletionConfirmed()=%v want %v", got, tt.want)
			}
		})
	}
}
