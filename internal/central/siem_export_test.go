package central

import (
	"testing"
	"time"
)

func TestSIEMAlertEventTimePrefersAlertLastSeen(t *testing.T) {
	fallback := time.Date(2026, 8, 11, 18, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2026, 8, 11, 17, 42, 13, 123, time.UTC)
	got := siemAlertEventTime(map[string]interface{}{
		"LastSeen":  lastSeen.Format(time.RFC3339Nano),
		"FirstSeen": time.Date(2026, 8, 11, 17, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}, fallback)
	if !got.Equal(lastSeen) {
		t.Fatalf("event time=%s want %s", got, lastSeen)
	}
}

func TestSIEMAlertEventTimeFallsBackForMalformedTimestamp(t *testing.T) {
	fallback := time.Date(2026, 8, 11, 18, 0, 0, 0, time.UTC)
	got := siemAlertEventTime(map[string]interface{}{"LastSeen": "not-a-time"}, fallback)
	if !got.Equal(fallback) {
		t.Fatalf("event time=%s want fallback %s", got, fallback)
	}
}
