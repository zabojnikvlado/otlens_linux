package persist

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/detect"
)

func TestAlertStateRoundTripPreservesRestartState(t *testing.T) {
	t.Parallel()

	db, err := Open(filepath.Join(t.TempDir(), "sensor.sqlite"))
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	})

	firstSeen := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	lastSeen := firstSeen.Add(37 * time.Minute)
	want := []*detect.Alert{{
		ID: "alert-1", Type: detect.AlertType("external_communication"), Severity: "high",
		Message: "persist me", IP: "10.1.2.3", FirstSeen: firstSeen, LastSeen: lastSeen,
		Count: 42, Status: detect.AlertStatusNew, Synced: true,
		Evidence: map[string]interface{}{"destination": "203.0.113.10", "port": float64(443)},
	}}
	if err := syncKeyed(db, bucketAlerts, want, func(item *detect.Alert) string { return item.ID }); err != nil {
		t.Fatalf("syncKeyed() failed: %v", err)
	}

	got, err := loadKeyed[*detect.Alert](db, bucketAlerts)
	if err != nil {
		t.Fatalf("loadKeyed() failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("loaded %d alerts, want 1", len(got))
	}
	alert := got[0]
	if alert.ID != want[0].ID || alert.Count != 42 || alert.Status != detect.AlertStatusNew || !alert.Synced {
		t.Fatalf("alert restart state changed: %#v", alert)
	}
	if !alert.FirstSeen.Equal(firstSeen) || !alert.LastSeen.Equal(lastSeen) {
		t.Fatalf("alert timestamps changed: first=%s last=%s", alert.FirstSeen, alert.LastSeen)
	}
	if alert.Evidence["destination"] != "203.0.113.10" {
		t.Fatalf("alert evidence changed: %#v", alert.Evidence)
	}
}
