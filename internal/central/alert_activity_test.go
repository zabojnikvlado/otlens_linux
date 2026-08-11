package central

import (
	"testing"
	"time"
)

func TestAlertIsActive(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	if !alertIsActive("new", now.Add(-4*time.Minute), now) {
		t.Fatal("recent unreviewed alert should be active")
	}
	if !alertIsActive("confirmed", now.Add(-time.Minute), now) {
		t.Fatal("recent confirmed alert should be active")
	}
	if alertIsActive("approved", now.Add(-time.Minute), now) {
		t.Fatal("approved alert must not be active")
	}
	if alertIsActive("new", now.Add(-6*time.Minute), now) {
		t.Fatal("stale alert should be resolved/inactive")
	}
}
