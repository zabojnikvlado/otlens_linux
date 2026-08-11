package behaviorbaseline

import (
	"testing"
	"time"
)

func TestCompleteLearningRequiresMinimumUnlessForcedAndPersists(t *testing.T) {
	now := time.Now().UTC()
	engine := New(nil, Config{Enabled: true, LearningDuration: time.Hour, MaxProfiles: 100, MaxAssetProfiles: 100})
	engine.ensureStarted(now.Add(-time.Minute))

	if changed, err := engine.CompleteLearning(false); err == nil || changed {
		t.Fatalf("normal completion before minimum should fail, changed=%v err=%v", changed, err)
	}
	changed, err := engine.CompleteLearning(true)
	if err != nil || !changed {
		t.Fatalf("forced completion failed: changed=%v err=%v", changed, err)
	}
	if status := engine.Status(now); status.Mode != ModeMonitoring {
		t.Fatalf("forced completion did not enter monitoring: %q", status.Mode)
	}

	snapshot := engine.Snapshot(now)
	if snapshot.Mode != ModeMonitoring || snapshot.Version != 5 {
		t.Fatalf("unexpected snapshot after completion: mode=%q version=%d", snapshot.Mode, snapshot.Version)
	}

	restored := New(nil, Config{Enabled: true, LearningDuration: time.Hour, MaxProfiles: 100, MaxAssetProfiles: 100})
	if err := restored.Restore(snapshot); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	// The original learning start is still less than an hour old. Monitoring
	// here therefore proves the manual completion flag survived persistence.
	if status := restored.Status(now); status.Mode != ModeMonitoring {
		t.Fatalf("manual completion was not persisted: %q", status.Mode)
	}
}
