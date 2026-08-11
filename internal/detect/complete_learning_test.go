package detect

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func TestCompleteBaselineRequiresMinimumUnlessForced(t *testing.T) {
	bus := core.NewEventBus()
	completed := bus.Subscribe(core.EventBaselineLearningComplete)
	engine := &Engine{
		baselineEnabled:  true,
		baselineMode:     BaselineModeLearning,
		learningStarted:  time.Now().Add(-time.Minute),
		learningDuration: time.Hour,
		learnedPatterns:  map[string]bool{"baseline|tcp|a|b|443": true},
		learnedAssets:    map[string]bool{"00:11:22:33:44:55": true},
		eventBus:         bus,
	}

	if changed, err := engine.CompleteBaseline(false); err == nil || changed {
		t.Fatalf("normal completion before minimum should fail, changed=%v err=%v", changed, err)
	}
	changed, err := engine.CompleteBaseline(true)
	if err != nil || !changed {
		t.Fatalf("forced completion failed: changed=%v err=%v", changed, err)
	}
	if engine.baselineMode != BaselineModeMonitoring {
		t.Fatalf("baseline mode=%q, want monitoring", engine.baselineMode)
	}
	if engine.behaviorDetectionsSuppressed() {
		t.Fatal("behavior detections remained suppressed after completion")
	}
	select {
	case event := <-completed:
		if event.Type != core.EventBaselineLearningComplete {
			t.Fatalf("unexpected completion event: %q", event.Type)
		}
	default:
		t.Fatal("baseline.learning_complete was not published")
	}
}
