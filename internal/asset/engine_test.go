package asset

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"go.uber.org/zap"
)

func TestUpdateTracksLifecycleAndProtectsARPVerifiedIP(t *testing.T) {
	previousLogger := logger.Log
	logger.Log = zap.NewNop()
	t.Cleanup(func() { logger.Log = previousLogger })

	engine := NewEngine(map[string]int{"10.0.0.10": 90}, 50)
	first := time.Now().Add(-time.Minute)

	engine.Update("10.0.0.10", "00:11:22:33:44:55", "plc-1", first, true, true, 42)
	got := engine.Get("00:11:22:33:44:55")
	if got == nil {
		t.Fatal("asset was not created")
	}
	if got.IP != "10.0.0.10" || got.Score != 90 || got.PacketCount != 1 ||
		!got.FromAnalysis || got.VLANID != 42 || !got.Confirmed {
		t.Fatalf("unexpected initial asset: %+v", got)
	}

	// Routed traffic must not replace an IP established by ARP. A live
	// observation does, however, clear the historical-analysis marker.
	engine.Update("203.0.113.20", got.MAC, "", first.Add(time.Second), false, false, 0)
	got = engine.Get(got.MAC)
	if got.IP != "10.0.0.10" || got.Score != 90 || got.FromAnalysis ||
		got.VLANID != 42 || got.PacketCount != 2 {
		t.Fatalf("unexpected updated asset: %+v", got)
	}
}

func TestRestorePruneConfirmAndSnapshots(t *testing.T) {
	engine := NewEngine(nil, 50)
	old := time.Now().Add(-2 * time.Hour)
	engine.Restore([]*Asset{
		{MAC: "old", IP: "10.0.0.1", LastSeen: old},
		{MAC: "analysis", IP: "10.0.0.2", LastSeen: old, FromAnalysis: true},
	})

	if removed := engine.Prune(time.Hour); removed != 1 {
		t.Fatalf("Prune removed %d assets, want 1", removed)
	}
	if engine.Get("analysis") == nil || engine.Get("old") != nil {
		t.Fatal("prune did not preserve analysis-only asset")
	}

	copy := engine.Get("analysis")
	copy.IP = "mutated"
	if engine.Get("analysis").IP == "mutated" {
		t.Fatal("Get returned mutable internal state")
	}
	if engine.Confirm("missing") {
		t.Fatal("Confirm reported success for an unknown asset")
	}
	engine.Clear()
	if engine.Count() != 0 {
		t.Fatalf("Clear left %d assets", engine.Count())
	}
}
