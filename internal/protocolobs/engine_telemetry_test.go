package protocolobs

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func TestTimeoutTelemetryCountsAllProtocolExchanges(t *testing.T) {
	engine := New(core.NewEventBus())
	now := time.Unix(30_000, 0).UTC()
	engine.publishExchanges([]any{
		NTPExchange{RequestedAt: now, TimedOut: true},
		SNMPExchange{RequestedAt: now, TimedOut: true},
		SIPDialog{StartedAt: now, TimedOut: false},
	})
	if got := engine.Timeouts(); got != 2 {
		t.Fatalf("timeouts = %d, want 2", got)
	}
	engine.Reset()
	if got := engine.Timeouts(); got != 0 {
		t.Fatalf("timeouts after reset = %d, want 0", got)
	}
}
