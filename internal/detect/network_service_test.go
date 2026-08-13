package detect

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func TestBaselineServicePortClassification(t *testing.T) {
	tests := []struct {
		name string
		p    core.Packet
		want uint16
	}{
		{"tcp request uses SYN destination", core.Packet{L4Protocol: "TCP", SrcPort: 55000, DstPort: 443, TCPFlags: "SYN"}, 443},
		{"tcp response uses SYN ACK source", core.Packet{L4Protocol: "TCP", SrcPort: 443, DstPort: 55000, TCPFlags: "SYN,ACK"}, 443},
		{"known udp service wins", core.Packet{L4Protocol: "UDP", SrcPort: 55000, DstPort: 5353}, 5353},
		{"linux vxlan is classified as service", core.Packet{L4Protocol: "UDP", SrcPort: 8472, DstPort: 46890}, 8472},
		{"unknown dynamic udp pair collapses", core.Packet{L4Protocol: "UDP", SrcPort: 60000, DstPort: 61000}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := baselineServicePort(tt.p); got != tt.want {
				t.Fatalf("baselineServicePort()=%d want %d", got, tt.want)
			}
		})
	}
}

func TestRoutineDiscoveryTrafficRequiresGroupDestination(t *testing.T) {
	multicast := core.Packet{L4Protocol: "UDP", DstIP: "224.0.0.251", SrcPort: 5353, DstPort: 5353}
	if !routineDiscoveryTraffic(multicast) {
		t.Fatal("mDNS multicast should be routine discovery")
	}
	unicast := multicast
	unicast.DstIP = "10.1.2.3"
	if routineDiscoveryTraffic(unicast) {
		t.Fatal("unicast traffic should not be suppressed merely because it uses a discovery port")
	}
}

func TestLegacyLearnedBaselineStillSuppressesNewClassifierKey(t *testing.T) {
	p := core.Packet{
		Timestamp:  time.Now(),
		L4Protocol: "UDP",
		SrcIP:      "10.0.0.1",
		DstIP:      "10.0.0.2",
		SrcPort:    60000,
		DstPort:    61000,
	}
	e := &Engine{
		baselineMode:    BaselineModeMonitoring,
		learnedPatterns: map[string]bool{},
		learnedAssets:   map[string]bool{},
		assetFirstSeen:  map[string]time.Time{},
		assetSamples:    map[string]uint64{},
		knownMAC:        map[string]string{},
		candidateMAC:    map[string]string{},
		alerts:          map[string]*Alert{},
	}
	legacy := e.legacyBaselineKeyForPacketLocked(p)
	current := e.baselineKeyForPacketLocked(p)
	if legacy == current {
		t.Fatal("test requires legacy and current keys to differ")
	}
	e.learnedPatterns[legacy] = true
	e.handleBaseline(p)
	if len(e.alerts) != 0 {
		t.Fatalf("legacy learned key should suppress post-upgrade alert, got %d alerts", len(e.alerts))
	}
}
