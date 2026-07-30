package nba

import (
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/behaviorbaseline"
)

func baselineFixture() behaviorbaseline.Snapshot {
	key := behaviorbaseline.Key{SensorID: "s", Scope: behaviorbaseline.ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Transport: "udp", Protocol: "udp", ServicePort: 53, TimeBucket: 10}
	packetStats := behaviorbaseline.RunningStats{}
	for _, v := range []float64{100, 101, 99, 102, 98, 100} {
		packetStats.Add(v)
	}
	return behaviorbaseline.Snapshot{Version: 2, Profiles: []behaviorbaseline.Profile{{Key: key, Packets: 6, PacketBytes: packetStats}}, AssetProfiles: []behaviorbaseline.AssetBehaviorProfile{{
		Key:     behaviorbaseline.AssetKey{SensorID: "s", AssetID: "mac:a", TimeBucket: 10},
		Inbound: behaviorbaseline.DirectionTotals{}, Outbound: behaviorbaseline.DirectionTotals{Packets: 6, Bytes: 600, Events: 6},
		Peers:     map[string]behaviorbaseline.PeerStats{"mac:b": {Outbound: behaviorbaseline.DirectionTotals{Packets: 6, Events: 6}}},
		Protocols: map[string]behaviorbaseline.DirectionTotals{"udp": {Events: 6}},
		Ports:     map[uint16]behaviorbaseline.DirectionTotals{53: {Events: 6}},
		IPs:       map[string]uint64{"10.0.0.1": 6},
	}}}
}

func TestEvaluatorAcceptsBaselineBehavior(t *testing.T) {
	e := NewEvaluator(baselineFixture())
	key := behaviorbaseline.Key{SensorID: "s", Scope: behaviorbaseline.ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Transport: "udp", Protocol: "udp", ServicePort: 53, TimeBucket: 10}
	if anomaly := e.Evaluate(Input{At: time.Now(), Key: key, SrcAssetID: "mac:a", DstAssetID: "mac:b", PacketBytes: 101}); anomaly != nil {
		t.Fatalf("normal behavior flagged: %#v", anomaly)
	}
}

func TestEvaluatorExplainsNewPeerProtocolAndPort(t *testing.T) {
	e := NewEvaluator(baselineFixture())
	key := behaviorbaseline.Key{SensorID: "s", Scope: behaviorbaseline.ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Transport: "tcp", Protocol: "tcp", ServicePort: 443, TimeBucket: 10}
	anomaly := e.Evaluate(Input{At: time.Now(), Key: key, SrcAssetID: "mac:a", DstAssetID: "ip:8.8.8.8", PacketBytes: 1200})
	if anomaly == nil || anomaly.Score < 90 {
		t.Fatalf("expected strong anomaly, got %#v", anomaly)
	}
	kinds := map[Kind]bool{}
	for _, reason := range anomaly.Reasons {
		kinds[reason.Kind] = true
	}
	for _, kind := range []Kind{KindNewFlow, KindNewPeer, KindNewProtocol, KindNewPort} {
		if !kinds[kind] {
			t.Fatalf("missing reason %s: %#v", kind, anomaly.Reasons)
		}
	}
}

func TestEvaluatorDetectsUnusualTimeAndDirection(t *testing.T) {
	snapshot := baselineFixture()
	profile := snapshot.AssetProfiles[0]
	peer := profile.Peers["mac:b"]
	peer.Outbound = behaviorbaseline.DirectionTotals{}
	peer.Inbound = behaviorbaseline.DirectionTotals{Events: 6}
	profile.Peers["mac:b"] = peer
	snapshot.AssetProfiles[0] = profile
	e := NewEvaluator(snapshot)
	key := behaviorbaseline.Key{SensorID: "s", Scope: behaviorbaseline.ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Transport: "udp", Protocol: "udp", ServicePort: 53, TimeBucket: 30}
	anomaly := e.Evaluate(Input{At: time.Now(), Key: key, SrcAssetID: "mac:a", DstAssetID: "mac:b", PacketBytes: 100})
	kinds := map[Kind]bool{}
	for _, reason := range anomaly.Reasons {
		kinds[reason.Kind] = true
	}
	if !kinds[KindUnusualTime] || !kinds[KindDirection] {
		t.Fatalf("expected time and direction reasons: %#v", anomaly)
	}
}

func BenchmarkEvaluatorNormalFlow(b *testing.B) {
	e := NewEvaluator(baselineFixture())
	key := behaviorbaseline.Key{SensorID: "s", Scope: behaviorbaseline.ScopeNetwork, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Transport: "udp", Protocol: "udp", ServicePort: 53, TimeBucket: 10}
	input := Input{At: time.Now(), Key: key, SrcAssetID: "mac:a", DstAssetID: "mac:b", PacketBytes: 101}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.Evaluate(input)
	}
}
