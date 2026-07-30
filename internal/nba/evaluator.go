package nba

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/behaviorbaseline"
)

type flowBase struct {
	SensorID, SrcIP, DstIP, Transport, Protocol string
	Scope                                       behaviorbaseline.Scope
	ServicePort                                 uint16
}

type assetBase struct{ SensorID, AssetID string }

type assetKnowledge struct {
	buckets   map[uint16]struct{}
	peers     map[string]behaviorbaseline.PeerStats
	protocols map[string]behaviorbaseline.DirectionTotals
	ports     map[uint16]behaviorbaseline.DirectionTotals
	samples   uint64
}

type Evaluator struct {
	flows        map[behaviorbaseline.Key]behaviorbaseline.Profile
	flowStats    map[flowBase]behaviorbaseline.Profile
	assets       map[assetBase]*assetKnowledge
	identityByIP map[string]string
}

func NewEvaluator(snapshot behaviorbaseline.Snapshot) *Evaluator {
	e := &Evaluator{flows: make(map[behaviorbaseline.Key]behaviorbaseline.Profile, len(snapshot.Profiles)), flowStats: make(map[flowBase]behaviorbaseline.Profile), assets: make(map[assetBase]*assetKnowledge), identityByIP: make(map[string]string)}
	for _, profile := range snapshot.Profiles {
		e.flows[profile.Key] = profile
		base := baseFor(profile.Key)
		merged := e.flowStats[base]
		merged.PacketBytes = mergeStats(merged.PacketBytes, profile.PacketBytes)
		merged.RTTMillis = mergeStats(merged.RTTMillis, profile.RTTMillis)
		merged.Packets += profile.Packets
		e.flowStats[base] = merged
	}
	for _, profile := range snapshot.AssetProfiles {
		base := assetBase{profile.Key.SensorID, profile.Key.AssetID}
		known := e.assets[base]
		if known == nil {
			known = &assetKnowledge{buckets: make(map[uint16]struct{}), peers: make(map[string]behaviorbaseline.PeerStats), protocols: make(map[string]behaviorbaseline.DirectionTotals), ports: make(map[uint16]behaviorbaseline.DirectionTotals)}
			e.assets[base] = known
		}
		known.buckets[profile.Key.TimeBucket] = struct{}{}
		known.samples += profile.Inbound.Events + profile.Outbound.Events
		for key, value := range profile.Peers {
			known.peers[key] = mergePeer(known.peers[key], value)
		}
		for key, value := range profile.Protocols {
			total := known.protocols[key]
			addTotals(&total, value)
			known.protocols[key] = total
		}
		for key, value := range profile.Ports {
			total := known.ports[key]
			addTotals(&total, value)
			known.ports[key] = total
		}
		for ip := range profile.IPs {
			e.identityByIP[profile.Key.SensorID+"|"+ip] = profile.Key.AssetID
		}
	}
	return e
}

type Input struct {
	At                     time.Time
	Key                    behaviorbaseline.Key
	SrcAssetID, DstAssetID string
	PacketBytes            uint64
	RTTMillis              float64
}

func (e *Evaluator) Evaluate(input Input) *Anomaly {
	if input.At.IsZero() {
		input.At = time.Now().UTC()
	}
	if input.SrcAssetID == "" {
		input.SrcAssetID = e.resolve(input.Key.SensorID, input.Key.SrcIP)
	}
	if input.DstAssetID == "" {
		input.DstAssetID = e.resolve(input.Key.SensorID, input.Key.DstIP)
	}
	var reasons []Reason
	add := func(kind Kind, weight float64, message string, observed, expected any) {
		reasons = append(reasons, Reason{Kind: kind, Weight: weight, Message: message, Observed: observed, Expected: expected})
	}
	if _, ok := e.flows[input.Key]; !ok {
		add(KindNewFlow, 35, "Flow was not present in this time bucket", input.Key, nil)
	}
	known := e.assets[assetBase{input.Key.SensorID, input.SrcAssetID}]
	confidenceSamples := uint64(0)
	if known == nil {
		add(KindNewAsset, 40, "Asset has no learned behavior profile", input.SrcAssetID, nil)
	} else {
		confidenceSamples = known.samples
		if _, ok := known.buckets[input.Key.TimeBucket]; !ok {
			add(KindUnusualTime, 20, "Asset is not normally active in this time bucket", input.Key.TimeBucket, knownBucketList(known.buckets))
		}
		peer, peerKnown := known.peers[input.DstAssetID]
		if !peerKnown {
			add(KindNewPeer, 30, "Asset has not communicated with this peer", input.DstAssetID, nil)
		} else if peer.Outbound.Events == 0 && peer.Inbound.Events > 0 {
			add(KindDirection, 25, "Communication direction is reversed from baseline", "outbound", "inbound")
		}
		if _, ok := known.protocols[input.Key.Protocol]; !ok {
			add(KindNewProtocol, 25, "Protocol was not observed for this asset", input.Key.Protocol, mapKeys(known.protocols))
		}
		if _, ok := known.ports[input.Key.ServicePort]; !ok {
			add(KindNewPort, 15, "Service port was not observed for this asset", input.Key.ServicePort, portKeys(known.ports))
		}
	}
	stats := e.flowStats[baseFor(input.Key)]
	if input.PacketBytes > 0 {
		if z, ok := deviation(float64(input.PacketBytes), stats.PacketBytes); ok {
			add(KindPacketSize, math.Min(25, 8+z*3), "Packet size is outside the learned distribution", input.PacketBytes, stats.PacketBytes.Mean)
		}
	}
	if input.RTTMillis > 0 {
		if z, ok := deviation(input.RTTMillis, stats.RTTMillis); ok {
			add(KindRTT, math.Min(25, 8+z*3), "RTT is outside the learned distribution", input.RTTMillis, stats.RTTMillis.Mean)
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	score := 0.0
	for _, reason := range reasons {
		score += reason.Weight
	}
	score = math.Min(100, score)
	confidence := math.Min(1, float64(confidenceSamples)/20)
	if confidence == 0 && stats.Packets > 0 {
		confidence = math.Min(1, float64(stats.Packets)/20)
	}
	return &Anomaly{ID: anomalyID(input, reasons), Timestamp: input.At, SensorID: input.Key.SensorID, AssetID: input.SrcAssetID, PeerID: input.DstAssetID, SrcIP: input.Key.SrcIP, DstIP: input.Key.DstIP, FlowID: flowID(input.Key), Protocol: input.Key.Protocol, Score: score, Confidence: confidence, Reasons: reasons}
}

func (e *Evaluator) resolve(sensor, ip string) string {
	if id := e.identityByIP[sensor+"|"+ip]; id != "" {
		return id
	}
	return "ip:" + ip
}
func baseFor(key behaviorbaseline.Key) flowBase {
	return flowBase{key.SensorID, key.SrcIP, key.DstIP, key.Transport, key.Protocol, key.Scope, key.ServicePort}
}
func flowID(key behaviorbaseline.Key) string {
	return fmt.Sprintf("%s|%s|%s:%d|%s", key.SensorID, key.Protocol, key.SrcIP, key.ServicePort, key.DstIP)
}
func anomalyID(input Input, reasons []Reason) string {
	kinds := make([]string, len(reasons))
	for i, r := range reasons {
		kinds[i] = string(r.Kind)
	}
	return fmt.Sprintf("%s|%d|%s", flowID(input.Key), input.Key.TimeBucket, strings.Join(kinds, ","))
}
func deviation(value float64, stats behaviorbaseline.RunningStats) (float64, bool) {
	if stats.Count < 5 {
		return 0, false
	}
	sd := math.Sqrt(stats.Variance())
	if sd == 0 {
		if value == stats.Mean {
			return 0, false
		}
		return math.Abs(value-stats.Mean) / math.Max(1, math.Abs(stats.Mean)), math.Abs(value-stats.Mean) > math.Max(1, math.Abs(stats.Mean)*.25)
	}
	z := math.Abs(value-stats.Mean) / sd
	return z, z >= 3
}
func mergeStats(a, b behaviorbaseline.RunningStats) behaviorbaseline.RunningStats {
	if a.Count == 0 {
		return b
	}
	if b.Count == 0 {
		return a
	}
	count := a.Count + b.Count
	delta := b.Mean - a.Mean
	a.Mean = (float64(a.Count)*a.Mean + float64(b.Count)*b.Mean) / float64(count)
	a.M2 += b.M2 + delta*delta*float64(a.Count*b.Count)/float64(count)
	a.Count = count
	if b.Min < a.Min {
		a.Min = b.Min
	}
	if b.Max > a.Max {
		a.Max = b.Max
	}
	return a
}
func addTotals(a *behaviorbaseline.DirectionTotals, b behaviorbaseline.DirectionTotals) {
	a.Packets += b.Packets
	a.Bytes += b.Bytes
	a.Events += b.Events
}
func mergePeer(a, b behaviorbaseline.PeerStats) behaviorbaseline.PeerStats {
	addTotals(&a.Inbound, b.Inbound)
	addTotals(&a.Outbound, b.Outbound)
	if b.LastSeen.After(a.LastSeen) {
		a.LastSeen = b.LastSeen
	}
	return a
}
func knownBucketList(values map[uint16]struct{}) []uint16 {
	out := make([]uint16, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	return out
}
func mapKeys[V any](values map[string]V) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	return out
}
func portKeys[V any](values map[uint16]V) []uint16 {
	out := make([]uint16, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	return out
}
