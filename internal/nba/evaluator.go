package nba

import (
	"fmt"
	"math"
	"sort"
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
	contexts   map[string]struct{}
	buckets    map[uint16]struct{}
	dayClasses map[string]struct{}
	shifts     map[string]struct{}
	peers      map[string]behaviorbaseline.PeerStats
	protocols  map[string]behaviorbaseline.DirectionTotals
	ports      map[uint16]behaviorbaseline.DirectionTotals
	samples    uint64
}

type Evaluator struct {
	flows          map[behaviorbaseline.Key]behaviorbaseline.Profile
	flowStats      map[flowBase]behaviorbaseline.Profile
	flowBases      map[flowBase]struct{}
	assets         map[assetBase]*assetKnowledge
	identityByIP   map[string]string
	minStatSamples int
	bucketsPerDay  int
}

func NewEvaluator(snapshot behaviorbaseline.Snapshot) *Evaluator {
	minSamples := snapshot.MinStatSamples
	if minSamples <= 0 {
		minSamples = 30
	}
	bucketsPerDay := snapshot.BucketsPerDay
	if bucketsPerDay <= 0 {
		bucketsPerDay = 24
	}
	e := &Evaluator{
		flows:     make(map[behaviorbaseline.Key]behaviorbaseline.Profile, len(snapshot.Profiles)),
		flowStats: make(map[flowBase]behaviorbaseline.Profile), flowBases: make(map[flowBase]struct{}),
		assets: make(map[assetBase]*assetKnowledge), identityByIP: make(map[string]string), minStatSamples: minSamples, bucketsPerDay: bucketsPerDay,
	}
	for _, profile := range snapshot.Profiles {
		e.flows[profile.Key] = profile
		base := baseFor(profile.Key)
		e.flowBases[base] = struct{}{}
		merged := e.flowStats[base]
		merged.PacketBytes = mergeStats(merged.PacketBytes, profile.PacketBytes)
		merged.RTTMillis = mergeStats(merged.RTTMillis, profile.RTTMillis)
		merged.InterArrival = mergeStats(merged.InterArrival, profile.InterArrival)
		merged.Packets += profile.Packets
		e.flowStats[base] = merged
	}
	for _, profile := range snapshot.AssetProfiles {
		base := assetBase{profile.Key.SensorID, profile.Key.AssetID}
		known := e.assets[base]
		if known == nil {
			known = &assetKnowledge{
				contexts: make(map[string]struct{}), buckets: make(map[uint16]struct{}), dayClasses: make(map[string]struct{}), shifts: make(map[string]struct{}),
				peers: make(map[string]behaviorbaseline.PeerStats), protocols: make(map[string]behaviorbaseline.DirectionTotals), ports: make(map[uint16]behaviorbaseline.DirectionTotals),
			}
			e.assets[base] = known
		}
		known.contexts[timeContext(profile.Key.TimeBucket, profile.Key.DayClass, profile.Key.Shift, profile.Key.Context)] = struct{}{}
		known.buckets[profile.Key.TimeBucket] = struct{}{}
		if profile.Key.DayClass != "" {
			known.dayClasses[profile.Key.DayClass] = struct{}{}
		}
		if profile.Key.Shift != "" {
			known.shifts[profile.Key.Shift] = struct{}{}
		}
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
	if input.Key.Context == "maintenance" {
		// Approved maintenance is deliberately a separate context. Hard
		// security detectors continue to run, but behavior deviations are not
		// promoted into production-baseline anomalies.
		return nil
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

	base := baseFor(input.Key)
	if _, ok := e.flowBases[base]; !ok {
		add(KindNewFlow, 35, "Flow/service was not present in the trusted baseline", input.Key, nil)
	}

	known := e.assets[assetBase{input.Key.SensorID, input.SrcAssetID}]
	confidenceSamples := uint64(0)
	if known == nil {
		add(KindNewAsset, 40, "Asset has no mature trusted behavior profile", input.SrcAssetID, nil)
	} else {
		confidenceSamples = known.samples
		ctx := timeContext(input.Key.TimeBucket, input.Key.DayClass, input.Key.Shift, input.Key.Context)
		if _, exact := known.contexts[ctx]; !exact && known.samples >= uint64(e.minStatSamples) {
			_, hourKnown := known.buckets[input.Key.TimeBucket]
			_, shiftKnown := known.shifts[input.Key.Shift]
			switch {
			case hourKnown:
				add(KindUnusualTime, 8, "Time-of-day is known but this weekday/weekend context is new", input.Key.DayClass, sortedStrings(known.dayClasses))
			case shiftKnown:
				add(KindUnusualTime, 12, "Shift is known but this time bucket is unusual", input.Key.TimeBucket, knownBucketList(known.buckets))
			case timeCoverage(known.buckets, e.bucketsPerDay) >= .5:
				add(KindUnusualTime, 20, "Asset is not normally active at this time of day", input.Key.TimeBucket, knownBucketList(known.buckets))
			}
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

	stats := e.flowStats[base]
	if input.PacketBytes > 0 {
		if distance, expected, ok := robustDeviation(float64(input.PacketBytes), stats.PacketBytes, e.minStatSamples); ok {
			add(KindPacketSize, math.Min(25, 8+distance*3), "Packet size is outside the robust learned distribution", input.PacketBytes, expected)
		}
	}
	if input.RTTMillis > 0 {
		if distance, expected, ok := robustDeviation(input.RTTMillis, stats.RTTMillis, e.minStatSamples); ok {
			add(KindRTT, math.Min(25, 8+distance*3), "RTT is outside the robust learned distribution", input.RTTMillis, expected)
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
	confidence := math.Min(1, float64(confidenceSamples)/float64(maxInt(e.minStatSamples*2, 1)))
	if confidence == 0 && stats.Packets > 0 {
		confidence = math.Min(1, float64(stats.Packets)/float64(maxInt(e.minStatSamples*2, 1)))
	}
	// Asset maturity is enforced by Engine before production evaluation. Keep
	// the raw anomaly score explainable here; confidence is carried separately
	// into risk/correlation and preview rendering.
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
	return fmt.Sprintf("%s|%d|%s|%s", flowID(input.Key), input.Key.TimeBucket, input.Key.DayClass, strings.Join(kinds, ","))
}
func timeContext(bucket uint16, dayClass, shift, context string) string {
	return fmt.Sprintf("%d|%s|%s|%s", bucket, dayClass, shift, context)
}

func robustDeviation(value float64, stats behaviorbaseline.RunningStats, minSamples int) (float64, float64, bool) {
	if minSamples <= 0 {
		minSamples = 30
	}
	if stats.Count < uint64(minSamples) {
		return 0, 0, false
	}
	median, mad, ok := stats.MedianMAD()
	if ok && mad > 0 {
		scaled := 1.4826 * mad
		z := math.Abs(value-median) / scaled
		return z, median, z >= 3.5
	}
	p05, ok05 := stats.Quantile(.05)
	p95, ok95 := stats.Quantile(.95)
	if ok05 && ok95 {
		span := math.Max(p95-p05, math.Max(1, math.Abs(median)*.05))
		deadband := span * .25
		if value < p05-deadband {
			return (p05-value)/span + 3, median, true
		}
		if value > p95+deadband {
			return (value-p95)/span + 3, median, true
		}
		return 0, median, false
	}
	sd := math.Sqrt(stats.Variance())
	if sd == 0 {
		return 0, stats.Mean, false
	}
	z := math.Abs(value-stats.Mean) / sd
	return z, stats.Mean, z >= 4
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
	a.Samples = append(a.Samples, b.Samples...)
	if len(a.Samples) > 128 {
		// Evenly downsample merged reservoirs to preserve both histories.
		values := make([]float64, 0, 128)
		step := float64(len(a.Samples)) / 128
		for i := 0; i < 128; i++ {
			values = append(values, a.Samples[int(float64(i)*step)])
		}
		a.Samples = values
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
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func sortedStrings(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func timeCoverage(values map[uint16]struct{}, bucketsPerDay int) float64 {
	if bucketsPerDay <= 0 {
		bucketsPerDay = 24
	}
	return math.Min(1, float64(len(values))/float64(bucketsPerDay))
}
func mapKeys[V any](values map[string]V) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func portKeys[V any](values map[uint16]V) []uint16 {
	out := make([]uint16, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
