package central

import (
	"math"
	"sort"
	"strings"
	"time"
)

// TrafficExpectedPoint is the schedule-aware expected traffic envelope for the
// visible bucket. It is derived from historical traffic for the same local
// time-of-day and, where enough samples exist, the same weekday/weekend class.
type TrafficExpectedPoint struct {
	Time           time.Time `json:"time"`
	MedianBytes    uint64    `json:"median_bytes"`
	P10Bytes       uint64    `json:"p10_bytes"`
	P95Bytes       uint64    `json:"p95_bytes"`
	ThresholdBytes uint64    `json:"threshold_bytes"`
	MedianOutBytes uint64    `json:"median_out_bytes"`
	MedianInBytes  uint64    `json:"median_in_bytes"`
	Samples        int       `json:"samples"`
	Source         string    `json:"source"`
}

// TrafficBaselineComparison is an optional, deeper comparison requested by the
// operator. It intentionally remains separate from the lightweight baseline
// used by every Analytics graph so normal Analytics remains fast.
type TrafficBaselineComparison struct {
	Enabled               bool                   `json:"enabled"`
	Available             bool                   `json:"available"`
	Maturity              string                 `json:"maturity"`
	HistoryDays           int                    `json:"history_days"`
	HistorySamples        int                    `json:"history_samples"`
	LookbackDays          int                    `json:"lookback_days"`
	ProfileSource         string                 `json:"profile_source"`
	ExpectedTotalBytes    uint64                 `json:"expected_total_bytes"`
	ObservedTotalBytes    uint64                 `json:"observed_total_bytes"`
	DeviationPercent      float64                `json:"deviation_percent"`
	DirectionDeltaPercent float64                `json:"direction_delta_percent"`
	BehaviorScore         int                    `json:"behavior_score"`
	NewPeers              []string               `json:"new_peers"`
	NewServices           []string               `json:"new_services"`
	CoverageCapped        bool                   `json:"coverage_capped,omitempty"`
	Series                []TrafficExpectedPoint `json:"series"`
	Message               string                 `json:"message,omitempty"`
}

type trafficProfileValues struct {
	total []float64
	out   []float64
	in    []float64
}

func analyticsLocation(offsetMinutes int) *time.Location {
	// JavaScript Date#getTimezoneOffset is UTC-local, therefore the local offset
	// from UTC is the negative of the supplied number.
	return time.FixedZone("analytics-local", -offsetMinutes*60)
}

func trafficSlotKey(t time.Time, step int, loc *time.Location, includeWeekend bool) string {
	lt := t.In(loc)
	seconds := lt.Hour()*3600 + lt.Minute()*60 + lt.Second()
	slot := seconds / analyticsMaxInt(step, 1)
	if !includeWeekend {
		return "all:" + strconvI(slot)
	}
	weekend := lt.Weekday() == time.Saturday || lt.Weekday() == time.Sunday
	if weekend {
		return "weekend:" + strconvI(slot)
	}
	return "weekday:" + strconvI(slot)
}

func strconvI(v int) string {
	// Avoid fmt in the high-frequency profile builder.
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [24]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func analyticsMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func fillTrafficSeries(series []TrafficSeriesPoint, from, to time.Time, step int) []TrafficSeriesPoint {
	if step <= 0 || !from.Before(to) {
		return append([]TrafficSeriesPoint(nil), series...)
	}
	byBucket := make(map[int64]TrafficSeriesPoint, len(series))
	for _, p := range series {
		bucket := p.Time.Unix() / int64(step) * int64(step)
		p.Time = time.Unix(bucket, 0).UTC()
		byBucket[bucket] = p
	}
	start := from.Unix() / int64(step) * int64(step)
	end := to.Unix()
	out := make([]TrafficSeriesPoint, 0, int((end-start)/int64(step))+1)
	for ts := start; ts < end; ts += int64(step) {
		if p, ok := byBucket[ts]; ok {
			out = append(out, p)
		} else {
			out = append(out, TrafficSeriesPoint{Time: time.Unix(ts, 0).UTC()})
		}
	}
	return out
}

func scaleTrafficSeries(series []TrafficSeriesPoint, numerator, denominator int) []TrafficSeriesPoint {
	if numerator <= 0 || denominator <= 0 || numerator == denominator {
		return append([]TrafficSeriesPoint(nil), series...)
	}
	ratio := float64(numerator) / float64(denominator)
	out := make([]TrafficSeriesPoint, len(series))
	for i, p := range series {
		p.OutBytes = uint64(math.Round(float64(p.OutBytes) * ratio))
		p.InBytes = uint64(math.Round(float64(p.InBytes) * ratio))
		p.TotalBytes = p.OutBytes + p.InBytes
		p.OutPackets = uint64(math.Round(float64(p.OutPackets) * ratio))
		p.InPackets = uint64(math.Round(float64(p.InPackets) * ratio))
		p.TotalPackets = p.OutPackets + p.InPackets
		p.Connections = int64(math.Round(float64(p.Connections) * ratio))
		out[i] = p
	}
	return out
}

func uniqueTrafficHistoryDays(series []TrafficSeriesPoint, loc *time.Location) int {
	seen := map[string]struct{}{}
	for _, p := range series {
		if p.TotalBytes == 0 && p.Connections == 0 {
			continue
		}
		seen[p.Time.In(loc).Format("2006-01-02")] = struct{}{}
	}
	return len(seen)
}

func trafficBaselineMaturity(raw []TrafficSeriesPoint, from time.Time, loc *time.Location) (string, int) {
	days := uniqueTrafficHistoryDays(raw, loc)
	if len(raw) == 0 || days == 0 {
		return "Learning", 0
	}
	last := raw[len(raw)-1].Time
	if from.Sub(last) > 7*24*time.Hour {
		return "Stale", days
	}
	switch {
	case days < 2:
		return "Learning", days
	case days < 7:
		return "Limited", days
	case days < 14:
		return "Established", days
	default:
		return "Mature", days
	}
}

func buildTrafficProfile(history []TrafficSeriesPoint, historyStep int, loc *time.Location) (map[string]*trafficProfileValues, map[string]*trafficProfileValues) {
	byClass := map[string]*trafficProfileValues{}
	allDays := map[string]*trafficProfileValues{}
	for _, p := range history {
		classKey := trafficSlotKey(p.Time, historyStep, loc, true)
		allKey := trafficSlotKey(p.Time, historyStep, loc, false)
		for key, dst := range map[string]map[string]*trafficProfileValues{classKey: byClass, allKey: allDays} {
			v := dst[key]
			if v == nil {
				v = &trafficProfileValues{}
				dst[key] = v
			}
			v.total = append(v.total, float64(p.TotalBytes))
			v.out = append(v.out, float64(p.OutBytes))
			v.in = append(v.in, float64(p.InBytes))
		}
	}
	return byClass, allDays
}

func expectedPointFromValues(t time.Time, vals *trafficProfileValues, scale float64, step int, source string) TrafficExpectedPoint {
	if vals == nil || len(vals.total) == 0 {
		return TrafficExpectedPoint{Time: t, Source: "insufficient", Samples: 0}
	}
	p10 := percentile(vals.total, .10) * scale
	med := percentile(vals.total, .50) * scale
	p95 := percentile(vals.total, .95) * scale
	dev := make([]float64, 0, len(vals.total))
	baseMedian := percentile(vals.total, .50)
	for _, v := range vals.total {
		dev = append(dev, math.Abs(v-baseMedian))
	}
	mad := percentile(dev, .50) * scale
	minThreshold := 64.0 * 1024.0 * math.Max(1, float64(step)/60.0)
	threshold := math.Max(minThreshold, math.Max(med*3, med+6*1.4826*mad))
	if p95 > threshold {
		threshold = p95 * 1.5
	}
	return TrafficExpectedPoint{
		Time: t, MedianBytes: uint64(math.Round(med)), P10Bytes: uint64(math.Round(p10)), P95Bytes: uint64(math.Round(p95)),
		ThresholdBytes: uint64(math.Round(threshold)), MedianOutBytes: uint64(math.Round(percentile(vals.out, .50) * scale)),
		MedianInBytes: uint64(math.Round(percentile(vals.in, .50) * scale)), Samples: len(vals.total), Source: source,
	}
}

func scheduleAwareExpectedSeries(current []TrafficSeriesPoint, history []TrafficSeriesPoint, currentStep, historyStep, tzOffset int) ([]TrafficExpectedPoint, string) {
	loc := analyticsLocation(tzOffset)
	byClass, allDays := buildTrafficProfile(history, historyStep, loc)
	scale := float64(currentStep) / float64(historyStep)
	out := make([]TrafficExpectedPoint, len(current))
	usedClass, usedAll := 0, 0
	for i, p := range current {
		classKey := trafficSlotKey(p.Time, historyStep, loc, true)
		allKey := trafficSlotKey(p.Time, historyStep, loc, false)
		vals := byClass[classKey]
		source := "weekday_time_of_day"
		// Four samples means roughly four weeks of same weekday/weekend timing.
		// When that is unavailable, broaden to the same time-of-day across all days.
		if vals == nil || len(vals.total) < 4 {
			vals = allDays[allKey]
			source = "time_of_day"
			usedAll++
		} else {
			usedClass++
		}
		out[i] = expectedPointFromValues(p.Time, vals, scale, currentStep, source)
	}
	profileSource := "weekday/weekend + time-of-day"
	if usedAll > usedClass {
		profileSource = "time-of-day with weekday/weekend where mature"
	}
	return out, profileSource
}

func stringSet(rows []TrafficBreakdown) map[string]struct{} {
	out := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		name := strings.ToLower(strings.TrimSpace(r.Name))
		if name != "" && name != "unknown" {
			out[name] = struct{}{}
		}
	}
	return out
}

func newBreakdownNames(current, history []TrafficBreakdown) []string {
	known := stringSet(history)
	seen := map[string]struct{}{}
	out := []string{}
	for _, r := range current {
		name := strings.TrimSpace(r.Name)
		key := strings.ToLower(name)
		if key == "" || key == "unknown" {
			continue
		}
		if _, ok := known[key]; ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func buildScheduleAwareAnomalies(current []TrafficSeriesPoint, expected []TrafficExpectedPoint) []TrafficAnomaly {
	out := []TrafficAnomaly{}
	for i := range current {
		if i >= len(expected) || expected[i].Samples == 0 || current[i].TotalBytes == 0 {
			continue
		}
		threshold := expected[i].ThresholdBytes
		if current[i].TotalBytes <= threshold {
			continue
		}
		comparison := expected[i].MedianBytes
		if comparison == 0 {
			comparison = maxU64(expected[i].P95Bytes, threshold)
		}
		ratio := float64(current[i].TotalBytes) / math.Max(float64(comparison), 1)
		current[i].Anomaly = true
		current[i].Ratio = ratio
		out = append(out, TrafficAnomaly{Time: current[i].Time, Bytes: current[i].TotalBytes, Baseline: expected[i].MedianBytes, Threshold: threshold, Ratio: ratio, Description: "Traffic volume above schedule-aware baseline"})
	}
	return out
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func buildTrafficBaselineComparison(req trafficAnalyticsRequest, current *trafficAnalyticsBundle, rawHistory, filledHistory []TrafficSeriesPoint, historyBundle trafficAnalyticsBundle, currentStep, historyStep int) (TrafficBaselineComparison, []TrafficAnomaly) {
	loc := analyticsLocation(req.TZOffsetMinutes)
	maturity, historyDays := trafficBaselineMaturity(rawHistory, req.From, loc)
	expected, profileSource := scheduleAwareExpectedSeries(current.Series, filledHistory, currentStep, historyStep, req.TZOffsetMinutes)
	var expectedTotal uint64
	for _, p := range expected {
		expectedTotal += p.MedianBytes
	}
	observed := current.Summary.TotalBytes
	deviation := 0.0
	if expectedTotal > 0 {
		deviation = (float64(observed) - float64(expectedTotal)) / float64(expectedTotal) * 100
	} else if observed > 0 {
		deviation = 100
	}
	currentShare, historyShare := 0.0, 0.0
	if current.Summary.TotalBytes > 0 {
		currentShare = float64(current.Summary.OutBytes) / float64(current.Summary.TotalBytes)
	}
	if historyBundle.Summary.TotalBytes > 0 {
		historyShare = float64(historyBundle.Summary.OutBytes) / float64(historyBundle.Summary.TotalBytes)
	}
	directionDelta := math.Abs(currentShare-historyShare) * 100
	newPeers := newBreakdownNames(current.TopPeers, historyBundle.TopPeers)
	newServices := newBreakdownNames(current.TopProtocols, historyBundle.TopProtocols)

	anomalies := buildScheduleAwareAnomalies(current.Series, expected)
	for i := range current.Series {
		current.Series[i].Anomaly = false
		current.Series[i].Ratio = 0
	}
	for _, a := range anomalies {
		for i := range current.Series {
			if current.Series[i].Time.Equal(a.Time) {
				current.Series[i].Anomaly = true
				current.Series[i].Ratio = a.Ratio
				break
			}
		}
	}
	current.Summary.AnomalousIntervals = len(anomalies)

	penalty := 0
	if len(current.Series) > 0 {
		penalty += int(math.Min(40, float64(len(anomalies))/float64(len(current.Series))*100))
	}
	penalty += analyticsMinInt(len(newPeers)*8, 24)
	penalty += analyticsMinInt(len(newServices)*10, 20)
	if directionDelta > 20 {
		penalty += int(math.Min(16, (directionDelta-20)/5))
	}
	if math.Abs(deviation) > 100 {
		penalty += int(math.Min(20, math.Abs(deviation)/100*5))
	}
	score := clampInt(100-penalty, 0, 100)
	if maturity == "Learning" {
		score = analyticsMinInt(score, 70)
	} else if maturity == "Limited" {
		score = analyticsMinInt(score, 85)
	}

	return TrafficBaselineComparison{
		Enabled: true, Available: len(rawHistory) > 0, Maturity: maturity, HistoryDays: historyDays,
		HistorySamples: len(rawHistory), LookbackDays: req.BaselineDays, ProfileSource: profileSource,
		ExpectedTotalBytes: expectedTotal, ObservedTotalBytes: observed, DeviationPercent: deviation,
		DirectionDeltaPercent: directionDelta, BehaviorScore: score, NewPeers: newPeers, NewServices: newServices,
		CoverageCapped: len(historyBundle.TopPeers) >= 4096 || len(historyBundle.TopProtocols) >= 4096,
		Series:         expected,
	}, anomalies
}

func analyticsMinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
