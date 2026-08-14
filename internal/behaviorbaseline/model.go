// Package behaviorbaseline learns bounded, explainable network behaviour
// profiles. It deliberately produces no alerts: NBA detectors consume
// immutable snapshots and decide whether a deviation is anomalous.
package behaviorbaseline

import (
	"math"
	"sort"
	"time"
)

type Mode string

const (
	ModeLearning   Mode = "learning"
	ModeMonitoring Mode = "monitoring"
)

type Scope string

const (
	ScopeNetwork     Scope = "network"
	ScopeApplication Scope = "application"
)

// Key is directional. TimeBucket is an intra-day bucket rather than an
// hour-of-week bucket. DayClass and Shift provide progressively more specific
// context without requiring a full seven-day learning cycle before NBA can
// reason about normal time-of-day behaviour.
type Key struct {
	SensorID    string `json:"sensor_id"`
	Scope       Scope  `json:"scope"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	Transport   string `json:"transport"`
	Protocol    string `json:"protocol"`
	ServicePort uint16 `json:"service_port"`
	TimeBucket  uint16 `json:"time_bucket"`
	DayClass    string `json:"day_class,omitempty"`
	Shift       string `json:"shift,omitempty"`
	Context     string `json:"context,omitempty"`
}

const runningStatsReservoir = 128

// RunningStats uses Welford's online algorithm and also keeps a tiny bounded
// deterministic reservoir. The reservoir lets NBA use median/MAD/percentiles
// instead of relying only on mean/variance, which is much more robust to a few
// outliers during learning. The reservoir is bounded, so persistence remains
// predictable even for very busy tags/flows.
type RunningStats struct {
	Count   uint64    `json:"count"`
	Mean    float64   `json:"mean"`
	M2      float64   `json:"m2"`
	Min     float64   `json:"min"`
	Max     float64   `json:"max"`
	Samples []float64 `json:"samples,omitempty"`
}

func (s *RunningStats) Add(value float64) {
	s.Count++
	if s.Count == 1 {
		s.Mean, s.Min, s.Max = value, value, value
	} else {
		if value < s.Min {
			s.Min = value
		}
		if value > s.Max {
			s.Max = value
		}
		delta := value - s.Mean
		s.Mean += delta / float64(s.Count)
		s.M2 += delta * (value - s.Mean)
	}
	if len(s.Samples) < runningStatsReservoir {
		s.Samples = append(s.Samples, value)
	} else {
		// Deterministic reservoir replacement. It is intentionally not random:
		// snapshots from identical traffic remain reproducible in tests.
		idx := int((s.Count * 11400714819323198485) % runningStatsReservoir)
		s.Samples[idx] = value
	}
}

func (s RunningStats) Variance() float64 {
	if s.Count < 2 {
		return 0
	}
	return s.M2 / float64(s.Count-1)
}

func (s RunningStats) Quantile(q float64) (float64, bool) {
	if len(s.Samples) == 0 {
		return 0, false
	}
	values := append([]float64(nil), s.Samples...)
	sort.Float64s(values)
	if q <= 0 {
		return values[0], true
	}
	if q >= 1 {
		return values[len(values)-1], true
	}
	pos := q * float64(len(values)-1)
	lo, hi := int(math.Floor(pos)), int(math.Ceil(pos))
	if lo == hi {
		return values[lo], true
	}
	frac := pos - float64(lo)
	return values[lo]*(1-frac) + values[hi]*frac, true
}

func (s RunningStats) MedianMAD() (median, mad float64, ok bool) {
	median, ok = s.Quantile(.5)
	if !ok {
		return 0, 0, false
	}
	deviations := make([]float64, 0, len(s.Samples))
	for _, value := range s.Samples {
		deviations = append(deviations, math.Abs(value-median))
	}
	sort.Float64s(deviations)
	if len(deviations) == 0 {
		return median, 0, true
	}
	mid := len(deviations) / 2
	if len(deviations)%2 == 0 {
		mad = (deviations[mid-1] + deviations[mid]) / 2
	} else {
		mad = deviations[mid]
	}
	return median, mad, true
}

type Profile struct {
	Key Key `json:"key"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	Packets      uint64            `json:"packets"`
	Bytes        uint64            `json:"bytes"`
	PacketBytes  RunningStats      `json:"packet_bytes"`
	InterArrival RunningStats      `json:"inter_arrival_millis"`
	RTTMillis    RunningStats      `json:"rtt_millis"`
	Operations   map[string]uint64 `json:"operations,omitempty"`
}

type AssetKey struct {
	SensorID   string `json:"sensor_id"`
	AssetID    string `json:"asset_id"`
	TimeBucket uint16 `json:"time_bucket"`
	DayClass   string `json:"day_class,omitempty"`
	Shift      string `json:"shift,omitempty"`
	Context    string `json:"context,omitempty"`
}

type DirectionTotals struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	Events  uint64 `json:"events"`
}

type PeerStats struct {
	Inbound  DirectionTotals `json:"inbound"`
	Outbound DirectionTotals `json:"outbound"`
	LastSeen time.Time       `json:"last_seen"`
}

// AssetBehaviorProfile is an analytical projection owned by this engine, not
// inventory state. AssetID is normally "mac:<address>" and falls back to
// "ip:<address>" until a stable L2 identity is observed.
type AssetBehaviorProfile struct {
	Key       AssetKey  `json:"key"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	Inbound  DirectionTotals `json:"inbound"`
	Outbound DirectionTotals `json:"outbound"`

	PacketBytes  RunningStats `json:"packet_bytes"`
	InterArrival RunningStats `json:"inter_arrival_millis"`
	RTTMillis    RunningStats `json:"rtt_millis"`

	Peers      map[string]PeerStats       `json:"peers,omitempty"`
	Protocols  map[string]DirectionTotals `json:"protocols,omitempty"`
	Ports      map[uint16]DirectionTotals `json:"ports,omitempty"`
	Operations map[string]uint64          `json:"operations,omitempty"`
	IPs        map[string]uint64          `json:"ips,omitempty"`
}

// Candidate is a shadow-baseline observation collected after the trusted
// learning phase. Candidates never silently modify the trusted baseline. An
// operator can explicitly promote them; until then NBA treats a candidate-only
// asset/pattern as still learning rather than immediately declaring it normal.
type Candidate struct {
	ID                string    `json:"id"`
	Key               Key       `json:"key"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	Observations      uint64    `json:"observations"`
	DistinctDays      int       `json:"distinct_days"`
	ObservationDays   []string  `json:"observation_days,omitempty"`
	Eligible          bool      `json:"eligible"`
	ReadyForPromotion bool      `json:"ready_for_promotion"`
	Reason            string    `json:"reason,omitempty"`
}

type LearningExclusionSnapshot struct {
	SensorID    string    `json:"sensor_id,omitempty"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	Protocol    string    `json:"protocol,omitempty"`
	ServicePort uint16    `json:"service_port,omitempty"`
	Until       time.Time `json:"until"`
}

type CandidateProfileSnapshot struct {
	ID       string  `json:"id"`
	Profile  Profile `json:"profile"`
	SrcAsset string  `json:"src_asset,omitempty"`
	DstAsset string  `json:"dst_asset,omitempty"`
}

type PromotedCandidate struct {
	ID         string    `json:"id"`
	PromotedAt time.Time `json:"promoted_at"`
}

type PromotionFailure struct {
	ID       string    `json:"id"`
	Error    string    `json:"error"`
	FailedAt time.Time `json:"failed_at"`
}

type AssetMaturity struct {
	AssetID       string    `json:"asset_id"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Samples       uint64    `json:"samples"`
	TimeBuckets   int       `json:"time_buckets"`
	Mature        bool      `json:"mature"`
	Readiness     float64   `json:"readiness"`
	CandidateOnly bool      `json:"candidate_only,omitempty"`
}

type Snapshot struct {
	Version            uint32                      `json:"version"`
	Mode               Mode                        `json:"mode"`
	LearningStarted    time.Time                   `json:"learning_started"`
	LearningEndsAt     time.Time                   `json:"learning_ends_at"`
	CapturedAt         time.Time                   `json:"captured_at"`
	Profiles           []Profile                   `json:"profiles"`
	AssetProfiles      []AssetBehaviorProfile      `json:"asset_profiles,omitempty"`
	Candidates         []Candidate                 `json:"candidates,omitempty"`
	CandidateProfiles  []CandidateProfileSnapshot  `json:"candidate_profiles,omitempty"`
	PromotedCandidates []PromotedCandidate         `json:"promoted_candidates,omitempty"`
	PromotionFailures  []PromotionFailure          `json:"promotion_failures,omitempty"`
	LearningExclusions []LearningExclusionSnapshot `json:"learning_exclusions,omitempty"`
	MinStatSamples     int                         `json:"min_stat_samples,omitempty"`
	BucketsPerDay      int                         `json:"buckets_per_day,omitempty"`
	Observed           uint64                      `json:"observed"`
	Dropped            uint64                      `json:"dropped"`
	Excluded           uint64                      `json:"excluded"`
	Evicted            uint64                      `json:"evicted"`
}

type Status struct {
	Enabled                   bool               `json:"enabled"`
	ManualCompletionSupported bool               `json:"manual_completion_supported"`
	Mode                      Mode               `json:"mode"`
	LearningStarted           time.Time          `json:"learning_started"`
	LearningEndsAt            time.Time          `json:"learning_ends_at"`
	MinimumDuration           time.Duration      `json:"minimum_duration"`
	Readiness                 float64            `json:"readiness"`
	Ready                     bool               `json:"ready"`
	ReadinessReason           string             `json:"readiness_reason,omitempty"`
	Profiles                  uint64             `json:"profiles"`
	AssetProfiles             uint64             `json:"asset_profiles"`
	MatureAssets              int                `json:"mature_assets"`
	LearningAssets            int                `json:"learning_assets"`
	CandidatePatterns         int                `json:"candidate_patterns"`
	CandidateAssets           int                `json:"candidate_assets"`
	Candidates                []Candidate        `json:"candidates,omitempty"`
	PromotedCandidates        []string           `json:"promoted_candidates,omitempty"`
	PromotionFailures         []PromotionFailure `json:"promotion_failures,omitempty"`
	AssetMaturity             []AssetMaturity    `json:"asset_maturity,omitempty"`
	NewPatternRate            float64            `json:"new_pattern_rate"`
	TimeCoverage              float64            `json:"time_coverage"`
	Observed                  uint64             `json:"observed"`
	Dropped                   uint64             `json:"dropped"`
	Excluded                  uint64             `json:"excluded"`
	Evicted                   uint64             `json:"evicted"`
}
