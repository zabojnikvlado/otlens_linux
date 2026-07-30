// Package behaviorbaseline learns bounded, explainable network behaviour
// profiles. It deliberately produces no alerts: future NBA detectors consume
// immutable snapshots and decide whether a deviation is anomalous.
package behaviorbaseline

import "time"

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

// Key is intentionally directional. Reverse communication is a separate
// profile, allowing NBA to identify a newly reversed request/response flow.
type Key struct {
	SensorID    string `json:"sensor_id"`
	Scope       Scope  `json:"scope"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	Transport   string `json:"transport"`
	Protocol    string `json:"protocol"`
	ServicePort uint16 `json:"service_port"`
	TimeBucket  uint16 `json:"time_bucket"`
}

// RunningStats uses Welford's online algorithm. It does not retain samples.
type RunningStats struct {
	Count uint64  `json:"count"`
	Mean  float64 `json:"mean"`
	M2    float64 `json:"m2"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
}

func (s *RunningStats) Add(value float64) {
	s.Count++
	if s.Count == 1 {
		s.Mean, s.Min, s.Max = value, value, value
		return
	}
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

func (s RunningStats) Variance() float64 {
	if s.Count < 2 {
		return 0
	}
	return s.M2 / float64(s.Count-1)
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

type Snapshot struct {
	Version         uint32                 `json:"version"`
	Mode            Mode                   `json:"mode"`
	LearningStarted time.Time              `json:"learning_started"`
	LearningEndsAt  time.Time              `json:"learning_ends_at"`
	CapturedAt      time.Time              `json:"captured_at"`
	Profiles        []Profile              `json:"profiles"`
	AssetProfiles   []AssetBehaviorProfile `json:"asset_profiles,omitempty"`
	Observed        uint64                 `json:"observed"`
	Dropped         uint64                 `json:"dropped"`
	Evicted         uint64                 `json:"evicted"`
}

type Status struct {
	Enabled         bool      `json:"enabled"`
	Mode            Mode      `json:"mode"`
	LearningStarted time.Time `json:"learning_started"`
	LearningEndsAt  time.Time `json:"learning_ends_at"`
	Profiles        uint64    `json:"profiles"`
	AssetProfiles   uint64    `json:"asset_profiles"`
	Observed        uint64    `json:"observed"`
	Dropped         uint64    `json:"dropped"`
	Evicted         uint64    `json:"evicted"`
}
