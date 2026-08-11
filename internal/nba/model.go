package nba

import "time"

type Kind string

const (
	KindNewFlow     Kind = "new_flow"
	KindNewAsset    Kind = "new_asset_behavior"
	KindNewPeer     Kind = "new_peer"
	KindNewProtocol Kind = "new_protocol"
	KindNewPort     Kind = "new_port"
	KindUnusualTime Kind = "unusual_time"
	KindDirection   Kind = "new_direction"
	KindPacketSize  Kind = "packet_size_deviation"
	KindRTT         Kind = "rtt_deviation"
)

type Reason struct {
	Kind     Kind    `json:"kind"`
	Weight   float64 `json:"weight"`
	Message  string  `json:"message"`
	Observed any     `json:"observed,omitempty"`
	Expected any     `json:"expected,omitempty"`
}

type Anomaly struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	SensorID   string    `json:"sensor_id"`
	AssetID    string    `json:"asset_id"`
	PeerID     string    `json:"peer_id,omitempty"`
	SrcIP      string    `json:"src_ip,omitempty"`
	DstIP      string    `json:"dst_ip,omitempty"`
	FlowID     string    `json:"flow_id"`
	Protocol   string    `json:"protocol"`
	Score      float64   `json:"score"`
	Confidence float64   `json:"confidence"`
	Reasons    []Reason  `json:"reasons"`
}

type Telemetry struct {
	EvaluatedTotal        uint64  `json:"evaluated_total"`
	LearningSkippedTotal  uint64  `json:"learning_skipped_total"`
	BelowThresholdTotal   uint64  `json:"below_threshold_total"`
	DeduplicatedTotal     uint64  `json:"deduplicated_total"`
	AnomaliesTotal        uint64  `json:"anomalies_total"`
	ActiveAnomalies       int     `json:"active_anomalies"`
	AverageAnomalyScore   float64 `json:"average_anomaly_score"`
	PreviewEvaluatedTotal uint64  `json:"preview_evaluated_total"`
	PreviewAnomaliesTotal uint64  `json:"preview_anomalies_total"`
	PreviewTopScore       float64 `json:"preview_top_score"`
	PreviewTopReason      string  `json:"preview_top_reason,omitempty"`
	CandidateGraceSkipped uint64  `json:"candidate_grace_skipped_total"`
}

type Snapshot struct {
	Version   uint32               `json:"version"`
	Anomalies []Anomaly            `json:"anomalies"`
	Last      map[string]time.Time `json:"last"`
	Telemetry Telemetry            `json:"telemetry"`
}

func cloneAnomaly(value Anomaly) Anomaly {
	value.Reasons = append([]Reason(nil), value.Reasons...)
	return value
}
