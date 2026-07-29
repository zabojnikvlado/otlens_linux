package udpconversation

// ManagerStats is a point-in-time snapshot of manager activity.
type ManagerStats struct {
	Active  uint64
	Created uint64
	Updated uint64
	Expired uint64
	Evicted uint64
	Dropped uint64

	TotalPackets uint64
	TotalBytes   uint64
}

// Stats is kept as an alias for callers using the original API name.
type Stats = ManagerStats

type Telemetry struct {
	UDPConversationsActive       uint64  `json:"udp_conversations_active"`
	UDPConversationsCreatedTotal uint64  `json:"udp_conversations_created_total"`
	UDPConversationsExpiredTotal uint64  `json:"udp_conversations_expired_total"`
	UDPConversationsEvictedTotal uint64  `json:"udp_conversations_evicted_total"`
	UDPPacketsTotal              uint64  `json:"udp_packets_total"`
	UDPBytesTotal                uint64  `json:"udp_bytes_total"`
	UDPUnmatchedResponsesTotal   uint64  `json:"udp_unmatched_responses_total"`
	UDPRequestTimeoutsTotal      uint64  `json:"udp_request_timeouts_total"`
	UDPAverageDuration           float64 `json:"udp_average_duration"`
	UDPAverageRTT                float64 `json:"udp_average_rtt"`
}
