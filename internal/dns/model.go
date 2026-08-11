package dns

import "time"

// Observation is a normalized passive DNS query/response event.
type Observation struct {
	Timestamp      time.Time `json:"timestamp"`
	ConversationID string    `json:"conversation_id,omitempty"`
	Direction      string    `json:"direction,omitempty"`
	TransactionID  uint16    `json:"transaction_id"`
	ClientIP       string    `json:"client_ip"`
	ServerIP       string    `json:"server_ip"`
	QueryName      string    `json:"query_name"`
	QueryType      uint16    `json:"query_type"`
	ResponseCode   uint8     `json:"response_code"`
	IsResponse     bool      `json:"is_response"`
	AnswerCount    int       `json:"answer_count"`
	Answers        []string  `json:"answers,omitempty"`
	CNAMEs         []string  `json:"cnames,omitempty"`
	TTL            uint32    `json:"ttl,omitempty"`
	PayloadBytes   int       `json:"payload_bytes,omitempty"`
}

type DNSExchange struct {
	ConversationID string        `json:"conversation_id,omitempty"`
	Direction      string        `json:"direction,omitempty"`
	TransactionID  uint16        `json:"transaction_id"`
	QueryName      string        `json:"query_name"`
	QueryType      uint16        `json:"query_type"`
	RequestedAt    time.Time     `json:"requested_at,omitempty"`
	RespondedAt    time.Time     `json:"responded_at,omitempty"`
	RTT            time.Duration `json:"rtt"`
	ResponseCode   uint8         `json:"response_code"`
	Answers        int           `json:"answers"`
	TTL            uint32        `json:"ttl,omitempty"`
	TimedOut       bool          `json:"timed_out"`
}

type Telemetry struct {
	DNSQueries            uint64  `json:"dns_queries"`
	DNSResponses          uint64  `json:"dns_responses"`
	DNSTimeouts           uint64  `json:"dns_timeouts"`
	DNSAverageRTT         float64 `json:"dns_average_rtt"`
	DNSNXDOMAIN           uint64  `json:"dns_nxdomain"`
	DNSSERVFAIL           uint64  `json:"dns_servfail"`
	DNSUnmatchedResponses uint64  `json:"dns_unmatched_responses"`
}
