package dns

import "time"

// Observation is a normalized passive DNS query/response event.
type Observation struct {
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"client_ip"`
	ServerIP     string    `json:"server_ip"`
	QueryName    string    `json:"query_name"`
	QueryType    uint16    `json:"query_type"`
	ResponseCode uint8     `json:"response_code"`
	IsResponse   bool      `json:"is_response"`
	Answers      []string  `json:"answers,omitempty"`
	CNAMEs       []string  `json:"cnames,omitempty"`
	TTL          uint32    `json:"ttl,omitempty"`
}
