package protocolobs

import "time"

// Observation is normalized application-protocol metadata. Payloads and secrets
// are deliberately not retained.
type Observation struct {
	Timestamp    time.Time         `json:"timestamp"`
	Protocol     string            `json:"protocol"`
	Transport    string            `json:"transport"`
	SrcIP        string            `json:"src_ip"`
	DstIP        string            `json:"dst_ip"`
	SrcPort      uint16            `json:"src_port"`
	DstPort      uint16            `json:"dst_port"`
	Operation    string            `json:"operation,omitempty"`
	Host         string            `json:"host,omitempty"`
	Resource     string            `json:"resource,omitempty"`
	Username     string            `json:"username,omitempty"`
	Status       string            `json:"status,omitempty"`
	Summary      string            `json:"summary,omitempty"`
	Encrypted    bool              `json:"encrypted,omitempty"`
	FromAnalysis bool              `json:"from_analysis,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}
