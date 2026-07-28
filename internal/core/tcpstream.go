package core

import "time"

// TCPStreamChunk contains contiguous application bytes reconstructed from one
// direction of a TCP connection. Src/Dst describe the direction of these bytes.
type TCPStreamChunk struct {
	ConnectionID       string
	SrcIP              string
	DstIP              string
	SrcPort            uint16
	DstPort            uint16
	Timestamp          time.Time
	Data               []byte
	Midstream          bool
	Gapped             bool
	GapBefore          uint32
	Overlap            bool
	Protocol           string
	ProtocolConfidence uint8
	Asymmetric         bool
}

// TCPStreamEvent reports lifecycle and quality changes for a reconstructed TCP stream.
type TCPStreamEvent struct {
	ConnectionID string    `json:"connection_id"`
	Type         string    `json:"type"`
	Reason       string    `json:"reason,omitempty"`
	State        string    `json:"state,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	SrcIP        string    `json:"src_ip,omitempty"`
	DstIP        string    `json:"dst_ip,omitempty"`
	SrcPort      uint16    `json:"src_port,omitempty"`
	DstPort      uint16    `json:"dst_port,omitempty"`
	Buffered     int       `json:"buffered"`
	Protocol     string    `json:"protocol,omitempty"`
	PacketsA2B   uint64    `json:"packets_a_to_b"`
	PacketsB2A   uint64    `json:"packets_b_to_a"`
	BytesA2B     uint64    `json:"bytes_a_to_b"`
	BytesB2A     uint64    `json:"bytes_b_to_a"`
}

// TCPReassemblyStats is a lock-free snapshot suitable for diagnostics and metrics.
type TCPReassemblyStats struct {
	Enabled                  bool    `json:"enabled"`
	Running                  bool    `json:"running"`
	ActiveConnections        int64   `json:"active_connections"`
	ConnectionsOpened        uint64  `json:"connections_opened_total"`
	ConnectionsClosed        uint64  `json:"connections_closed_total"`
	BufferedBytes            int64   `json:"buffered_bytes"`
	SegmentsSeen             uint64  `json:"segments_seen"`
	BytesSeen                uint64  `json:"bytes_seen"`
	ChunksEmitted            uint64  `json:"chunks_emitted"`
	BytesEmitted             uint64  `json:"bytes_emitted"`
	OutOfOrderSegments       uint64  `json:"out_of_order_segments"`
	RetransmittedBytes       uint64  `json:"retransmitted_bytes"`
	OverlapSegments          uint64  `json:"overlap_segments"`
	OverlapConflicts         uint64  `json:"overlap_conflicts"`
	GapRecoveries            uint64  `json:"gap_recoveries"`
	EvictedConnections       uint64  `json:"evicted_connections"`
	DroppedSegments          uint64  `json:"dropped_segments"`
	DuplicateSegments        uint64  `json:"duplicate_segments"`
	TimedOutConnections      uint64  `json:"timed_out_connections"`
	ResetConnections         uint64  `json:"reset_connections"`
	PeakActiveConnections    int64   `json:"peak_active_connections"`
	BufferedBytesHighWater   int64   `json:"buffered_bytes_high_water"`
	AverageDurationMS        float64 `json:"average_connection_duration_ms"`
	MaxConnectionsPerIPDrops uint64  `json:"max_connections_per_ip_drops"`
	MidstreamConnections     uint64  `json:"midstream_connections"`
	AsymmetricConnections    uint64  `json:"asymmetric_connections"`
	LowConfidenceChunks      uint64  `json:"low_confidence_chunks"`
}

// DCERPCFragment is an SMB named-pipe payload handed to the DCE/RPC parser.
type DCERPCFragment struct {
	Timestamp    time.Time
	ConnectionID string
	ClientIP     string
	ServerIP     string
	NamedPipe    string
	Data         []byte
}
