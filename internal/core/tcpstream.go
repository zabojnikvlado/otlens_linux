package core

import "time"

// TCPStreamChunk contains contiguous application bytes reconstructed from one
// direction of a TCP connection. Src/Dst describe the direction of these bytes.
type TCPStreamChunk struct {
	ConnectionID string
	SrcIP        string
	DstIP        string
	SrcPort      uint16
	DstPort      uint16
	Timestamp    time.Time
	Data         []byte
	Midstream    bool
	Gapped       bool
	GapBefore    uint32
	Overlap      bool
	Protocol     string
}

// TCPStreamEvent reports lifecycle and quality changes for a reconstructed TCP stream.
type TCPStreamEvent struct {
	ConnectionID string
	Type         string
	Reason       string
	Timestamp    time.Time
	Buffered     int
	Protocol     string
}

// TCPReassemblyStats is a lock-free snapshot suitable for diagnostics and metrics.
type TCPReassemblyStats struct {
	Enabled               bool   `json:"enabled"`
	Running               bool   `json:"running"`
	ActiveConnections     int64  `json:"active_connections"`
	ConnectionsOpened     uint64 `json:"connections_opened_total"`
	ConnectionsClosed     uint64 `json:"connections_closed_total"`
	BufferedBytes         int64  `json:"buffered_bytes"`
	SegmentsSeen          uint64 `json:"segments_seen"`
	BytesSeen             uint64 `json:"bytes_seen"`
	ChunksEmitted         uint64 `json:"chunks_emitted"`
	BytesEmitted          uint64 `json:"bytes_emitted"`
	OutOfOrderSegments    uint64 `json:"out_of_order_segments"`
	RetransmittedBytes    uint64 `json:"retransmitted_bytes"`
	OverlapSegments       uint64 `json:"overlap_segments"`
	OverlapConflicts      uint64 `json:"overlap_conflicts"`
	GapRecoveries         uint64 `json:"gap_recoveries"`
	EvictedConnections    uint64 `json:"evicted_connections"`
	DroppedSegments       uint64 `json:"dropped_segments"`
	PacketEventsReceived  uint64 `json:"packet_events_received"`
	TCPPacketsReceived    uint64 `json:"tcp_packets_received"`
	TypeAssertionFailures uint64 `json:"type_assertion_failures"`
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
