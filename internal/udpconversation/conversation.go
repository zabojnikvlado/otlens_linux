package udpconversation

import "time"

// Conversation contains UDP metadata and counters only. Datagram payloads are
// deliberately never retained, which keeps memory usage bounded independently
// of packet size.
type Conversation struct {
	ID       string
	FlowID   string
	SensorID string
	Key      Key
	Protocol string

	StartedAt  time.Time
	LastSeenAt time.Time

	Packets uint64
	Bytes   uint64

	// DirectionA is the number of packets from endpoint A to endpoint B.
	// DirectionB is the number in the reverse direction.
	DirectionA uint64
	DirectionB uint64

	DirectionABytes uint64
	DirectionBBytes uint64

	lastDirection Direction
	lastPacketAt  time.Time
}
