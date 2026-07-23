package ics

import (
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// Message is a normalized, decoded OT/ICS application-layer message.
// It deliberately holds small structured fields instead of raw
// payload bytes: the whole point of decoding Modbus/S7comm/etc. is
// that downstream storage only needs to keep a handful of scalars
// per message (protocol, function, unit ID...) rather than the full
// packet capture — see the storage design notes in internal/store.
type Message struct {
	Timestamp time.Time

	// FromAnalysis — see core.RawFrame's doc comment. Propagated
	// straight through by newMessage.
	FromAnalysis bool

	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16

	Protocol string // "Modbus", "S7comm"

	FunctionCode uint8
	FunctionName string

	IsException bool
	IsResponse  bool

	UnitID uint8 // Modbus unit/slave identifier; 0 if not applicable

	// Details carries a handful of protocol-specific extra fields
	// (e.g. register address/quantity for Modbus, ROSCTR type for
	// S7comm). Kept as a small generic map on purpose so each new
	// protocol parser doesn't need its own top-level Message type —
	// but it must stay small: a handful of scalars, never payload
	// bytes or bulk data.
	Details map[string]any
}

// newMessage builds a Message pre-filled with the fields shared by
// every OT protocol (endpoints, ports, timestamp), so each parser
// only has to fill in what's specific to it.
func newMessage(packet core.Packet, protocol string) Message {

	return Message{
		Timestamp: packet.Timestamp,

		FromAnalysis: packet.FromAnalysis,

		SrcIP:   packet.SrcIP,
		DstIP:   packet.DstIP,
		SrcPort: packet.SrcPort,
		DstPort: packet.DstPort,

		Protocol: protocol,

		Details: make(map[string]any),
	}
}
