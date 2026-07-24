// Package core holds the types shared across every engine —
// the event bus itself, the raw captured frame, the parsed packet,
// and the event envelope that carries them between engines. Nothing
// in this package knows about capture, parsing, or any specific
// protocol; it's deliberately the "lowest common denominator" that
// every other internal package depends on, so it must never import
// any of them back.
package core

import "time"

// EventType identifies what kind of data an Event carries, so
// subscribers can filter to just the events they care about via
// EventBus.Subscribe.
type EventType string

const (
	// EventPacketCaptured carries a core.RawFrame — the raw bytes
	// straight off the wire, before any parsing.
	EventPacketCaptured EventType = "packet.captured"

	// EventPacketParsed carries a core.Packet — the decoded
	// Ethernet/IP/TCP/UDP/ARP fields produced by internal/parser.
	EventPacketParsed EventType = "packet.parsed"

	// EventConnectionSeen is reserved for a future connection-level
	// (as opposed to per-packet) event; not yet published anywhere.
	EventConnectionSeen EventType = "connection.seen"

	// EventICSMessage carries an ics.Message — a decoded Modbus/S7comm
	// application-layer message produced by internal/ics.
	EventICSMessage EventType = "ics.message"

	// EventHostnameSeen carries a hostname.Observation — a MAC-to-
	// hostname mapping learned from mDNS or DHCP traffic, produced by
	// internal/hostname and consumed by internal/asset to enrich an
	// already-discovered asset's Hostname field.
	EventHostnameSeen EventType = "hostname.seen"

	// EventIPFIXFlow carries an ipfix.FlowRecord — a decoded flow
	// summary exported by a router/switch/probe, produced by
	// internal/ipfix when capture.mode is "ipfix" instead of
	// "npcap". Consumed by internal/flow to update flow tracking the
	// same way it would from live packets, via
	// flow.Engine.ApplyExternalDelta.
	EventIPFIXFlow EventType = "ipfix.flow"

	// EventBaselineLearningComplete carries a BaselineComplete —
	// published exactly once by internal/detect when baseline
	// learning finishes, with every device MAC observed during that
	// window. internal/asset uses it to decide whether a device
	// discovered afterward is already known (confirmed) or genuinely
	// new (see EventAssetUnconfirmed).
	EventBaselineLearningComplete EventType = "baseline.learning_complete"

	// EventAssetUnconfirmed carries an UnconfirmedAsset — published
	// by internal/asset the moment it discovers a device after
	// baseline learning completed that wasn't part of the learned
	// set. internal/detect consumes this to raise a "new_asset"
	// Alert; internal/topology renders the device in red until it's
	// confirmed via POST /assets/:mac/confirm.
	EventAssetUnconfirmed EventType = "asset.unconfirmed"

	// EventValueOutOfRange carries an OutOfRangeValue — published by
	// internal/store when an OT variable's value, observed after
	// baseline learning completed, falls outside the [MinValue,
	// MaxValue] range that same variable was seen to occupy during
	// learning (see store.Tag.MinValue/MaxValue). internal/detect
	// consumes this to raise a "value_out_of_range" Alert — keeping
	// the actual anomaly detection/alerting logic in internal/detect,
	// same as every other alert type, rather than internal/store
	// (whose job is tracking/persisting values, not deciding what's
	// alert-worthy) raising alerts directly.
	EventValueOutOfRange EventType = "value.out_of_range"
)

// BaselineComplete is the payload for EventBaselineLearningComplete.
// Defined here in core (rather than in internal/detect, the
// publisher) specifically so internal/asset — the consumer — doesn't
// have to import internal/detect: internal/detect also needs to
// consume internal/asset's UnconfirmedAsset below, and having each
// package import the other's event-payload type would be an import
// cycle. Both payload types live here instead, the same way
// core.Packet does for internal/parser's output.
type BaselineComplete struct {
	LearnedAssetMACs []string
}

// UnconfirmedAsset is the payload for EventAssetUnconfirmed — see
// BaselineComplete's doc comment for why this lives in core rather
// than in internal/asset.
type UnconfirmedAsset struct {
	MAC string
	IP  string
}

// OutOfRangeValue is the payload for EventValueOutOfRange — see that
// event's doc comment. Lives here in core, same reasoning as
// BaselineComplete/UnconfirmedAsset: internal/detect (the consumer)
// shouldn't need to import internal/store (the producer) just for
// this one payload type.
type OutOfRangeValue struct {
	TagKey string

	DeviceIP     string
	DevicePort   uint16
	AddressSpace string
	Address      uint32

	MinValue any
	MaxValue any
	Value    any
}


// Event is the envelope published through the in-process EventBus.
type Event struct {
	Type EventType
	Timestamp time.Time
	Data any
}
