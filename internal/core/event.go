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

	// EventAlertRaised carries a *detect.Alert — published by
	// internal/detect every time a genuinely NEW alert is created
	// (not on every repeat-occurrence Count/LastSeen bump of an
	// already-existing one — see each raise*/handle* function in
	// internal/detect). internal/export consumes this to forward new
	// findings to an external server as they happen. The payload is
	// the concrete *detect.Alert type rather than a core-level
	// wrapper struct: unlike BaselineComplete/UnconfirmedAsset/
	// OutOfRangeValue, this event only flows in one direction
	// (detect -> export), so there's no mutual-import problem to
	// avoid by keeping the payload shape in core — internal/api
	// already imports internal/detect directly for the same Alert
	// type, so this isn't introducing a new kind of dependency.
	EventAlertRaised EventType = "alert.raised"

	// EventAuditAction carries an AuditEntry — published by
	// internal/api whenever an admin/state-changing action happens
	// (asset confirm/delete, alert approve/confirm, capture stop/
	// start, pcap analyze, database wipe) or authentication fails.
	// internal/audit consumes this to write the durable audit trail
	// (a rotated file, and optionally forwarded to an external server
	// the same way alerts are — see internal/export). Kept separate
	// from EventAlertRaised: an audit entry is a record of an action
	// taken through the API, not a detection finding, even though
	// both end up exported to the same place.
	EventAuditAction EventType = "audit.action"
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

// AuditEntry is the payload for EventAuditAction — one record of an
// action taken through the API (or an attempt that failed
// authentication). Lives here in core rather than internal/api (the
// producer), same reasoning as the other payload types above:
// internal/audit (the consumer) shouldn't need to import
// internal/api just for this one type.
type AuditEntry struct {
	Timestamp time.Time

	// Action identifies what happened, e.g. "asset.confirm",
	// "admin.wipe", "auth.failed" — see internal/audit's doc comment
	// for the full list.
	Action string

	SourceIP string

	// User is the authenticated identity that performed the action —
	// currently always the single configured api.username (Basic
	// Auth has no concept of separate per-person accounts yet), or
	// "" if api.username/password aren't configured at all (API
	// running unauthenticated). Recorded now, even though it can
	// only ever hold one value today, so a future move to real
	// per-user accounts doesn't need to touch the audit trail's
	// shape — only how this field gets populated.
	User string

	// Success distinguishes a completed action from a failed
	// authentication attempt (Action: "auth.failed") — true for
	// every other Action, since a request that failed authorization
	// never reaches the handler that would publish one of those in
	// the first place.
	Success bool

	// Details holds action-specific extra context, e.g. {"mac":
	// "aa:bb:..."} for asset.confirm or {"filename": "..."} for
	// admin.capture.analyze. Deliberately map[string]string rather
	// than `any` — keeps every audit entry trivially JSON-
	// serializable without surprises, at the cost of the caller
	// having to stringify non-string details itself.
	Details map[string]string
}

// Event is the envelope every engine publishes and subscribes to.
// Data's concrete type depends on Type — see the EventType constants
// above for which Go type to expect and type-assert to.
type Event struct {
	Type EventType

	Timestamp time.Time

	Data any
}
