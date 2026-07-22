// Package store implements the data model for how OTLens retains OT
// process data long-term — see engine.go for the Engine that
// actually subscribes/dedupes/persists using this model.
//
// # Storage design notes (Nozomi Guardian-style retention)
//
// The naive approach — append every ics.Message (every single
// Modbus/S7 poll) to disk — does not scale for OT traffic. A single
// PLC polled every 100ms for 50 registers produces ~500 messages/sec
// from one device alone, nearly all of them reporting the exact same
// value as last time. Nozomi (and Zeek/Suricata-derived ICS
// monitors) avoid this with three techniques, all reflected below:
//
//  1. Identity over history: track one row per *variable* (a
//     specific address/register on a specific device), not one row
//     per poll. The row is updated in place on every poll.
//  2. Counters instead of rows: PollCount/ChangeCount capture "how
//     often was this touched" and "how often did the value actually
//     change" without storing each occurrence.
//  3. Value-change events are the only append-only data: a new
//     historical record is only written when LastValue actually
//     changes, not on every read. Routine polling therefore costs
//     O(1) storage (just updates counters on the existing Tag row);
//     only genuine state changes and control operations (writes,
//     PLC Stop/Start) grow storage over time, and those are rare and
//     high-signal by nature in a stable OT process.
//
// A Tag's identity (see Tag.Key) intentionally excludes any raw
// value or timestamp, so the same variable always maps to the same
// row no matter how many times it's polled — this is what makes
// technique #1 possible.
package store

import "time"

// Tag represents a single OT process variable observed on the wire:
// e.g. "Modbus holding register 40001 on unit 3 at 10.0.0.5:502", or
// "S7 DB1.DBX0.0 read from 10.0.0.10:102". It is the long-term,
// storage-efficient counterpart to the high-volume, ephemeral
// ics.Message events emitted per packet.
type Tag struct {
	// Key uniquely identifies this variable/address across polls —
	// see BuildKey. It deliberately contains no value or timestamp,
	// so repeated polls of the same address always resolve to the
	// same Tag rather than creating a new row each time.
	Key string

	Protocol string // "Modbus" | "S7comm"

	// Endpoint identifies the device holding this variable — the
	// side of the conversation that is the PLC/RTU/controller, not
	// the polling engineering workstation/HMI. Resolved from
	// ics.Message.IsResponse in engine.go: for request messages this
	// is the DstIP:DstPort; for responses it is Src.
	DeviceIP   string
	DevicePort uint16

	UnitID uint8 // Modbus unit/slave ID; 0 if not applicable

	// AddressSpace + Address identify the variable within the
	// device, e.g. AddressSpace="HoldingRegister" Address=40001, or
	// AddressSpace="DB1" Address=0 for an S7 data block offset.
	AddressSpace string
	Address      uint32

	// Operation is "Read" or "Write" — writes are always kept as
	// individual events regardless of dedup (see ControlEvent
	// below), since a write is a control action, not a passive
	// observation.
	Operation string

	// LastValue is the most recently observed value for this
	// variable, kept as a generic scalar/slice since width varies by
	// protocol and register type (bit, 16-bit register, etc.).
	// Storage only needs to retain this single latest value, not a
	// running log of every read — that's the core space saving.
	LastValue any

	// PreviousValue + LastChangeAt describe the most recent value
	// transition directly on the Tag row itself — "what was it
	// before, and when did it change" — so a client asking about one
	// variable gets that in the same place as its current value,
	// without having to filter the separate ValueChange history by
	// TagKey. The full change history still lives in ValueChange for
	// trending; these two fields are just the latest entry, kept
	// close to LastValue for O(1) lookup.
	PreviousValue any
	LastChangeAt  time.Time

	// MinValue/MaxValue are the smallest/largest numeric value
	// observed for this variable *during baseline learning only* —
	// see store.Engine.updateTag. Once learning completes they
	// freeze at whatever range was learned; a later value falling
	// outside [MinValue, MaxValue] triggers a "value_out_of_range"
	// Alert (core.EventValueOutOfRange -> internal/detect) instead of
	// silently updating the range further. nil for non-numeric values
	// (coils/bits — "min/max" isn't a meaningful concept for an
	// ON/OFF flag) or for a tag that was never observed during
	// learning at all (nothing to range-check against, so it's
	// simply never flagged by this mechanism).
	MinValue any
	MaxValue any

	FirstSeen time.Time
	LastSeen  time.Time

	// PollCount counts every observation of this tag, whether or not
	// the value changed. ChangeCount counts only the subset where
	// LastValue differed from the previous value. A tag with a huge
	// PollCount but ChangeCount of 0 or 1 is a static setpoint or
	// slow-changing measurement — normal. A high ChangeCount relative
	// to PollCount on what's expected to be a stable register is
	// itself a useful anomaly signal for the later rule/baseline
	// engine.
	PollCount   uint64
	ChangeCount uint64

	// FromAnalysis — see asset.Asset's field of the same name for the
	// full explanation. Same semantics here.
	FromAnalysis bool
}

// ValueChange is the append-only record created only when a Tag's
// value actually changes (technique #3 above). This — not the raw
// per-packet messages — is the historical trend data OTLens keeps
// long-term for a given variable.
type ValueChange struct {
	TagKey string

	OldValue any
	NewValue any

	Timestamp time.Time

	// FromAnalysis — see asset.Asset's field of the same name for the
	// full explanation. Unlike Asset/Flow/Tag's mutable "current
	// state", this never needs to be cleared later: a ValueChange is
	// a fixed point-in-time historical record, permanently true or
	// permanently false from the moment it's created.
	FromAnalysis bool
}

// ControlEvent is the append-only record for operations that are
// inherently significant regardless of whether any monitored value
// changed as a result: writes to any address, and protocol-level
// control functions (S7 PLCStop/PLCControl, Modbus writes). These
// are never deduplicated away — each occurrence is retained, because
// each one is a discrete action taken against the process, not a
// passive observation of state like a poll.
type ControlEvent struct {
	TagKey string

	Protocol     string
	FunctionName string

	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16

	SecurityRelevant bool

	Timestamp time.Time

	// FromAnalysis — see ValueChange's field of the same name.
	FromAnalysis bool
}
