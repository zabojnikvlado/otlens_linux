// Engine subscribes to core.EventICSMessage and implements the
// dedup/storage logic described in model.go's package doc comment.
package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/ics"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"go.uber.org/zap"
)

// defaultMaxValueChanges/defaultMaxControlEvents are the fallback
// caps used when NewEngine is given a zero or negative value —
// configurable via store.maxvaluechanges/store.maxcontrolevents in
// config.yaml.
const (
	defaultMaxValueChanges  = 1000
	defaultMaxControlEvents = 1000
)

// Engine implements the dedup storage model described in model.go:
// one Tag row per variable, updated in place on every poll, with
// only genuine value changes and control actions kept as append-only
// history. This is what keeps OT monitoring storage bounded — a busy
// polling loop grows PollCount on an existing row instead of adding
// a new one every cycle.
type Engine struct {
	mutex sync.RWMutex

	tags map[string]*Tag

	valueChanges    []ValueChange
	maxValueChanges int

	controlEvents    []ControlEvent
	maxControlEvents int

	eventBus *core.EventBus

	// learningActive gates MinValue/MaxValue tracking in updateTag —
	// true until core.EventBaselineLearningComplete is received (see
	// startBaselineWatch), mirroring asset.Engine's
	// baselineEstablished/knownFromBaseline. Starts true rather than
	// false so a value seen before that event ever arrives (e.g.
	// while baseline.enabled is true and learning is still genuinely
	// in progress) contributes to the learned range instead of
	// immediately being flagged out-of-range against an empty one.
	learningActive bool
}

func NewEngine(maxValueChanges, maxControlEvents int) *Engine {

	if maxValueChanges <= 0 {
		maxValueChanges = defaultMaxValueChanges
	}

	if maxControlEvents <= 0 {
		maxControlEvents = defaultMaxControlEvents
	}

	return &Engine{
		tags: make(map[string]*Tag),

		maxValueChanges:  maxValueChanges,
		maxControlEvents: maxControlEvents,

		learningActive: true,
	}
}

func (e *Engine) Start(bus *core.EventBus) {

	logger.Log.Info(
		"Store engine started",
	)

	e.eventBus = bus

	e.startICSWatch(bus)
	e.startBaselineWatch(bus)
}

func (e *Engine) startICSWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventICSMessage)

	go func() {

		for event := range ch {

			msg, ok := event.Data.(ics.Message)

			if !ok {
				continue
			}

			e.handle(msg)

		}

	}()

}

// startBaselineWatch consumes core.EventBaselineLearningComplete
// (published once by internal/detect — see baseline.go) to know when
// to stop treating incoming values as baseline-learning material and
// start range-checking them instead — see updateTag's MinValue/
// MaxValue handling and learningActive's doc comment.
func (e *Engine) startBaselineWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventBaselineLearningComplete)

	go func() {

		for range ch {

			e.mutex.Lock()
			e.learningActive = false
			e.mutex.Unlock()

		}

	}()

}

func (e *Engine) handle(msg ics.Message) {

	addressSpace, startAddress, ok := extractAddress(msg)

	if !ok {

		// No decodable variable identity (e.g. a bare Ack) — nothing
		// to tag, but still worth recording individually if the ics
		// parser already flagged it as security-relevant.
		if isSecurityRelevant(msg) {
			e.recordControlEvent(msg, "")
		}

		return
	}

	// The device (PLC/RTU) is whichever side did not initiate the
	// request: Dst for requests, Src for responses.
	deviceIP, devicePort := msg.DstIP, msg.DstPort

	if msg.IsResponse {
		deviceIP, devicePort = msg.SrcIP, msg.SrcPort
	}

	operation := "Read"

	if isWriteOperation(msg) {
		operation = "Write"
	}

	rawValue, hasValue := msg.Details["value"]

	var quantity uint16

	if q, ok := msg.Details["quantity"].(uint16); ok {
		quantity = q
	}

	// A multi-register/coil read response or WriteMultiple* request
	// covers a whole range of addresses in one message, not just
	// startAddress — decodeModbusData already decoded each individual
	// value (see internal/ics/modbus.go), but without this expansion
	// step every one of those values would collapse into a single Tag
	// keyed on just the starting address, with the *entire* block
	// dumped into that one Tag's LastValue as a giant list. That's
	// both unreadable (a "Coil 8" row showing hundreds of values) and
	// actively harmful for change tracking: comparing whole blocks as
	// one opaque blob makes nearly every poll look like "the value
	// changed" (any single bit differing flips the whole block),
	// flooding the shared ValueChange history cap with noise and
	// evicting genuinely useful history for other tags. Expanding
	// here gives every individual register/coil its own Tag row and
	// its own honest change history, matching the "one row per
	// variable" design the rest of this package already follows.
	addresses, values, expandedHasValue := expandAddressRange(startAddress, rawValue, hasValue, quantity)

	now := msg.Timestamp

	var lastKey string

	for i, addr := range addresses {

		key := BuildKey(
			msg.Protocol,
			deviceIP,
			devicePort,
			msg.UnitID,
			addressSpace,
			addr,
		)

		lastKey = key

		var value any

		if expandedHasValue {
			value = values[i]
		}

		oldValue, valueChanged := e.updateTag(
			key,
			msg,
			deviceIP,
			devicePort,
			addressSpace,
			addr,
			operation,
			value,
			expandedHasValue,
			now,
		)

		if valueChanged {

			e.appendValueChange(
				ValueChange{
					TagKey:    key,
					OldValue:  oldValue,
					NewValue:  value,
					Timestamp: now,

					FromAnalysis: msg.FromAnalysis,
				},
			)
		}
	}

	// Writes and security-relevant control functions are recorded as
	// one event per message (not one per expanded address — a single
	// WriteMultipleCoils command is one discrete action, even though
	// it's now tracked against many individual Tag rows above),
	// linked to the first address touched.
	if operation == "Write" || isSecurityRelevant(msg) {
		e.recordControlEvent(msg, lastKey)
	}
}

// expandAddressRange turns a possibly multi-value observation
// (a []uint16 or []bool decoded from a multi-register/coil
// read/write — see internal/ics/modbus.go) into one (address, scalar
// value) pair per element, starting at startAddress. A plain
// single-value observation (the common case: single register/coil
// reads and writes) passes through unchanged as exactly one pair.
//
// quantity, when known (from the Modbus request's own quantity
// field), trims the expansion to that many entries — coil bit
// decoding always rounds up to a full byte, so a request for e.g. 5
// coils can carry up to 3 trailing padding bits with no real address
// of their own; quantity is what says where the real data actually
// ends.
func expandAddressRange(
	startAddress uint32,
	value any,
	hasValue bool,
	quantity uint16,
) ([]uint32, []any, bool) {

	if !hasValue {
		return []uint32{startAddress}, nil, false
	}

	switch v := value.(type) {

	case []uint16:

		n := len(v)

		if quantity > 0 && int(quantity) < n {
			n = int(quantity)
		}

		addresses := make([]uint32, n)
		values := make([]any, n)

		for i := 0; i < n; i++ {
			addresses[i] = startAddress + uint32(i)
			values[i] = v[i]
		}

		return addresses, values, true

	case []bool:

		n := len(v)

		if quantity > 0 && int(quantity) < n {
			n = int(quantity)
		}

		addresses := make([]uint32, n)
		values := make([]any, n)

		for i := 0; i < n; i++ {
			addresses[i] = startAddress + uint32(i)
			values[i] = v[i]
		}

		return addresses, values, true

	default:

		// Single scalar value (uint16 from a single register/coil
		// write, etc.) — nothing to expand.
		return []uint32{startAddress}, []any{value}, true
	}
}

// updateTag creates the Tag on first sight or updates the existing
// one in place, and reports whether the observed value differs from
// what was previously stored.
func (e *Engine) updateTag(
	key string,
	msg ics.Message,
	deviceIP string,
	devicePort uint16,
	addressSpace string,
	address uint32,
	operation string,
	value any,
	hasValue bool,
	now time.Time,
) (oldValue any, changed bool) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	tag, exists := e.tags[key]

	if !exists {

		tag = &Tag{
			Key: key,

			Protocol: msg.Protocol,

			DeviceIP:   deviceIP,
			DevicePort: devicePort,

			UnitID: msg.UnitID,

			AddressSpace: addressSpace,
			Address:      address,

			Operation: operation,

			FirstSeen: now,

			FromAnalysis: msg.FromAnalysis,
		}

		e.tags[key] = tag

		logger.Log.Info(
			"OT variable discovered",
			zap.String("protocol", msg.Protocol),
			zap.String("address_space", addressSpace),
		)

	} else if !msg.FromAnalysis {

		// A live sighting of an already-known tag permanently clears
		// FromAnalysis — same reasoning as asset.Engine.Update.
		tag.FromAnalysis = false
	}

	tag.LastSeen = now
	tag.PollCount++

	// A tag can legitimately be both read and written over its
	// lifetime (e.g. a setpoint); keep the most recently observed
	// operation rather than trying to represent both.
	tag.Operation = operation

	if hasValue {

		oldValue = tag.LastValue

		if exists && oldValue != nil && !valuesEqual(oldValue, value) {

			changed = true
			tag.ChangeCount++

			tag.PreviousValue = oldValue
			tag.LastChangeAt = now
		}

		tag.LastValue = value

		if numeric, ok := numericValue(value); ok {

			if e.learningActive {

				// Still learning — expand the range to include this
				// value (the first numeric sighting bootstraps both
				// ends at once, since a nil MinValue/MaxValue always
				// fails the numericValue check below and loses the
				// comparison).
				if minNumeric, minOK := numericValue(tag.MinValue); !minOK || numeric < minNumeric {
					tag.MinValue = value
				}

				if maxNumeric, maxOK := numericValue(tag.MaxValue); !maxOK || numeric > maxNumeric {
					tag.MaxValue = value
				}

			} else {

				// Learning is done — if this tag has a learned range,
				// check whether the new value falls outside it. A tag
				// with no learned range (never observed during
				// learning at all) has nothing to compare against, so
				// it's simply never flagged by this mechanism.
				minNumeric, minOK := numericValue(tag.MinValue)
				maxNumeric, maxOK := numericValue(tag.MaxValue)

				if minOK && maxOK && (numeric < minNumeric || numeric > maxNumeric) && e.eventBus != nil {

					e.eventBus.Publish(
						core.Event{
							Type: core.EventValueOutOfRange,
							Data: core.OutOfRangeValue{
								TagKey: key,

								DeviceIP:     deviceIP,
								DevicePort:   devicePort,
								AddressSpace: addressSpace,
								Address:      address,

								MinValue: tag.MinValue,
								MaxValue: tag.MaxValue,
								Value:    value,
							},
						},
					)
				}
			}
		}
	}

	return oldValue, changed
}

// numericValue converts a decoded Tag value into a float64 for
// MinValue/MaxValue tracking and range comparison, when it's a type
// that makes the comparison meaningful. bool (coils/discrete
// inputs — "min/max" isn't a meaningful concept for an ON/OFF flag)
// and slices (a raw multi-value read that never got decomposed — see
// expandAddressRange, should be rare in practice after that
// decomposition) are deliberately excluded, returning ok=false. Also
// handles float64, which is what a uint8/16/32 value comes back as
// after a JSON persist/restore round-trip (see valuesEqual's doc
// comment for the same issue affecting LastValue) — without this,
// every tag's learned range would look unusable immediately after
// the first restart.
func numericValue(value any) (float64, bool) {

	switch v := value.(type) {

	case uint8:
		return float64(v), true

	case uint16:
		return float64(v), true

	case uint32:
		return float64(v), true

	case float64:
		return v, true

	default:
		return 0, false
	}
}

// valuesEqual compares two Tag values for equality using their
// string representation rather than Go's == operator. Two reasons:
//   - After a persist/restore round-trip through JSON, a numeric
//     value that started as e.g. uint16 comes back as float64 (JSON
//     has one number type). Raw `==` would then report every
//     previously-known tag as "changed" on the very first poll after
//     a restart, purely from the type mismatch, not a real change.
//   - Go's == panics at runtime if the dynamic type inside an `any`
//     is non-comparable (e.g. a slice) — fmt.Sprint never does.
func valuesEqual(a, b any) bool {
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func (e *Engine) appendValueChange(vc ValueChange) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.valueChanges = appendBounded(e.valueChanges, vc, e.maxValueChanges)
}

func (e *Engine) recordControlEvent(msg ics.Message, tagKey string) {

	securityRelevant := isSecurityRelevant(msg)

	event := ControlEvent{
		TagKey: tagKey,

		Protocol:     msg.Protocol,
		FunctionName: msg.FunctionName,

		SrcIP:   msg.SrcIP,
		DstIP:   msg.DstIP,
		SrcPort: msg.SrcPort,
		DstPort: msg.DstPort,

		SecurityRelevant: securityRelevant,

		Timestamp: msg.Timestamp,

		FromAnalysis: msg.FromAnalysis,
	}

	if securityRelevant {

		logger.Log.Warn(
			"Security-relevant OT control operation observed",
			zap.String("protocol", msg.Protocol),
			zap.String("function", msg.FunctionName),
			zap.String("src_ip", msg.SrcIP),
			zap.String("dst_ip", msg.DstIP),
		)
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.controlEvents = appendBounded(e.controlEvents, event, e.maxControlEvents)
}

// appendBounded appends item to s, dropping the oldest entries once
// the length exceeds max. This is a count-based safety cap so a
// runaway burst can't grow memory unbounded between prune passes;
// the actual retention policy is time-based — see PruneHistory.
func appendBounded[T any](s []T, item T, max int) []T {

	s = append(s, item)

	if len(s) > max {
		s = s[len(s)-max:]
	}

	return s
}

// filterRecent returns only the items that are either at or after
// cutoff (per tsFn), or that protectedFn reports as exempt from
// age-based pruning entirely — see ValueChange.FromAnalysis's doc
// comment for why a manually-analyzed pcap's history needs that
// exemption. Preserves order.
func filterRecent[T any](items []T, cutoff time.Time, tsFn func(T) time.Time, protectedFn func(T) bool) []T {

	kept := make([]T, 0, len(items))

	for _, item := range items {

		if protectedFn(item) || !tsFn(item).Before(cutoff) {
			kept = append(kept, item)
		}
	}

	return kept
}

// CountTags returns the number of tracked variables.
func (e *Engine) CountTags() int {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return len(e.tags)
}

// GetTags returns a snapshot of every tracked tag. Each element is a
// shallow copy, not a pointer into the live map — see
// asset.Engine.GetAll's doc comment for why that matters in general.
// It matters more here than anywhere else: LastValue/MinValue/
// MaxValue/PreviousValue are `any`, and a Go interface value is
// internally a two-word pair (type, data) — a data race on a write
// to one of these (updateTag reassigning tag.LastValue while this
// runs concurrently, unguarded, on a caller's copy) could in
// principle observe a torn read pairing a stale type word with a
// fresh data word, not just stale-but-consistent data. A shallow
// copy of the whole struct is enough (nothing here is a slice/map
// mutated in place after assignment — LastValue etc. are always
// wholesale-reassigned, never element-mutated), but skipping the
// copy entirely would leave exactly this field type exposed.
func (e *Engine) GetTags() []*Tag {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]*Tag, 0, len(e.tags))

	for _, tag := range e.tags {

		clone := *tag

		result = append(
			result,
			&clone,
		)

	}

	return result
}

// GetValueChanges returns a snapshot of the retained value-change
// history (most recent defaultMaxValueChanges entries).
func (e *Engine) GetValueChanges() []ValueChange {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]ValueChange, len(e.valueChanges))
	copy(result, e.valueChanges)

	return result
}

// GetControlEvents returns a snapshot of the retained control-event
// history (most recent defaultMaxControlEvents entries).
func (e *Engine) GetControlEvents() []ControlEvent {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]ControlEvent, len(e.controlEvents))
	copy(result, e.controlEvents)

	return result
}

// RestoreTags rehydrates the tag map from previously persisted Tags,
// e.g. at startup after loading from disk.
func (e *Engine) RestoreTags(tags []*Tag) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	for _, tag := range tags {
		e.tags[tag.Key] = tag
	}
}

// RestoreValueChanges replaces the in-memory value-change history
// with a previously persisted one.
func (e *Engine) RestoreValueChanges(changes []ValueChange) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.valueChanges = changes
}

// RestoreControlEvents replaces the in-memory control-event history
// with a previously persisted one.
func (e *Engine) RestoreControlEvents(events []ControlEvent) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.controlEvents = events
}

// PruneTags removes variables not seen within maxAge — e.g. a
// register on a device that was decommissioned or moved off the
// network long ago. Returns the number removed.
func (e *Engine) PruneTags(maxAge time.Duration) int {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)

	removed := 0

	for key, tag := range e.tags {

		if tag.FromAnalysis {
			continue
		}

		if tag.LastSeen.Before(cutoff) {
			delete(e.tags, key)
			removed++
		}
	}

	return removed
}

// Clear removes every tracked tag along with its value-change and
// control-event history — the admin UI's "wipe database" action.
// Unlike PruneTags, this isn't selective; it's a full
// reset.
func (e *Engine) Clear() {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.tags = make(map[string]*Tag)
	e.valueChanges = nil
	e.controlEvents = nil
}

// PruneHistory drops value-change and control-event entries older
// than maxAge. This is on top of the count-based appendBounded cap —
// that cap protects against a single burst ballooning memory before
// the next prune pass runs; this is the actual configured retention
// window.
//
// Entries with FromAnalysis set are exempt regardless of age — same
// reasoning as PruneTags/asset.Engine.Prune/flow.Engine.Prune: a
// manually-analyzed pcap's history legitimately carries old
// timestamps, and this is what actually populates the Tag History
// popup's Value Changes/Control Events tables, so without this
// exemption they'd go empty within one flush interval of appearing
// even though the parent Tag itself (protected separately) survives.
func (e *Engine) PruneHistory(maxAge time.Duration) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)

	e.valueChanges = filterRecent(
		e.valueChanges,
		cutoff,
		func(vc ValueChange) time.Time { return vc.Timestamp },
		func(vc ValueChange) bool { return vc.FromAnalysis },
	)

	e.controlEvents = filterRecent(
		e.controlEvents,
		cutoff,
		func(ce ControlEvent) time.Time { return ce.Timestamp },
		func(ce ControlEvent) bool { return ce.FromAnalysis },
	)
}
