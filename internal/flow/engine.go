package flow

import (
	"fmt"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/ipfix"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
)

type Engine struct {
	EventBus *core.EventBus

	mutex sync.RWMutex

	flows map[string]*Flow

	// deceptionScores/honeypotThreshold — see config.Deception.
	// Read-only after construction, so no lock needed to read them.
	// Used to set Flow.HoneypotInitiated per-packet — see Update.
	deceptionScores   map[string]int
	honeypotThreshold int
}

func New(bus *core.EventBus, deceptionScores map[string]int, honeypotThreshold int) *Engine {

	if deceptionScores == nil {
		deceptionScores = make(map[string]int)
	}

	return &Engine{
		EventBus:          bus,
		flows:             make(map[string]*Flow),
		deceptionScores:   deceptionScores,
		honeypotThreshold: honeypotThreshold,
	}
}

func (e *Engine) Start() {

	logger.Log.Info(
		"Flow engine started",
	)

	e.startPacketWatch()
	e.startIPFIXWatch()

}

func (e *Engine) startPacketWatch() {

	ch := e.EventBus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			e.handle(event)

		}

	}()

}

// startIPFIXWatch consumes flow records exported by a router/switch
// (see internal/ipfix) when capture.mode is "ipfix" instead of
// "npcap" — a separate data source from live-captured packets, but
// updating the exact same Flow records via ApplyExternalDelta.
func (e *Engine) startIPFIXWatch() {

	ch := e.EventBus.Subscribe(core.EventIPFIXFlow)

	go func() {

		for event := range ch {

			record, ok := event.Data.(ipfix.FlowRecord)

			if !ok {
				continue
			}

			if record.SrcIP == "" || record.DstIP == "" {
				continue
			}

			e.ApplyExternalDelta(
				record.Protocol,
				record.SrcIP,
				record.SrcPort,
				record.DstIP,
				record.DstPort,
				record.Packets,
				record.Bytes,
			)

		}

	}()

}

func (e *Engine) handle(event core.Event) {

	packet, ok := event.Data.(core.Packet)

	if !ok {
		return
	}

	// Flows are keyed on the IP 5-tuple. L2-only traffic (ARP, and
	// any other non-IP frame) has no src/dst IP and therefore no
	// meaningful flow — skip it here rather than track bogus flows
	// keyed on empty addresses.
	if packet.SrcIP == "" || packet.DstIP == "" {
		return
	}

	e.Update(packet)
}

// Update records one packet against its flow, creating the flow on
// first sight. Both directions of a conversation (A->B and B->A)
// are folded into the same flow, matching how NetFlow/IPFIX-style
// tools report a single bidirectional flow per conversation.
func (e *Engine) Update(packet core.Packet) {

	key := flowKey(
		packet.L4Protocol,
		packet.SrcIP,
		packet.SrcPort,
		packet.DstIP,
		packet.DstPort,
	)

	now := packet.Timestamp

	e.mutex.Lock()
	defer e.mutex.Unlock()

	f, exists := e.flows[key]

	if !exists {

		f = &Flow{
			ID: key,

			SrcIP: packet.SrcIP,
			DstIP: packet.DstIP,

			SrcPort: packet.SrcPort,
			DstPort: packet.DstPort,

			Protocol: packet.L4Protocol,

			FirstSeen: now,

			FromAnalysis: packet.FromAnalysis,
		}

		e.flows[key] = f

		logger.Log.Info(
			"Flow discovered",
		)

	} else if !packet.FromAnalysis {

		// A live sighting of an already-known flow permanently clears
		// FromAnalysis — see asset.Engine.Update's identical logic
		// for the full reasoning.
		f.FromAnalysis = false
	}

	// Checked on every packet, using packet.SrcIP directly — not
	// derived from f.SrcIP/DstIP above, which only reflect whichever
	// direction happened to create the record first. See
	// Flow.HoneypotInitiated's doc comment.
	if score, ok := e.deceptionScores[packet.SrcIP]; ok && score >= e.honeypotThreshold {
		f.HoneypotInitiated = true
	}

	// Only overwrite with a non-zero VLAN tag — see
	// asset.Engine.Update's identical reasoning.
	if packet.VLANID != 0 {
		f.VLANID = packet.VLANID
	}

	f.Packets++
	f.Bytes += uint64(packet.Length)
	f.LastSeen = now
}

// ApplyExternalDelta updates a flow from an already-aggregated
// external source (currently: internal/ipfix) rather than a single
// captured packet. Unlike Update, which always adds exactly one
// packet, this adds the caller-supplied packetsDelta/bytesDelta —
// an IPFIX exporter reports "N packets, M bytes since I last told
// you about this flow," not one packet at a time, so folding that
// straight into Packets++ would drastically undercount traffic.
func (e *Engine) ApplyExternalDelta(
	protocol string,
	srcIP string,
	srcPort uint16,
	dstIP string,
	dstPort uint16,
	packetsDelta uint64,
	bytesDelta uint64,
) {

	key := flowKey(protocol, srcIP, srcPort, dstIP, dstPort)

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	f, exists := e.flows[key]

	if !exists {

		f = &Flow{
			ID: key,

			SrcIP: srcIP,
			DstIP: dstIP,

			SrcPort: srcPort,
			DstPort: dstPort,

			Protocol: protocol,

			FirstSeen: now,
		}

		e.flows[key] = f

		logger.Log.Info(
			"Flow discovered (IPFIX)",
		)

	} else if f.FromAnalysis {

		// IPFIX data is always current/live by nature — same
		// clear-on-live-touch logic as Update().
		f.FromAnalysis = false
	}

	// Same reasoning as Update() — see Flow.HoneypotInitiated's doc
	// comment.
	if score, ok := e.deceptionScores[srcIP]; ok && score >= e.honeypotThreshold {
		f.HoneypotInitiated = true
	}

	f.Packets += packetsDelta
	f.Bytes += bytesDelta
	f.LastSeen = now
}

// Count returns the number of tracked flows.
func (e *Engine) Count() int {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return len(e.flows)
}

// Restore rehydrates the engine's in-memory state from previously
// persisted flows, e.g. at startup after loading from disk.
func (e *Engine) Restore(flows []*Flow) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	for _, f := range flows {
		e.flows[f.ID] = f
	}
}

// Prune removes flows not seen within maxAge. This is the biggest
// disk-growth risk in the whole persistence layer: every new
// client-initiated connection uses a fresh ephemeral source port, so
// flows keeps growing for as long as the process runs unless old
// entries are dropped. Returns the number removed.
func (e *Engine) Prune(maxAge time.Duration) int {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)

	removed := 0

	for key, f := range e.flows {

		if f.FromAnalysis {
			continue
		}

		if f.LastSeen.Before(cutoff) {
			delete(e.flows, key)
			removed++
		}
	}

	return removed
}

// Clear removes every tracked flow — the admin UI's "wipe database"
// action. Unlike Prune, this isn't selective; it's a full reset.
func (e *Engine) Clear() {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.flows = make(map[string]*Flow)
}

// GetAll returns a snapshot of every tracked flow. Each element is a
// shallow copy, not a pointer into the live map — see
// asset.Engine.GetAll's doc comment for why that matters (a data
// race between this and Update()/ApplyExternalDelta() otherwise).
func (e *Engine) GetAll() []*Flow {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]*Flow, 0, len(e.flows))

	for _, f := range e.flows {

		clone := *f

		result = append(
			result,
			&clone,
		)

	}

	return result
}

// flowKey builds a direction-independent identifier for a
// conversation between two endpoints, so packets seen in either
// direction map to the same flow. The protocol is included since
// the same IP:port pair can carry independent TCP and UDP flows.
func flowKey(
	protocol string,
	ip1 string,
	port1 uint16,
	ip2 string,
	port2 uint16,
) string {

	a := fmt.Sprintf("%s:%d", ip1, port1)
	b := fmt.Sprintf("%s:%d", ip2, port2)

	if a > b {
		a, b = b, a
	}

	return fmt.Sprintf("%s|%s|%s", protocol, a, b)
}
