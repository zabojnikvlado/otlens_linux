package protocolobs

import (
	"sync"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

const maxObservations = 10000

type Engine struct {
	bus          *core.EventBus
	mu           sync.RWMutex
	observations []Observation
}

func New(bus *core.EventBus) *Engine { return &Engine{bus: bus} }

func (e *Engine) Start() {
	packets := e.bus.Subscribe(core.EventPacketParsed)
	streams := e.bus.Subscribe(core.EventTCPStreamData)
	go func() {
		for ev := range packets {
			if p, ok := ev.Data.(core.Packet); ok && p.L4Protocol == "UDP" {
				for _, o := range parseUDP(p) {
					e.add(o)
				}
			}
		}
	}()
	go func() {
		for ev := range streams {
			if ch, ok := ev.Data.(core.TCPStreamChunk); ok {
				for _, o := range parseTCP(ch) {
					e.add(o)
				}
			}
		}
	}()
}

func (e *Engine) add(o Observation) {
	if o.Protocol == "" {
		return
	}
	e.mu.Lock()
	e.observations = append(e.observations, o)
	if len(e.observations) > maxObservations {
		e.observations = append([]Observation(nil), e.observations[len(e.observations)-maxObservations:]...)
	}
	e.mu.Unlock()
	e.bus.Publish(core.Event{Type: core.EventProtocolObservation, Timestamp: o.Timestamp, Data: o})
}

func (e *Engine) GetObservations() []Observation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Observation, len(e.observations))
	copy(out, e.observations)
	return out
}
