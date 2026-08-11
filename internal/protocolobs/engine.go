package protocolobs

import (
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

const maxObservations = 10000

type Engine struct {
	bus          *core.EventBus
	mu           sync.RWMutex
	observations []Observation
	exchanges    []any
	correlator   *Correlator
	stop         chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
}

func New(bus *core.EventBus) *Engine {
	return NewWithConfig(bus, CorrelatorConfig{})
}

func NewWithConfig(bus *core.EventBus, config CorrelatorConfig) *Engine {
	return &Engine{bus: bus, correlator: NewCorrelatorWithConfig(config), stop: make(chan struct{})}
}

func (e *Engine) Reset() {
	e.mu.Lock()
	e.observations = nil
	e.exchanges = nil
	e.mu.Unlock()
	if e.correlator != nil {
		e.correlator.Reset()
	}
}

func (e *Engine) Start() {
	packets := e.bus.Subscribe(core.EventUDPConversationPacket)
	streams := e.bus.Subscribe(core.EventTCPStreamData)
	e.wg.Add(3)
	go func() {
		defer e.wg.Done()
		for {
			select {
			case <-e.stop:
				return
			case ev := <-packets:
				contextual, ok := ev.Data.(udpconversation.ContextualPacket)
				if !ok {
					continue
				}
				for _, observation := range parseUDPWithContext(contextual.Packet, &contextual.Context) {
					e.add(observation)
				}
				if contextual.Context.ConversationID != "" {
					e.publishExchanges(e.correlator.Observe(contextual.Packet, contextual.Context))
				}
			}
		}
	}()
	go func() {
		defer e.wg.Done()
		for {
			select {
			case <-e.stop:
				return
			case ev := <-streams:
				if ch, ok := ev.Data.(core.TCPStreamChunk); ok {
					for _, o := range parseTCP(ch) {
						e.add(o)
					}
				}
			}
		}
	}()
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(exchangeTimeout / 2)
		defer ticker.Stop()
		for {
			select {
			case <-e.stop:
				return
			case now := <-ticker.C:
				e.publishExchanges(e.correlator.Expire(now))
			}
		}
	}()
}

func (e *Engine) Stop() {
	e.stopOnce.Do(func() { close(e.stop) })
	e.wg.Wait()
}

func (e *Engine) publishExchanges(exchanges []any) {
	for _, exchange := range exchanges {
		eventType, timestamp := exchangeEvent(exchange)
		if eventType != "" {
			e.mu.Lock()
			e.exchanges = append(e.exchanges, exchange)
			if len(e.exchanges) > maxObservations {
				e.exchanges = append([]any(nil), e.exchanges[len(e.exchanges)-maxObservations:]...)
			}
			e.mu.Unlock()
			e.bus.Publish(core.Event{Type: eventType, Timestamp: timestamp, Data: exchange})
		}
	}
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

func (e *Engine) GetExchanges() []any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]any, len(e.exchanges))
	copy(result, e.exchanges)
	return result
}
