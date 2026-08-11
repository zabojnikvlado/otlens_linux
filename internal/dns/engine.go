package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

const maxNamePointerHops = 32

type Engine struct {
	bus             *core.EventBus
	mu              sync.RWMutex
	observations    []Observation
	maxObservations int
	tracker         *Tracker
	stop            chan struct{}
	stopOnce        sync.Once
	wg              sync.WaitGroup
}

func New(bus *core.EventBus, maxObservations int) *Engine {
	return NewWithTimeout(bus, maxObservations, defaultExchangeTimeout)
}

func NewWithTimeout(bus *core.EventBus, maxObservations int, timeout time.Duration) *Engine {
	if maxObservations <= 0 {
		maxObservations = 5000
	}
	return &Engine{
		bus:             bus,
		maxObservations: maxObservations,
		tracker:         NewTracker(timeout, maxObservations),
		stop:            make(chan struct{}),
	}
}

func (e *Engine) Start() {
	if logger.Log != nil {
		logger.Log.Info("Passive DNS engine started")
	}
	ch := e.bus.Subscribe(core.EventUDPConversationPacket)
	e.wg.Add(2)
	go func() {
		defer e.wg.Done()
		for {
			select {
			case <-e.stop:
				return
			case event := <-ch:
				contextual, ok := event.Data.(udpconversation.ContextualPacket)
				if !ok {
					continue
				}
				p := contextual.Packet
				if len(p.AppPayload) < 12 || !isDNSPort(p.SrcPort, p.DstPort) {
					continue
				}
				observation, ok := parse(p)
				if !ok {
					continue
				}
				observation.ConversationID = contextual.Context.ConversationID
				observation.Direction = string(contextual.Context.Direction)
				e.addObservation(observation)
				if contextual.Context.ConversationID != "" {
					if exchange := e.tracker.Observe(observation, contextual.Context); exchange != nil {
						e.publishExchange(*exchange)
					}
				}
			}
		}
	}()
	go func() {
		defer e.wg.Done()
		interval := e.tracker.timeout / 2
		if interval < 100*time.Millisecond {
			interval = 100 * time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-e.stop:
				return
			case now := <-ticker.C:
				for _, exchange := range e.tracker.Expire(now) {
					e.publishExchange(exchange)
				}
			}
		}
	}()
}

func (e *Engine) Stop() {
	e.stopOnce.Do(func() { close(e.stop) })
	e.wg.Wait()
}

func (e *Engine) addObservation(observation Observation) {
	e.mu.Lock()
	e.observations = append(e.observations, observation)
	if len(e.observations) > e.maxObservations {
		copy(e.observations, e.observations[len(e.observations)-e.maxObservations:])
		e.observations = e.observations[:e.maxObservations]
	}
	e.mu.Unlock()
	e.bus.Publish(core.Event{Type: core.EventDNSObservation, Timestamp: observation.Timestamp, Data: observation})
}

func (e *Engine) publishExchange(exchange DNSExchange) {
	timestamp := exchange.RespondedAt
	if timestamp.IsZero() {
		timestamp = exchange.RequestedAt
	}
	e.bus.Publish(core.Event{Type: core.EventDNSExchange, Timestamp: timestamp, Data: exchange})
}

func (e *Engine) Reset() {
	e.mu.Lock()
	e.observations = nil
	e.mu.Unlock()
	if e.tracker != nil {
		e.tracker.Reset()
	}
}

func (e *Engine) GetObservations() []Observation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Observation, len(e.observations))
	copy(out, e.observations)
	return out
}

func (e *Engine) GetExchanges() []DNSExchange { return e.tracker.Exchanges() }

func (e *Engine) Stats() Telemetry { return e.tracker.Stats() }

func isDNSPort(a, b uint16) bool { return a == 53 || b == 53 }

func parse(p core.Packet) (Observation, bool) {
	data := p.AppPayload
	if len(data) < 12 {
		return Observation{}, false
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	isResponse := flags&0x8000 != 0
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	an := int(binary.BigEndian.Uint16(data[6:8]))
	obs := Observation{Timestamp: p.Timestamp, TransactionID: binary.BigEndian.Uint16(data[0:2]), QueryName: "", ResponseCode: uint8(flags & 0x000f), IsResponse: isResponse, AnswerCount: an, PayloadBytes: len(data)}
	if isResponse {
		obs.ClientIP, obs.ServerIP = p.DstIP, p.SrcIP
	} else {
		obs.ClientIP, obs.ServerIP = p.SrcIP, p.DstIP
	}
	off := 12
	for i := 0; i < qd; i++ {
		name, next, err := decodeName(data, off)
		if err != nil || next+4 > len(data) {
			return Observation{}, false
		}
		if i == 0 {
			obs.QueryName = normalize(name)
			obs.QueryType = binary.BigEndian.Uint16(data[next : next+2])
		}
		off = next + 4
	}
	for i := 0; i < an; i++ {
		_, next, err := decodeName(data, off)
		if err != nil || next+10 > len(data) {
			break
		}
		typ := binary.BigEndian.Uint16(data[next : next+2])
		ttl := binary.BigEndian.Uint32(data[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(data[next+8 : next+10]))
		rstart := next + 10
		if rstart+rdlen > len(data) {
			break
		}
		if obs.TTL == 0 || ttl < obs.TTL {
			obs.TTL = ttl
		}
		switch typ {
		case 1:
			if rdlen == 4 {
				obs.Answers = append(obs.Answers, net.IP(data[rstart:rstart+4]).String())
			}
		case 28:
			if rdlen == 16 {
				obs.Answers = append(obs.Answers, net.IP(data[rstart:rstart+16]).String())
			}
		case 5:
			if n, _, err := decodeName(data, rstart); err == nil {
				obs.CNAMEs = append(obs.CNAMEs, normalize(n))
			}
		}
		off = rstart + rdlen
	}
	return obs, obs.QueryName != ""
}

func normalize(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func decodeName(data []byte, offset int) (string, int, error) {
	var labels []string
	pos := offset
	end := offset
	jumped := false
	hops := 0
	for {
		if pos >= len(data) {
			return "", 0, fmt.Errorf("dns name out of bounds")
		}
		l := int(data[pos])
		if l == 0 {
			pos++
			if !jumped {
				end = pos
			}
			break
		}
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(data) {
				return "", 0, fmt.Errorf("truncated pointer")
			}
			hops++
			if hops > maxNamePointerHops {
				return "", 0, fmt.Errorf("pointer loop")
			}
			if !jumped {
				end = pos + 2
				jumped = true
			}
			pos = int(binary.BigEndian.Uint16(data[pos:pos+2]) & 0x3fff)
			continue
		}
		if l > 63 || pos+1+l > len(data) {
			return "", 0, fmt.Errorf("invalid label")
		}
		labels = append(labels, string(data[pos+1:pos+1+l]))
		pos += 1 + l
	}
	return strings.Join(labels, "."), end, nil
}
