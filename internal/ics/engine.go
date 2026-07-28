// Package ics decodes OT/ICS application protocols into normalized Message events.
package ics

import (
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"go.uber.org/zap"
)

const (
	PortModbus     uint16 = 502
	PortS7Comm     uint16 = 102
	PortEtherNetIP uint16 = 44818
	PortDNP3       uint16 = 20000
	PortOPCUA      uint16 = 4840
	PortBACnet     uint16 = 47808
	PortIEC104     uint16 = 2404
)

type Config struct{ ModbusPort, S7Port, EtherNetIPPort, DNP3Port, OPCUAPort, BACnetPort, IEC104Port uint16 }

type protocolParser interface {
	Name() string
	CanParse(core.Packet) bool
	Parse(core.Packet) (Message, bool)
}

type ParserStats struct {
	Name           string  `json:"name"`
	Candidates     uint64  `json:"candidates"`
	Parsed         uint64  `json:"parsed"`
	Rejected       uint64  `json:"rejected"`
	Panics         uint64  `json:"panics"`
	TotalParseNS   uint64  `json:"total_parse_ns"`
	AverageParseUS float64 `json:"average_parse_us"`
}

type Engine struct {
	EventBus   *core.EventBus
	Config     Config
	ModbusPort uint16
	S7Port     uint16
	parsers    []protocolParser
	statsMu    sync.RWMutex
	stats      map[string]*ParserStats
}

func New(bus *core.EventBus, cfg Config) *Engine {
	if cfg.ModbusPort == 0 {
		cfg.ModbusPort = PortModbus
	}
	if cfg.S7Port == 0 {
		cfg.S7Port = PortS7Comm
	}
	if cfg.EtherNetIPPort == 0 {
		cfg.EtherNetIPPort = PortEtherNetIP
	}
	if cfg.DNP3Port == 0 {
		cfg.DNP3Port = PortDNP3
	}
	if cfg.OPCUAPort == 0 {
		cfg.OPCUAPort = PortOPCUA
	}
	if cfg.BACnetPort == 0 {
		cfg.BACnetPort = PortBACnet
	}
	if cfg.IEC104Port == 0 {
		cfg.IEC104Port = PortIEC104
	}
	e := &Engine{EventBus: bus, Config: cfg, ModbusPort: cfg.ModbusPort, S7Port: cfg.S7Port, stats: map[string]*ParserStats{}}
	e.parsers = []protocolParser{
		portParser{"Modbus", "TCP", cfg.ModbusPort, func(p core.Packet) (Message, bool) { return parseModbus(p, cfg.ModbusPort) }},
		portParser{"S7comm", "TCP", cfg.S7Port, parseS7Comm},
		portParser{"EtherNet/IP", "TCP", cfg.EtherNetIPPort, parseEtherNetIP},
		portParser{"DNP3", "TCP", cfg.DNP3Port, parseDNP3},
		portParser{"OPC UA", "TCP", cfg.OPCUAPort, parseOPCUA},
		portParser{"BACnet/IP", "UDP", cfg.BACnetPort, parseBACnet},
		portParser{"IEC 60870-5-104", "TCP", cfg.IEC104Port, parseIEC104},
		profinetParser{},
	}
	for _, p := range e.parsers {
		e.stats[p.Name()] = &ParserStats{Name: p.Name()}
	}
	return e
}

type portParser struct {
	name, transport string
	port            uint16
	parse           func(core.Packet) (Message, bool)
}

func (p portParser) Name() string { return p.name }
func (p portParser) CanParse(pkt core.Packet) bool {
	return pkt.L4Protocol == p.transport && (pkt.SrcPort == p.port || pkt.DstPort == p.port) && len(pkt.AppPayload) > 0
}
func (p portParser) Parse(pkt core.Packet) (Message, bool) { return p.parse(pkt) }

func (e *Engine) Start() {
	logger.Log.Info("ICS engine started", zap.Int("protocols", len(e.parsers)))
	ch := e.EventBus.Subscribe(core.EventPacketParsed)
	go func() {
		for event := range ch {
			e.handle(event)
		}
	}()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for now := range t.C {
			e.EventBus.Publish(core.Event{Type: core.EventParserDiagnostics, Timestamp: now, Data: e.Stats()})
		}
	}()
}
func (e *Engine) handle(event core.Event) {
	packet, ok := event.Data.(core.Packet)
	if !ok {
		return
	}
	msg, ok := e.decode(packet)
	if !ok {
		return
	}
	e.EventBus.Publish(core.Event{Type: core.EventICSMessage, Timestamp: msg.Timestamp, Data: msg})
}
func (e *Engine) decode(packet core.Packet) (Message, bool) {
	for _, parser := range e.parsers {
		if !parser.CanParse(packet) {
			continue
		}
		name := parser.Name()
		started := time.Now()
		var msg Message
		var ok bool
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					logger.Log.Error("protocol parser panic isolated", zap.String("parser", name), zap.Any("panic", r))
				}
			}()
			msg, ok = parser.Parse(packet)
		}()
		e.record(name, ok, panicked, time.Since(started))
		if ok {
			return msg, true
		}
	}
	return Message{}, false
}
func (e *Engine) record(name string, parsed, panicked bool, elapsed time.Duration) {
	e.statsMu.Lock()
	defer e.statsMu.Unlock()
	st := e.stats[name]
	if st == nil {
		st = &ParserStats{Name: name}
		e.stats[name] = st
	}
	st.Candidates++
	st.TotalParseNS += uint64(elapsed)
	if panicked {
		st.Panics++
	} else if parsed {
		st.Parsed++
	} else {
		st.Rejected++
	}
	if st.Candidates > 0 {
		st.AverageParseUS = float64(st.TotalParseNS) / float64(st.Candidates) / 1000
	}
}
func (e *Engine) Stats() []ParserStats {
	e.statsMu.RLock()
	defer e.statsMu.RUnlock()
	out := make([]ParserStats, 0, len(e.stats))
	for _, st := range e.stats {
		out = append(out, *st)
	}
	return out
}
