// Package ics decodes OT/ICS application protocols into normalized Message events.
package ics

import (
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
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

type Config struct {
	ModbusPort, S7Port, EtherNetIPPort, DNP3Port, OPCUAPort, BACnetPort, IEC104Port uint16
}

type protocolParser interface {
	Name() string
	CanParse(core.Packet) bool
	Parse(core.Packet) (Message, bool)
}

type Engine struct {
	EventBus *core.EventBus
	Config   Config

	// Compatibility fields used by topology/API wiring.
	ModbusPort uint16
	S7Port     uint16
	parsers    []protocolParser
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
	e := &Engine{EventBus: bus, Config: cfg, ModbusPort: cfg.ModbusPort, S7Port: cfg.S7Port}
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
	logger.Log.WithField("protocols", len(e.parsers)).Info("ICS engine started")
	ch := e.EventBus.Subscribe(core.EventPacketParsed)
	go func() {
		for event := range ch {
			e.handle(event)
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
	e.EventBus.Publish(core.Event{Type: core.EventICSMessage, Data: msg})
}
func (e *Engine) decode(packet core.Packet) (Message, bool) {
	for _, parser := range e.parsers {
		if parser.CanParse(packet) {
			if msg, ok := parser.Parse(packet); ok {
				return msg, true
			}
		}
	}
	return Message{}, false
}
