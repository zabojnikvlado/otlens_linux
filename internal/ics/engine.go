// Package ics decodes OT/ICS application-layer protocols — currently
// Modbus/TCP (modbus.go) and S7comm (s7comm.go) — from already
// TCP-parsed packets, port-matched via Engine.ModbusPort/S7Port. Each
// decoded message is normalized into the protocol-agnostic Message
// type (message.go) and published as core.EventICSMessage, so
// downstream consumers (internal/store, internal/detect) don't need
// to know Modbus from S7comm.
package ics

import (
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
)

const (
	// PortModbus and PortS7Comm are the default well-known TCP ports
	// these protocols run on, used when New is given a zero port.
	// Exported so other packages (e.g. topology's OT/IT
	// classification, or config defaulting) can reference the same
	// defaults without duplicating magic numbers.
	PortModbus uint16 = 502
	PortS7Comm uint16 = 102
)

// Engine recognizes OT/ICS traffic among already-parsed packets and
// decodes it into normalized ics.Message events. Protocol detection
// is port-based (same first-pass approach Nozomi/Zeek use), since
// these protocols don't self-identify the way e.g. TLS ALPN does.
// The ports are configurable — some deployments run Modbus/S7comm on
// non-standard ports.
type Engine struct {
	EventBus *core.EventBus

	ModbusPort uint16
	S7Port     uint16
}

// New creates an ICS decoding engine. A zero modbusPort/s7Port falls
// back to the standard PortModbus/PortS7Comm.
func New(bus *core.EventBus, modbusPort, s7Port uint16) *Engine {

	if modbusPort == 0 {
		modbusPort = PortModbus
	}

	if s7Port == 0 {
		s7Port = PortS7Comm
	}

	return &Engine{
		EventBus: bus,

		ModbusPort: modbusPort,
		S7Port:     s7Port,
	}
}

func (e *Engine) Start() {

	logger.Log.Info(
		"ICS engine started",
	)

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

	if packet.L4Protocol != "TCP" || len(packet.AppPayload) == 0 {
		return
	}

	msg, ok := e.decode(packet)

	if !ok {
		return
	}

	e.EventBus.Publish(
		core.Event{
			Type: core.EventICSMessage,
			Data: msg,
		},
	)

}

// decode dispatches to the right protocol parser based on the
// configured port. Any given parser can still reject the payload
// (return false) if it doesn't actually look like that protocol —
// port matching is just a cheap first filter, not proof.
func (e *Engine) decode(packet core.Packet) (Message, bool) {

	if packet.SrcPort == e.ModbusPort || packet.DstPort == e.ModbusPort {
		return parseModbus(packet, e.ModbusPort)
	}

	if packet.SrcPort == e.S7Port || packet.DstPort == e.S7Port {
		return parseS7Comm(packet)
	}

	return Message{}, false
}
