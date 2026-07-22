// Package debug prints every parsed packet and decoded ICS message
// to stdout as plain text — a lightweight sanity check for verifying
// capture/parsing/ICS decoding against real traffic, independent of
// the REST API or any persisted state. Not meant to stay on in a
// long-running deployment (it's unstructured stdout, not through
// the zap logger); the structured equivalents are internal/store's
// GetTags/GetValueChanges and internal/detect's GetAlerts.
package debug

import (
	"fmt"

	"github.com/zabojnikvlado/otlens/internal/core"
	"github.com/zabojnikvlado/otlens/internal/ics"
)

type Engine struct {
	EventBus *core.EventBus
}

func New(bus *core.EventBus) *Engine {
	return &Engine{
		EventBus: bus,
	}
}

func (e *Engine) Start() {

	e.startPacketLog()
	e.startICSLog()

}

// startPacketLog prints one line per parsed packet — the same
// data core.Packet carries, just human-readable.
func (e *Engine) startPacketLog() {

	ch := e.EventBus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)
			if !ok {
				continue
			}

			// ARP packets don't populate SrcIP/DstIP/SrcPort/DstPort
			// (those are IP/TCP/UDP-specific) — print the ARP fields
			// instead of falling through to blank ":0 -> :0".
			if packet.L4Protocol == "ARP" {

				fmt.Printf(
					"ARP %s: %s (%s) -> %s (%s)\n",
					packet.ARPOperation,
					packet.ARPSrcIP,
					packet.ARPSrcMAC,
					packet.ARPDstIP,
					packet.ARPDstMAC,
				)

				continue
			}

			fmt.Printf(
				"%s:%d -> %s:%d (%s)\n",
				packet.SrcIP,
				packet.SrcPort,
				packet.DstIP,
				packet.DstPort,
				packet.L4Protocol,
			)

		}

	}()

}

// startICSLog prints decoded OT/ICS messages (Modbus, S7comm) as a
// quick sanity check that protocol parsing matches real traffic —
// the structured/persisted equivalent is internal/store's GetTags
// and internal/detect's GetAlerts (for security_relevant findings).
func (e *Engine) startICSLog() {

	ch := e.EventBus.Subscribe(core.EventICSMessage)

	go func() {

		for event := range ch {

			msg, ok := event.Data.(ics.Message)
			if !ok {
				continue
			}

			alert := ""

			if relevant, _ := msg.Details["security_relevant"].(bool); relevant {
				alert = " [SECURITY RELEVANT]"
			}

			fmt.Printf(
				"[ICS] %s %s:%d -> %s:%d unit=%d fn=%s%s %v\n",
				msg.Protocol,
				msg.SrcIP,
				msg.SrcPort,
				msg.DstIP,
				msg.DstPort,
				msg.UnitID,
				msg.FunctionName,
				alert,
				msg.Details,
			)

		}

	}()

}
