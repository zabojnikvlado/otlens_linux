package hostname

import (
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
)

const portMDNS = 5353

// Engine watches parsed UDP packets for mDNS (port 5353) and DHCP
// (ports 67/68) traffic, and publishes any hostname it can extract
// as core.EventHostnameSeen for internal/asset to pick up.
type Engine struct {
	EventBus *core.EventBus
}

func New(bus *core.EventBus) *Engine {

	return &Engine{
		EventBus: bus,
	}
}

func (e *Engine) Start() {

	logger.Log.Info(
		"Hostname discovery engine started",
	)

	ch := e.EventBus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok || packet.L4Protocol != "UDP" || len(packet.AppPayload) == 0 {
				continue
			}

			e.handle(packet)

		}

	}()

}

func (e *Engine) handle(packet core.Packet) {

	switch {

	case packet.SrcPort == portMDNS || packet.DstPort == portMDNS:

		hostname, ok := parseMDNSHostname(packet.AppPayload)

		if !ok || packet.SrcMAC == "" {
			return
		}

		e.publish(packet.SrcMAC, hostname, "mDNS")

	case isDHCPPort(packet.SrcPort, packet.DstPort):

		mac, hostname, ok := parseDHCPHostname(packet.AppPayload)

		if !ok || hostname == "" {
			return
		}

		e.publish(mac, hostname, "DHCP")
	}

}

func (e *Engine) publish(mac, hostname, source string) {

	e.EventBus.Publish(
		core.Event{
			Type: core.EventHostnameSeen,
			Data: Observation{
				MAC:      mac,
				Hostname: hostname,
				Source:   source,
			},
		},
	)
}
