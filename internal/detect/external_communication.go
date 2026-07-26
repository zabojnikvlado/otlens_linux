package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// startExternalCommunicationWatch consumes core.EventPacketParsed (all
// IP traffic) to detect an internal/private asset exchanging traffic
// with a public internet address — see handleExternalCommunication's
// doc comment for why this exists as an alert rather than something
// the Topology tab draws.
func (e *Engine) startExternalCommunicationWatch(bus *core.EventBus) {

	ch := bus.Subscribe(
		core.EventPacketParsed,
	)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok {
				continue
			}

			e.handleExternalCommunication(packet)

		}

	}()

}

// handleExternalCommunication flags traffic between a private/internal
// address and a public one. The Topology map deliberately excludes
// non-private endpoints entirely (see internal/topology/build.go) —
// internet-facing traffic has no stable identity there anyway (rotating
// CDN/cloud IPs would otherwise make the Central-side topology ledger
// grow without bound, the same class of problem alert history had
// before delta-sync) — so this alert is what preserves the "does
// anything in my OT network talk to the internet at all" visibility
// instead, without needing a node on the map for every IP a device ever
// happens to contact.
//
// Deduplicated per internal IP, not per (internal, external) pair: a
// device that talks to many different external addresses (typical for
// anything doing normal DNS/NTP/update-check traffic) is one alert
// whose Count climbs, not a flood of one alert per destination. Traffic
// entirely inside the network, or — unusually — entirely outside it,
// isn't this rule's concern; exactly one side must be private.
func (e *Engine) handleExternalCommunication(packet core.Packet) {

	if !e.isRuleEnabled(string(AlertExternalCommunication)) {
		return
	}

	if packet.SrcIP == "" || packet.DstIP == "" {
		return
	}

	srcPrivate, dstPrivate := isPrivateIP(packet.SrcIP), isPrivateIP(packet.DstIP)

	if srcPrivate == dstPrivate {
		return
	}

	internalIP, externalIP := packet.SrcIP, packet.DstIP

	if dstPrivate {
		internalIP, externalIP = packet.DstIP, packet.SrcIP
	}

	key := fmt.Sprintf("external|%s", internalIP)

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[key]

	if exists && !e.allowAlertOccurrenceLocked(alert) {
		return
	}

	if !exists {

		alert = &Alert{
			ID: key,

			Type:     AlertExternalCommunication,
			Severity: "medium",
			Message: fmt.Sprintf(
				"%s communicated with external address %s",
				internalIP, externalIP,
			),

			IP: internalIP,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)

	}

	alert.LastSeen = now
	alert.Count++
	alert.Synced = false

}
