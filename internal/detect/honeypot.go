package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens/internal/core"
)

// startHoneypotWatch consumes core.EventPacketParsed (all IP traffic,
// not filtered to a single protocol the way startARPWatch is) to
// detect traffic touching a configured deception station — see
// config.Deception and handleHoneypot's doc comment for the two
// distinct findings this produces.
func (e *Engine) startHoneypotWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok {
				continue
			}

			e.handleHoneypot(packet)

		}

	}()

}

// handleHoneypot raises one of two distinct findings for a packet
// touching a configured deception station (config.Deception.
// Stations, scored at or above HoneypotThreshold):
//
//   - AlertHoneypotProbed (medium): something connects TO the
//     honeypot. Expected — this is exactly what a honeypot is for,
//     catching reconnaissance/scanning — but still a genuinely useful
//     signal ("something in the network is probing addresses it has
//     no legitimate reason to know about").
//   - AlertHoneypotLateralMovement (critical): the honeypot itself
//     initiates outbound traffic. This should never happen from a
//     station that exists purely as a decoy — it means the honeypot
//     has been compromised and whatever compromised it is now
//     pivoting to reach other hosts from it.
//
// Deliberately not the same alert with different severities: they
// represent genuinely different situations (something scanning the
// network vs. an actual compromise), and collapsing them would lose
// that distinction in the Alerts tab.
func (e *Engine) handleHoneypot(packet core.Packet) {

	if packet.SrcIP == "" || packet.DstIP == "" {
		return
	}

	srcScore, srcIsStation := e.deceptionScores[packet.SrcIP]
	dstScore, dstIsStation := e.deceptionScores[packet.DstIP]

	srcIsHoneypot := srcIsStation && srcScore >= e.honeypotThreshold
	dstIsHoneypot := dstIsStation && dstScore >= e.honeypotThreshold

	if srcIsHoneypot && e.isRuleEnabled(string(AlertHoneypotLateralMovement)) {
		e.raiseHoneypotAlert(
			AlertHoneypotLateralMovement,
			"critical",
			fmt.Sprintf("honeypot|lateral|%s|%s", packet.SrcIP, packet.DstIP),
			fmt.Sprintf(
				"Honeypot %s initiated outbound traffic to %s — likely compromised, possible lateral movement",
				packet.SrcIP, packet.DstIP,
			),
			packet.SrcIP,
		)
	}

	// Excludes honeypot-to-honeypot traffic (srcIsHoneypot already
	// true) — that's lateral movement between decoys, which the
	// alert above already captures; counting it as "probed" too
	// would just be double-booking the same underlying event under
	// a less severe label.
	if dstIsHoneypot && !srcIsHoneypot && e.isRuleEnabled(string(AlertHoneypotProbed)) {
		e.raiseHoneypotAlert(
			AlertHoneypotProbed,
			"medium",
			fmt.Sprintf("honeypot|probed|%s|%s", packet.SrcIP, packet.DstIP),
			fmt.Sprintf(
				"%s connected to honeypot %s",
				packet.SrcIP, packet.DstIP,
			),
			packet.DstIP,
		)
	}
}

// raiseHoneypotAlert creates or updates the deduplicated Alert for
// one specific (direction, src, dst) pair — repeated traffic on the
// same pair updates Count/LastSeen on the same alert rather than
// creating a new one each time, same as every other alert type here.
func (e *Engine) raiseHoneypotAlert(alertType AlertType, severity, key, message, ip string) {

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[key]

	if !exists {

		alert = &Alert{
			ID: key,

			Type:     alertType,
			Severity: severity,
			Message:  message,

			IP: ip,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)
	}

	alert.LastSeen = now
	alert.Count++
}
