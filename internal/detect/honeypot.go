package detect

import (
	"fmt"
	"net"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
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
// isPrivateIP reports whether ip is an RFC 1918 / RFC 4193 private
// address (or loopback) — used to scope "lateral movement" to actual
// movement within the network, not a honeypot's ordinary outbound
// internet traffic (Windows Update, NTP, DNS, telemetry, etc., if the
// honeypot happens to be a real OS rather than a bare decoy). Malformed/
// unparseable input is treated as not-private (fails safe: an
// unrecognized address doesn't get waved through as "internal").
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback()
}

func (e *Engine) handleHoneypot(packet core.Packet) {

	if packet.SrcIP == "" || packet.DstIP == "" {
		return
	}

	srcScore, srcIsStation := e.deceptionScores[packet.SrcIP]
	dstScore, dstIsStation := e.deceptionScores[packet.DstIP]

	srcIsHoneypot := srcIsStation && srcScore >= e.honeypotThreshold
	dstIsHoneypot := dstIsStation && dstScore >= e.honeypotThreshold

	if srcIsHoneypot && isPrivateIP(packet.DstIP) {
		e.excludePacketFromLearning(packet, "honeypot lateral movement")
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
	if dstIsHoneypot && !srcIsHoneypot {
		e.excludePacketFromLearning(packet, "honeypot activity")
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

// startHoneypotClearedWatch consumes core.EventHoneypotCleared —
// published by internal/asset the moment a device that was sitting on a
// configured decoy IP moves off it (or, less commonly, its configured
// score genuinely drops below the honeypot threshold). See that event's
// doc comment for why the IP it carries is the *previous* honeypot
// identity, not wherever the device ended up.
func (e *Engine) startHoneypotClearedWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventHoneypotCleared)

	go func() {

		for event := range ch {

			cleared, ok := event.Data.(core.HoneypotCleared)

			if !ok {
				continue
			}

			e.clearHoneypotAlerts(cleared.IP)

		}

	}()

}

// clearHoneypotAlerts removes every still-unreviewed
// (AlertStatusNew) lateral-movement/probed alert for ip. Called once
// internal/asset confirms ip is no longer a honeypot — continuing to
// show "lateral movement" for a device that isn't a decoy anymore
// would be actively misleading, not just stale.
//
// Alerts an operator already reviewed (AlertStatusApproved/Confirmed)
// are deliberately left alone: that's a human judgment about
// something that already happened on the network, and it shouldn't
// be silently erased just because the live honeypot configuration
// moved on. Only the not-yet-reviewed ones are cleared.
func (e *Engine) clearHoneypotAlerts(ip string) {

	if ip == "" {
		return
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	for key, alert := range e.alerts {

		if alert.IP != ip {
			continue
		}

		if alert.Type != AlertHoneypotLateralMovement && alert.Type != AlertHoneypotProbed {
			continue
		}

		if alert.Status != AlertStatusNew {
			continue
		}

		delete(e.alerts, key)

	}

}

// one specific (direction, src, dst) pair — repeated traffic on the
// same pair updates Count/LastSeen on the same alert rather than
// creating a new one each time, same as every other alert type here.
func (e *Engine) raiseHoneypotAlert(alertType AlertType, severity, key, message, ip string) {
	e.raiseBuiltinAlert(string(alertType), alertType, severity, key, message, ip, nil, time.Now(), alertEpisodeGap)
}
