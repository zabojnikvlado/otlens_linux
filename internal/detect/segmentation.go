package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// startSegmentationWatch consumes core.EventPacketParsed to track which
// VLAN each IP was last seen on, and to flag direct communication
// between VLANs whose configured Purdue Model levels are more than
// MaxLevelJump apart — see handleSegmentation's doc comment.
func (e *Engine) startSegmentationWatch(bus *core.EventBus) {

	if !e.segmentationEnabled {
		return
	}

	ch := bus.Subscribe(
		core.EventPacketParsed,
	)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok {
				continue
			}

			e.handleSegmentation(packet)

		}

	}()

}

// handleSegmentation flags traffic that crosses more Purdue Model
// levels directly than config.SensorConfig.Detect.Segmentation.
// MaxLevelJump allows — e.g. a Level 1 field device (PLC/RTU) talking
// straight to a Level 4/5 business system, skipping the Level 3/3.5
// DMZ a properly segmented network would route it through.
//
// A single 802.1Q-tagged packet only ever carries *one* VLAN — its
// own — never both endpoints' VLANs at once, so there's no way to
// evaluate "does this flow cross levels" from one packet alone. This
// works around that by remembering the last VLAN each IP was itself
// seen tagged with (ipVLAN, updated on every packet, independent of
// whether segmentation checking is what's using a given packet for)
// and comparing the *source* packet's own VLAN against the
// *destination* IP's last-known VLAN. Approximate — VLAN tags can be
// stripped by routing before an inter-VLAN packet reaches the sensor,
// and a device that changes VLANs takes one packet to catch up — but
// good enough for the common case of a directly-observed cross-VLAN
// conversation.
func (e *Engine) handleSegmentation(packet core.Packet) {

	if !e.segmentationEnabled || packet.SrcIP == "" || packet.DstIP == "" {
		return
	}

	e.ipVLANMutex.Lock()
	if e.ipVLAN == nil {
		e.ipVLAN = make(map[string]uint16)
	}
	dstVLAN, dstKnown := e.ipVLAN[packet.DstIP]
	e.ipVLAN[packet.SrcIP] = packet.VLANID
	e.ipVLANMutex.Unlock()

	if !dstKnown {
		return
	}

	srcLevel, srcKnown := e.vlanLevels[packet.VLANID]
	dstLevel, dstLevelKnown := e.vlanLevels[dstVLAN]

	// Both sides need a configured level for this to mean anything —
	// an unclassified VLAN never participates in a violation check,
	// rather than being treated as level 0 by default (which would
	// flag it against everything).
	if !srcKnown || !dstLevelKnown || packet.VLANID == dstVLAN {
		return
	}

	jump := srcLevel - dstLevel
	if jump < 0 {
		jump = -jump
	}
	if jump <= e.maxLevelJump {
		return
	}

	if !e.isRuleEnabled(string(AlertSegmentationViolation)) {
		return
	}

	key := fmt.Sprintf("segmentation|%s|%s", packet.SrcIP, packet.DstIP)

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

			Type:     AlertSegmentationViolation,
			Severity: "high",
			Message: fmt.Sprintf(
				"%s (level %.1f) communicated directly with %s (level %.1f), skipping %.1f level(s)",
				packet.SrcIP, srcLevel, packet.DstIP, dstLevel, jump,
			),

			IP: packet.SrcIP,

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
