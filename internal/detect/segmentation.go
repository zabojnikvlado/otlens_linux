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
//
// Always subscribes, even if segmentation starts disabled — enabled/
// vlanLevels/maxLevelJump can all change later at runtime (see
// UpdateSegmentationConfig, pushed from Central when an admin edits
// the Network Segmentation tab), and if this early-returned instead of
// subscribing, a later live-enable would have nothing listening to
// turn on.
func (e *Engine) startSegmentationWatch(bus *core.EventBus) {

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
// UpdateSegmentationConfig replaces the VLAN-level mapping and
// max-jump threshold used by handleSegmentation, and enables the rule
// if vlanLevels is non-empty (there's no point receiving a real
// mapping from Central and having it silently ignored because the
// sensor's own local config file still says segmentation.enabled:
// false — configuring VLAN levels via the Network Segmentation tab is
// itself the "yes, use this" signal). An empty/nil vlanLevels disables
// the rule again (nothing to check against) without needing a
// separate "disable" command.
//
// Called from cmd/otlens's command handler for the "segmentation.config"
// command, which Central queues whenever an admin edits a sensor's VLAN
// configuration — see internal/central's setVLANConfig. Thread-safe:
// e.vlanLevels is *replaced* wholesale (never mutated in place), so a
// concurrent handleSegmentation call already holding a reference to the
// old map is never affected by this update mid-flight.
func (e *Engine) UpdateSegmentationConfig(vlanLevels map[uint16]float64, maxLevelJump float64) {

	if maxLevelJump <= 0 {
		maxLevelJump = 1
	}

	e.ipVLANMutex.Lock()
	defer e.ipVLANMutex.Unlock()

	e.vlanLevels = vlanLevels
	e.maxLevelJump = maxLevelJump
	e.segmentationEnabled = len(vlanLevels) > 0

}

func (e *Engine) handleSegmentation(packet core.Packet) {

	if packet.SrcIP == "" || packet.DstIP == "" {
		return
	}

	// segmentationEnabled/vlanLevels/maxLevelJump can all change live —
	// see UpdateSegmentationConfig — so, unlike most of this engine's
	// config fields, they're no longer safe to read without a lock.
	// Reusing ipVLANMutex for this (rather than a separate lock) since
	// it's already held for every packet here anyway, and these fields
	// are read together with ipVLAN in the same critical section.
	e.ipVLANMutex.Lock()
	if !e.segmentationEnabled {
		e.ipVLANMutex.Unlock()
		return
	}
	if e.ipVLAN == nil {
		e.ipVLAN = make(map[string]uint16)
	}
	dstVLAN, dstKnown := e.ipVLAN[packet.DstIP]
	e.ipVLAN[packet.SrcIP] = packet.VLANID
	vlanLevels := e.vlanLevels
	maxLevelJump := e.maxLevelJump
	e.ipVLANMutex.Unlock()

	if !dstKnown {
		return
	}

	srcLevel, srcKnown := vlanLevels[packet.VLANID]
	dstLevel, dstLevelKnown := vlanLevels[dstVLAN]

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
	if jump <= maxLevelJump {
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

	if exists && alert.Status == AlertStatusApproved {
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

	e.recordEpisodeAlertLocked(alert, now, alertEpisodeGap)

}
