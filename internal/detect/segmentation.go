package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

const segmentationVLANObservationTTL = 30 * time.Minute

// SegmentationPolicyRule is an explicit source-zone -> destination-zone matrix
// entry. Wildcards are "*" or "any". The first matching entry wins. An empty
// policy retains the historical Purdue/VLAN max-level-jump fallback.
type SegmentationPolicyRule struct {
	SourceZone      string `json:"source_zone"`
	DestinationZone string `json:"destination_zone"`
	Protocol        string `json:"protocol"`
	Direction       string `json:"direction"`
	Allowed         bool   `json:"allowed"`
}

func (e *Engine) startSegmentationWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventPacketParsed)
	go func() {
		for event := range ch {
			if p, ok := event.Data.(core.Packet); ok {
				e.handleSegmentation(p)
			}
		}
	}()
}

func (e *Engine) ConfigureSegmentationPolicy(policy []SegmentationPolicyRule) {
	e.ipVLANMutex.Lock()
	e.segmentationPolicy = append([]SegmentationPolicyRule(nil), policy...)
	// An explicit zone matrix is independently useful even when the legacy
	// VLAN/Purdue fallback is disabled or no VLAN-level map is configured.
	e.segmentationEnabled = e.segmentationEnabled || len(policy) > 0
	e.ipVLANMutex.Unlock()
}

func validSegmentationPurdueLevel(level float64) bool {
	switch level {
	case 0, 1, 2, 3, 3.5, 4, 5:
		return true
	default:
		return false
	}
}

func (e *Engine) UpdateSegmentationConfig(vlanLevels map[uint16]float64, maxLevelJump float64) {
	if maxLevelJump <= 0 || maxLevelJump > 5 {
		maxLevelJump = 1
	}
	e.ipVLANMutex.Lock()
	defer e.ipVLANMutex.Unlock()
	levels := make(map[uint16]float64, len(vlanLevels))
	for vlan, level := range vlanLevels {
		if vlan > 4094 || !validSegmentationPurdueLevel(level) {
			continue
		}
		levels[vlan] = level
	}
	e.vlanLevels, e.maxLevelJump = levels, maxLevelJump
	e.segmentationManaged = true
	// Explicit asset-zone policy may work even without VLAN levels.
	e.segmentationEnabled = len(levels) > 0 || len(e.segmentationPolicy) > 0
}

// RestoreLocalSegmentationConfig relinquishes Central management and restores
// the validated detect.segmentation values loaded from the sensor YAML at
// startup. This matters when a sensor carrying a persisted Central-managed
// policy is enrolled into a fresh Central that has no segmentation policy.
func (e *Engine) RestoreLocalSegmentationConfig() {
	e.ipVLANMutex.Lock()
	defer e.ipVLANMutex.Unlock()
	// Central sends managed=false on every sync while it is not managing this
	// policy. Treat that as an idempotent state assertion, not a reset command:
	// clearing ipVLAN on every sync would prevent the local YAML Purdue fallback
	// from retaining independently ARP-confirmed VLAN membership long enough to
	// correlate traffic across segments. Only the actual managed -> local
	// transition invalidates observations learned under the Central policy.
	if !e.segmentationManaged {
		return
	}
	levels := make(map[uint16]float64, len(e.localVLANLevels))
	for vlan, level := range e.localVLANLevels {
		levels[vlan] = level
	}
	e.vlanLevels = levels
	e.maxLevelJump = e.localMaxLevelJump
	e.segmentationManaged = false
	e.segmentationEnabled = e.localSegmentationEnabled || len(e.segmentationPolicy) > 0
	// Do not carry IP->VLAN observations learned under a different policy.
	e.ipVLAN = make(map[string]uint16)
	e.ipVLANSeen = make(map[string]time.Time)
}

func wildcardMatch(want, got string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	got = strings.ToLower(strings.TrimSpace(got))
	return want == "" || want == "*" || want == "any" || want == got
}

func packetPolicyProtocol(p core.Packet) string {
	if x, ok := otServicePorts[p.DstPort]; ok {
		return x
	}
	if x, ok := remoteManagementPorts[p.DstPort]; ok {
		return x
	}
	if p.L4Protocol != "" {
		return strings.ToLower(p.L4Protocol)
	}
	return strings.ToLower(p.IPProtocol)
}

func (e *Engine) explicitSegmentationDecision(p core.Packet) (matched, allowed bool, srcZone, dstZone string) {
	src, sok := e.assetContext(p.SrcIP)
	dst, dok := e.assetContext(p.DstIP)
	if !sok || !dok || src.Zone == "" || dst.Zone == "" {
		return false, false, src.Zone, dst.Zone
	}
	proto := packetPolicyProtocol(p)
	e.ipVLANMutex.RLock()
	policy := append([]SegmentationPolicyRule(nil), e.segmentationPolicy...)
	e.ipVLANMutex.RUnlock()
	for _, r := range policy {
		if wildcardMatch(r.SourceZone, src.Zone) && wildcardMatch(r.DestinationZone, dst.Zone) && wildcardMatch(r.Protocol, proto) && wildcardMatch(r.Direction, "outbound") {
			return true, r.Allowed, src.Zone, dst.Zone
		}
	}
	return false, false, src.Zone, dst.Zone
}

func (e *Engine) arpConfirmsL2Endpoint(ip, mac string) bool {
	if ip == "" || mac == "" {
		return false
	}
	e.mutex.RLock()
	known := e.knownMAC[ip]
	e.mutex.RUnlock()
	return known != "" && strings.EqualFold(known, mac)
}

func (e *Engine) handleSegmentation(packet core.Packet) {
	if packet.SrcIP == "" || packet.DstIP == "" {
		return
	}

	if matched, allowed, srcZone, dstZone := e.explicitSegmentationDecision(packet); matched {
		if allowed {
			return
		}
		e.excludePacketFromLearning(packet, "explicit segmentation policy violation")
		now := packet.Timestamp
		if now.IsZero() {
			now = time.Now()
		}
		evidence := map[string]interface{}{"source_ip": packet.SrcIP, "destination_ip": packet.DstIP, "source_zone": srcZone, "destination_zone": dstZone, "protocol": packetPolicyProtocol(packet), "policy": "explicit_zone_matrix"}
		e.raiseBuiltinAlert(string(AlertSegmentationViolation), AlertSegmentationViolation, "high",
			fmt.Sprintf("segmentation-zone|%s|%s|%s", packet.SrcIP, packet.DstIP, packetPolicyProtocol(packet)),
			fmt.Sprintf("Segmentation policy denied %s -> %s (%s -> %s, %s)", packet.SrcIP, packet.DstIP, srcZone, dstZone, packetPolicyProtocol(packet)), packet.SrcIP, evidence, now, alertEpisodeGap)
		return
	}

	// Purdue/VLAN fallback learns IP membership only from an ARP-confirmed
	// IP<->MAC binding on the observed L2 segment. Reading the VLAN tag from a
	// routed frame and assigning it to both L3 endpoints is incorrect: the remote
	// endpoint is behind the router and does not belong to this VLAN. Once each
	// endpoint has independently been confirmed on its own segment, any routed
	// packet between their L3 addresses can be evaluated against both learned
	// VLAN memberships.
	srcDirect := e.arpConfirmsL2Endpoint(packet.SrcIP, packet.SrcMAC)
	dstDirect := e.arpConfirmsL2Endpoint(packet.DstIP, packet.DstMAC)

	e.ipVLANMutex.Lock()
	if !e.segmentationEnabled || len(e.vlanLevels) == 0 {
		e.ipVLANMutex.Unlock()
		return
	}
	if e.ipVLAN == nil {
		e.ipVLAN = map[string]uint16{}
	}
	if e.ipVLANSeen == nil {
		e.ipVLANSeen = map[string]time.Time{}
	}
	now := packet.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	if srcDirect {
		e.ipVLAN[packet.SrcIP] = packet.VLANID
		e.ipVLANSeen[packet.SrcIP] = now
	}
	if dstDirect {
		e.ipVLAN[packet.DstIP] = packet.VLANID
		e.ipVLANSeen[packet.DstIP] = now
	}

	lookup := func(ip string) (uint16, bool) {
		vlan, ok := e.ipVLAN[ip]
		if !ok {
			return 0, false
		}
		seen := e.ipVLANSeen[ip]
		if seen.IsZero() || now.Sub(seen) > segmentationVLANObservationTTL || now.Before(seen) {
			delete(e.ipVLAN, ip)
			delete(e.ipVLANSeen, ip)
			return 0, false
		}
		return vlan, true
	}
	srcVLAN, srcKnown := lookup(packet.SrcIP)
	dstVLAN, dstKnown := lookup(packet.DstIP)
	vlanLevels := e.vlanLevels
	maxJump := e.maxLevelJump
	e.ipVLANMutex.Unlock()
	if !srcKnown || !dstKnown || srcVLAN == dstVLAN {
		return
	}
	srcLevel, sok := vlanLevels[srcVLAN]
	dstLevel, dok := vlanLevels[dstVLAN]
	if !sok || !dok {
		return
	}
	jump := srcLevel - dstLevel
	if jump < 0 {
		jump = -jump
	}
	if jump <= maxJump {
		return
	}
	e.excludePacketFromLearning(packet, "Purdue segmentation policy violation")
	evidence := map[string]interface{}{"source_ip": packet.SrcIP, "destination_ip": packet.DstIP, "source_vlan": srcVLAN, "destination_vlan": dstVLAN, "source_level": srcLevel, "destination_level": dstLevel, "level_jump": jump, "policy": "purdue_fallback"}
	e.raiseBuiltinAlert(string(AlertSegmentationViolation), AlertSegmentationViolation, "high",
		fmt.Sprintf("segmentation|%s|%s", packet.SrcIP, packet.DstIP),
		fmt.Sprintf("%s (VLAN %d, level %.1f) communicated with %s (VLAN %d, level %.1f), jump %.1f exceeds %.1f", packet.SrcIP, srcVLAN, srcLevel, packet.DstIP, dstVLAN, dstLevel, jump, maxJump), packet.SrcIP, evidence, now, alertEpisodeGap)
}
