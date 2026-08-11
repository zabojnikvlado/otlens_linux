package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

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

func (e *Engine) UpdateSegmentationConfig(vlanLevels map[uint16]float64, maxLevelJump float64) {
	if maxLevelJump <= 0 {
		maxLevelJump = 1
	}
	e.ipVLANMutex.Lock()
	defer e.ipVLANMutex.Unlock()
	e.vlanLevels, e.maxLevelJump = vlanLevels, maxLevelJump
	// Explicit asset-zone policy may work even without VLAN levels.
	e.segmentationEnabled = len(vlanLevels) > 0 || len(e.segmentationPolicy) > 0
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

	e.ipVLANMutex.Lock()
	if !e.segmentationEnabled || len(e.vlanLevels) == 0 {
		e.ipVLANMutex.Unlock()
		return
	}
	if e.ipVLAN == nil {
		e.ipVLAN = map[string]uint16{}
	}
	dstVLAN, dstKnown := e.ipVLAN[packet.DstIP]
	e.ipVLAN[packet.SrcIP] = packet.VLANID
	vlanLevels, maxJump := e.vlanLevels, e.maxLevelJump
	e.ipVLANMutex.Unlock()
	if !dstKnown {
		return
	}
	srcLevel, sok := vlanLevels[packet.VLANID]
	dstLevel, dok := vlanLevels[dstVLAN]
	if !sok || !dok || packet.VLANID == dstVLAN {
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
	now := packet.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	evidence := map[string]interface{}{"source_ip": packet.SrcIP, "destination_ip": packet.DstIP, "source_vlan": packet.VLANID, "destination_vlan": dstVLAN, "source_level": srcLevel, "destination_level": dstLevel, "level_jump": jump, "policy": "purdue_fallback"}
	e.raiseBuiltinAlert(string(AlertSegmentationViolation), AlertSegmentationViolation, "high",
		fmt.Sprintf("segmentation|%s|%s", packet.SrcIP, packet.DstIP),
		fmt.Sprintf("%s (level %.1f) communicated directly with %s (level %.1f), jump %.1f exceeds %.1f", packet.SrcIP, srcLevel, packet.DstIP, dstLevel, jump, maxJump), packet.SrcIP, evidence, now, alertEpisodeGap)
}
