package detect

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/netutil"
)

func (e *Engine) startExternalCommunicationWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventPacketParsed)
	go func() {
		for event := range ch {
			if packet, ok := event.Data.(core.Packet); ok {
				e.handleExternalCommunication(packet)
			}
		}
	}()
}

// handleExternalCommunication keeps outbound and inbound exposure separate.
// Alerts are grouped by external network scope (/24 for IPv4, /64 for IPv6).
// That keeps CDN-style endpoint churn bounded while making analyst approval
// safe: approving one legitimate destination network does not suppress every
// future Internet destination for the same OT asset.
func (e *Engine) handleExternalCommunication(packet core.Packet) {
	if packet.SrcIP == "" || packet.DstIP == "" {
		return
	}
	srcPrivate, dstPrivate := isPrivateIP(packet.SrcIP), isPrivateIP(packet.DstIP)
	internalIP, externalIP, direction, peerPort := "", "", "", uint16(0)
	switch {
	case srcPrivate && netutil.IsPublicInternetUnicast(packet.DstIP):
		internalIP, externalIP, direction, peerPort = packet.SrcIP, packet.DstIP, "outbound", packet.DstPort
	case dstPrivate && netutil.IsPublicInternetUnicast(packet.SrcIP):
		internalIP, externalIP, direction, peerPort = packet.DstIP, packet.SrcIP, "inbound", packet.SrcPort
	default:
		return
	}
	e.excludePacketFromLearning(packet, "external communication requires explicit policy approval")
	now := packet.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	scope := externalPeerScope(externalIP)
	bucket := direction + "|" + internalIP + "|" + scope
	peerKey := fmt.Sprintf("%s:%d", externalIP, peerPort)
	e.policyMutex.Lock()
	if e.externalPeers == nil {
		e.externalPeers = make(map[string]map[string]bool)
	}
	if e.externalPeers[bucket] == nil {
		e.externalPeers[bucket] = map[string]bool{}
	}
	e.externalPeers[bucket][peerKey] = true
	// Keep memory bounded; the current peer remains evidence even when older
	// peers are evicted from the summary set.
	if len(e.externalPeers[bucket]) > 64 {
		for k := range e.externalPeers[bucket] {
			if k != peerKey {
				delete(e.externalPeers[bucket], k)
				if len(e.externalPeers[bucket]) <= 64 {
					break
				}
			}
		}
	}
	peers := make([]string, 0, len(e.externalPeers[bucket]))
	for k := range e.externalPeers[bucket] {
		peers = append(peers, k)
	}
	e.policyMutex.Unlock()
	sort.Strings(peers)
	shown := peers
	if len(shown) > 20 {
		shown = shown[len(shown)-20:]
	}

	ti := false
	if e.threatIntel != nil {
		_, ti = e.threatIntel.MatchIP(externalIP)
	}
	severity := "medium"
	if direction == "inbound" {
		severity = "high"
	}
	evidence := map[string]interface{}{
		"direction": direction, "internal_ip": internalIP, "external_ip": externalIP, "external_scope": scope,
		"external_port": peerPort, "destinations_seen": shown, "destination_count": len(peers),
		"threat_intel_match": ti,
	}
	e.raiseBuiltinAlert(string(AlertExternalCommunication), AlertExternalCommunication, severity,
		fmt.Sprintf("external|%s|%s|%s", direction, internalIP, scope),
		fmt.Sprintf("%s external communication: %s <-> %s:%d (%d public endpoint(s) observed)", direction, internalIP, externalIP, peerPort, len(peers)),
		internalIP, evidence, now, alertEpisodeGap)
}

// externalPeerScope returns a stable analyst-approval scope. It deliberately
// groups nearby public endpoints without turning an approval into an
// asset-wide Internet allow rule.
func externalPeerScope(ipText string) string {
	ip := net.ParseIP(ipText)
	if ip == nil {
		return ipText
	}
	if v4 := ip.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}
