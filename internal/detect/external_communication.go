package detect

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/netutil"
)

const (
	externalFlowSweepInterval = time.Minute
	maxTrackedExternalFlows   = 50000
)

type externalFlowState struct {
	Direction string
	Protocol  string
	LastSeen  time.Time
}

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

// handleExternalCommunication reports the direction in which the external
// conversation was initiated, not the direction of the individual packet.
// Replies that belong to an already-observed outbound UDP/TCP flow therefore
// remain part of the outbound finding instead of becoming a second inbound
// alert. This is particularly important for request/response protocols such as
// DNS and NTP.
//
// Alerts are grouped by external network scope (/24 for IPv4, /64 for IPv6).
// That keeps CDN-style endpoint churn bounded while making analyst approval
// safe: approving one legitimate destination network does not suppress every
// future Internet destination for the same OT asset.
func (e *Engine) handleExternalCommunication(packet core.Packet) {
	if packet.SrcIP == "" || packet.DstIP == "" {
		return
	}

	srcPrivate, dstPrivate := isPrivateIP(packet.SrcIP), isPrivateIP(packet.DstIP)
	internalIP, externalIP := "", ""
	internalPort, externalPort := uint16(0), uint16(0)
	srcIsInternal := false
	switch {
	case srcPrivate && netutil.IsPublicInternetUnicast(packet.DstIP):
		internalIP, externalIP = packet.SrcIP, packet.DstIP
		internalPort, externalPort = packet.SrcPort, packet.DstPort
		srcIsInternal = true
	case dstPrivate && netutil.IsPublicInternetUnicast(packet.SrcIP):
		internalIP, externalIP = packet.DstIP, packet.SrcIP
		internalPort, externalPort = packet.DstPort, packet.SrcPort
	default:
		return
	}

	now := packet.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	direction, correlated, ok := e.externalConversationDirection(packet, internalIP, externalIP, internalPort, externalPort, srcIsInternal, now)
	if !ok {
		// A TCP capture can start in the middle of an already-established
		// connection. Without a SYN/SYN-ACK (or existing flow state) we cannot
		// safely tell whether a public->private data packet is an unsolicited
		// inbound connection or merely a response. Prefer no direction alert to
		// a false HIGH finding; the next new handshake will establish direction.
		return
	}

	e.excludePacketFromLearning(packet, "external communication requires explicit policy approval")

	scope := externalPeerScope(externalIP)
	bucket := direction + "|" + internalIP + "|" + scope
	peerKey := fmt.Sprintf("%s:%d", externalIP, externalPort)
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
		"internal_port": internalPort, "external_port": externalPort, "destinations_seen": shown, "destination_count": len(peers),
		"response_correlated": correlated, "threat_intel_match": ti,
	}

	message := ""
	if direction == "inbound" {
		message = fmt.Sprintf("inbound external communication: %s:%d -> %s:%d (%d public endpoint(s) observed)", externalIP, externalPort, internalIP, internalPort, len(peers))
	} else {
		message = fmt.Sprintf("outbound external communication: %s:%d -> %s:%d (%d public endpoint(s) observed)", internalIP, internalPort, externalIP, externalPort, len(peers))
	}
	e.raiseBuiltinAlert(string(AlertExternalCommunication), AlertExternalCommunication, severity,
		fmt.Sprintf("external|%s|%s|%s", direction, internalIP, scope),
		message, internalIP, evidence, now, alertEpisodeGap)
}

// externalConversationDirection returns the initiator direction for the
// bidirectional five-tuple represented by packet. correlated is true when the
// packet matched existing state (for example an NTP response to an outbound
// request). ok=false means direction is intentionally unknown.
func (e *Engine) externalConversationDirection(packet core.Packet, internalIP, externalIP string, internalPort, externalPort uint16, srcIsInternal bool, now time.Time) (direction string, correlated bool, ok bool) {
	protocol := strings.ToUpper(strings.TrimSpace(packet.L4Protocol))
	if protocol == "" {
		protocol = strings.ToUpper(strings.TrimSpace(packet.IPProtocol))
	}
	key := externalFlowKey(protocol, internalIP, internalPort, externalIP, externalPort)

	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if e.externalFlows == nil {
		e.externalFlows = make(map[string]externalFlowState)
	}
	if e.externalFlowLastSweep.IsZero() || now.Sub(e.externalFlowLastSweep) >= externalFlowSweepInterval {
		for flowKey, state := range e.externalFlows {
			if now.Sub(state.LastSeen) > externalFlowTimeout(state.Protocol) {
				delete(e.externalFlows, flowKey)
			}
		}
		e.externalFlowLastSweep = now
	}

	if state, exists := e.externalFlows[key]; exists {
		if now.Sub(state.LastSeen) <= externalFlowTimeout(state.Protocol) {
			state.LastSeen = now
			e.externalFlows[key] = state
			return state.Direction, true, true
		}
		delete(e.externalFlows, key)
	}

	if protocol == "TCP" {
		flags := strings.ToUpper(packet.TCPFlags)
		syn := strings.Contains(flags, "SYN")
		ack := strings.Contains(flags, "ACK")
		switch {
		case syn && !ack && srcIsInternal:
			direction = "outbound"
		case syn && !ack && !srcIsInternal:
			direction = "inbound"
		case syn && ack && srcIsInternal:
			// We missed the public SYN; an internal SYN-ACK proves that the
			// connection was initiated from outside.
			direction = "inbound"
		case syn && ack && !srcIsInternal:
			// We missed the internal SYN; a public SYN-ACK proves that this is
			// the response leg of an outbound connection.
			direction = "outbound"
		default:
			return "", false, false
		}
	} else if srcIsInternal {
		direction = "outbound"
	} else {
		direction = "inbound"
	}

	// Keep runtime state bounded even on very busy SPAN/TAP links. The regular
	// expiry sweep normally keeps this far below the cap; if every tuple is
	// genuinely active, evict one old map entry rather than allowing an
	// unbounded detector-side allocation.
	if len(e.externalFlows) >= maxTrackedExternalFlows {
		for oldKey := range e.externalFlows {
			delete(e.externalFlows, oldKey)
			break
		}
	}
	e.externalFlows[key] = externalFlowState{Direction: direction, Protocol: protocol, LastSeen: now}
	return direction, false, true
}

func externalFlowKey(protocol, internalIP string, internalPort uint16, externalIP string, externalPort uint16) string {
	return fmt.Sprintf("%s|%s|%d|%s|%d", protocol, internalIP, internalPort, externalIP, externalPort)
}

func externalFlowTimeout(protocol string) time.Duration {
	switch strings.ToUpper(protocol) {
	case "TCP":
		return 15 * time.Minute
	case "UDP":
		return 2 * time.Minute
	case "ICMP", "ICMPV6":
		return 30 * time.Second
	default:
		return 2 * time.Minute
	}
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
