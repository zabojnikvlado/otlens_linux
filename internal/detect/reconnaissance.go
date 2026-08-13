package detect

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func (e *Engine) startReconnaissanceWatch(bus *core.EventBus) {
	if !e.reconnaissanceEnabled {
		return
	}
	ch := bus.Subscribe(core.EventPacketParsed)
	go func() {
		for event := range ch {
			if p, ok := event.Data.(core.Packet); ok {
				e.handleReconnaissance(p)
			}
		}
	}()
}

func (e *Engine) reconSignal(src, class string, now time.Time) int {
	key := src + "|" + class
	xs := append(e.reconSignals[key], now)
	cut := now.Add(-e.reconWindow)
	j := 0
	for _, t := range xs {
		if !t.Before(cut) {
			xs[j] = t
			j++
		}
	}
	xs = xs[:j]
	if len(xs) > 512 {
		xs = xs[len(xs)-512:]
	}
	e.reconSignals[key] = xs
	return len(xs)
}

func (e *Engine) handleReconnaissance(packet core.Packet) {
	if !e.reconnaissanceEnabled || packet.SrcIP == "" || packet.DstIP == "" {
		return
	}
	now := packet.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	e.scanMutex.Lock()
	if e.hostScanSeen[packet.SrcIP] == nil {
		e.hostScanSeen[packet.SrcIP] = map[string]time.Time{}
	}
	dstSeen := e.hostScanSeen[packet.SrcIP]
	dstSeen[packet.DstIP] = now
	for ip, t := range dstSeen {
		if now.Sub(t) > e.reconWindow {
			delete(dstSeen, ip)
		}
	}
	hostCount := len(dstSeen)
	portCount := 0
	if packet.DstPort > 0 {
		if e.portScanSeen[packet.SrcIP] == nil {
			e.portScanSeen[packet.SrcIP] = map[string]map[int]time.Time{}
		}
		if e.portScanSeen[packet.SrcIP][packet.DstIP] == nil {
			e.portScanSeen[packet.SrcIP][packet.DstIP] = map[int]time.Time{}
		}
		ps := e.portScanSeen[packet.SrcIP][packet.DstIP]
		ps[int(packet.DstPort)] = now
		for p, t := range ps {
			if now.Sub(t) > e.reconWindow {
				delete(ps, p)
			}
		}
		portCount = len(ps)
	}
	class := "host_scan"
	flags := strings.ToUpper(packet.TCPFlags)
	switch {
	case strings.Contains(strings.ToLower(packet.IPProtocol), "icmp") || strings.Contains(strings.ToLower(packet.L4Protocol), "icmp"):
		class = "icmp_sweep"
	case packet.L4Protocol == "TCP" && strings.Contains(flags, "SYN") && !strings.Contains(flags, "ACK"):
		class = "tcp_syn_scan"
	case packet.L4Protocol == "TCP":
		class = "tcp_connect_scan"
	case packet.L4Protocol == "UDP":
		class = "udp_service_scan"
	}
	ip := net.ParseIP(packet.DstIP)
	specialCount := 0
	routineDiscovery := routineDiscoveryTraffic(packet)
	if ip != nil && ip.IsMulticast() {
		class = "multicast_discovery"
		if !routineDiscovery {
			specialCount = e.reconSignal(packet.SrcIP, class, now)
		}
	}
	if packet.DstIP == "255.255.255.255" || groupDestination(packet) && (ip == nil || !ip.IsMulticast()) {
		class = "broadcast_discovery"
		if !routineDiscovery {
			specialCount = e.reconSignal(packet.SrcIP, class, now)
		}
	}
	if proto, ok := otServicePorts[packet.DstPort]; ok && hostCount >= maxReconInt(5, e.hostScanThreshold/2) {
		class = "ot_protocol_discovery_" + proto
	}
	e.scanMutex.Unlock()

	if e.behaviorDetectionsSuppressed() {
		return
	}
	ctx, _ := e.assetContext(packet.SrcIP)
	hostThreshold, portThreshold, discoveryThreshold := e.hostScanThreshold, e.portScanThreshold, 40
	if isTrustedDiscoveryRole(ctx.Role) {
		// NMS/vulnerability scanners legitimately fan out. Explicit operator
		// classification does not silence them completely, but requires a much
		// stronger deviation before creating a reconnaissance alert.
		hostThreshold *= 4
		portThreshold *= 4
		discoveryThreshold *= 4
	}
	evidence := func(kind string) map[string]interface{} {
		return map[string]interface{}{"scan_type": kind, "source_ip": packet.SrcIP, "source_role": ctx.Role, "source_zone": ctx.Zone, "distinct_hosts": hostCount, "distinct_ports": portCount, "host_threshold": hostThreshold, "port_threshold": portThreshold, "discovery_threshold": discoveryThreshold, "routine_discovery": routineDiscovery, "window": e.reconWindow.String(), "latest_target": packet.DstIP, "latest_port": packet.DstPort}
	}
	if specialCount >= discoveryThreshold {
		e.raiseBuiltinAlert(string(AlertReconnaissance), AlertReconnaissance, "high", "recon|"+class+"|"+packet.SrcIP,
			fmt.Sprintf("%s (%s) generated %d %s packets within %s", packet.SrcIP, roleLabel(ctx.Role), specialCount, class, e.reconWindow), packet.SrcIP, evidence(class), now, e.reconWindow)
		return
	}
	if hostCount >= hostThreshold {
		e.raiseBuiltinAlert(string(AlertReconnaissance), AlertReconnaissance, "high", "hostscan|"+class+"|"+packet.SrcIP,
			fmt.Sprintf("%s (%s) contacted %d distinct hosts within %s — %s", packet.SrcIP, roleLabel(ctx.Role), hostCount, e.reconWindow, class), packet.SrcIP, evidence(class), now, e.reconWindow)
	}
	if portCount >= portThreshold {
		kind := "port_scan"
		if packet.L4Protocol == "TCP" && strings.Contains(flags, "SYN") {
			kind = "tcp_syn_port_scan"
		} else if packet.L4Protocol == "UDP" {
			kind = "udp_port_scan"
		}
		e.raiseBuiltinAlert(string(AlertReconnaissance), AlertReconnaissance, "high", "portscan|"+kind+"|"+packet.SrcIP+"|"+packet.DstIP,
			fmt.Sprintf("%s (%s) contacted %d distinct ports on %s within %s — %s", packet.SrcIP, roleLabel(ctx.Role), portCount, packet.DstIP, e.reconWindow, kind), packet.SrcIP, evidence(kind), now, e.reconWindow)
	}
}

func isTrustedDiscoveryRole(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return strings.Contains(r, "scanner") || strings.Contains(r, "monitoring") || strings.Contains(r, "nms") ||
		strings.Contains(r, "vulnerability") || strings.Contains(r, "discovery") || strings.Contains(r, "inventory")
}

func roleLabel(role string) string {
	if strings.TrimSpace(role) == "" {
		return "unclassified"
	}
	return role
}
func maxReconInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
