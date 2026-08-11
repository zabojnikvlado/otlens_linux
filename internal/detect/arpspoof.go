package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// handleARP tracks trusted IP->MAC identity. A conflicting MAC is deliberately
// never promoted merely because it repeats: an attacker can repeat spoofed ARP
// replies too. Promotion is an analyst decision (ApproveAlert) or a fresh
// learning/factory reset.
func (e *Engine) handleARP(packet core.Packet) {
	ip, mac := packet.ARPSrcIP, packet.ARPSrcMAC
	if ip == "" || ip == "0.0.0.0" || mac == "" {
		return
	}
	now := packet.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	e.observeGratuitousARP(packet, now)

	e.mutex.Lock()
	known, exists := e.knownMAC[ip]
	if !exists {
		e.knownMAC[ip] = mac
		e.mutex.Unlock()
		return
	}
	if known == mac {
		delete(e.candidateMAC, ip)
		delete(e.candidateCount, ip)
		e.mutex.Unlock()
		return
	}
	if e.candidateMAC[ip] == mac {
		e.candidateCount[ip]++
	} else {
		e.candidateMAC[ip], e.candidateCount[ip] = mac, 1
	}
	count := e.candidateCount[ip]
	e.mutex.Unlock()

	// Redundancy virtual MAC movement is expected in VRRP/HSRP environments.
	// We still track the candidate but don't call it spoofing by default.
	if isRedundancyVirtualMAC(known) && isRedundancyVirtualMAC(mac) {
		return
	}

	evidence := map[string]interface{}{"ip": ip, "previous_mac": known, "new_mac": mac, "candidate_claims": count}
	key := fmt.Sprintf("arp|%s|%s|%s", ip, known, mac)
	e.raiseBuiltinAlert(string(AlertARPSpoof), AlertARPSpoof, "high", key,
		fmt.Sprintf("%s is claimed by %s, previously %s", ip, mac, known), ip, evidence, now, alertEpisodeGap)
	// Preserve legacy structured fields used by Central/UI.
	e.mutex.Lock()
	if a := e.alerts[key]; a != nil {
		a.PreviousMAC, a.NewMAC = known, mac
	}
	e.mutex.Unlock()

	if count >= e.arpConfirmThreshold {
		e.raiseBuiltinAlert("builtin.duplicate_ip", AlertDuplicateIP, "high",
			fmt.Sprintf("duplicate-ip|%s|%s|%s", ip, known, mac),
			fmt.Sprintf("Duplicate IP identity: %s is persistently claimed by both %s and %s", ip, known, mac), ip, evidence, now, alertEpisodeGap)
		if e.isGatewayAsset(ip) {
			e.raiseBuiltinAlert("builtin.gateway_mac_changed", AlertGatewayMACChanged, "critical",
				fmt.Sprintf("gateway-mac|%s|%s|%s", ip, known, mac),
				fmt.Sprintf("Gateway/router %s MAC identity changed from %s to %s", ip, known, mac), ip, evidence, now, alertEpisodeGap)
		}
	}
}

func (e *Engine) observeGratuitousARP(packet core.Packet, now time.Time) {
	gratuitous := packet.ARPSrcIP != "" && packet.ARPSrcIP == packet.ARPDstIP
	if !gratuitous {
		return
	}
	key := packet.ARPSrcIP + "|" + packet.ARPSrcMAC
	window := time.Duration(e.builtinParameter("builtin.gratuitous_arp_storm", "window_seconds", 60)) * time.Second
	if window <= 0 {
		window = time.Minute
	}
	threshold := int(e.builtinParameter("builtin.gratuitous_arp_storm", "events_threshold", 20))
	if threshold < 1 {
		threshold = 1
	}
	e.policyMutex.Lock()
	xs := append(e.gratuitousARP[key], now)
	cut := now.Add(-window)
	j := 0
	for _, t := range xs {
		if !t.Before(cut) {
			xs[j] = t
			j++
		}
	}
	xs = xs[:j]
	if len(xs) > 256 {
		xs = xs[len(xs)-256:]
	}
	e.gratuitousARP[key] = xs
	count := len(xs)
	e.policyMutex.Unlock()
	if count >= threshold {
		e.raiseBuiltinAlert("builtin.gratuitous_arp_storm", AlertGratuitousARPStorm, "medium",
			"garp-storm|"+key,
			fmt.Sprintf("%s/%s emitted %d gratuitous ARP announcements within %s", packet.ARPSrcIP, packet.ARPSrcMAC, count, window), packet.ARPSrcIP,
			map[string]interface{}{"ip": packet.ARPSrcIP, "mac": packet.ARPSrcMAC, "gratuitous_arp_count": count, "window_seconds": window.Seconds(), "threshold": threshold}, now, window)
	}
}
