package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// handleARP implements ARP spoofing detection: track the last
// confirmed MAC address claimed for each IP, and raise/update an
// Alert whenever a different MAC claims the same IP.
func (e *Engine) handleARP(packet core.Packet) {

	if !e.isRuleEnabled(string(AlertARPSpoof)) {
		return
	}

	ip := packet.ARPSrcIP
	mac := packet.ARPSrcMAC

	// Gratuitous ARP probes (sender IP 0.0.0.0, used for duplicate
	// address detection before a host has configured an address yet)
	// aren't an identity claim about that IP — nothing to track.
	if ip == "" || ip == "0.0.0.0" || mac == "" {
		return
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	known, exists := e.knownMAC[ip]

	if !exists {

		e.knownMAC[ip] = mac
		return
	}

	if known == mac {

		// Consistent with what we already know — clear out any
		// half-confirmed candidate from an earlier blip.
		delete(e.candidateMAC, ip)
		delete(e.candidateCount, ip)
		return
	}

	if e.candidateMAC[ip] == mac {
		e.candidateCount[ip]++
	} else {
		e.candidateMAC[ip] = mac
		e.candidateCount[ip] = 1
	}

	e.raiseARPAlert(ip, known, mac)

	if e.candidateCount[ip] >= e.arpConfirmThreshold {

		// The conflicting MAC has now repeated enough times to
		// accept as the new legitimate mapping, so future packets
		// from it don't keep re-triggering the alert. If it flips
		// back and forth between two MACs, each flip still raises
		// its own (deduplicated) alert via raiseARPAlert.
		e.knownMAC[ip] = mac
		delete(e.candidateMAC, ip)
		delete(e.candidateCount, ip)
	}
}

// raiseARPAlert creates or updates the deduplicated Alert for one
// specific (ip, previousMAC, newMAC) conflict. Caller must hold
// e.mutex.
func (e *Engine) raiseARPAlert(ip, previousMAC, newMAC string) {

	key := fmt.Sprintf("arp|%s|%s|%s", ip, previousMAC, newMAC)

	now := time.Now()

	alert, exists := e.alerts[key]

	if !exists {

		alert = &Alert{
			ID: key,

			Type:     AlertARPSpoof,
			Severity: "high",
			Message: fmt.Sprintf(
				"%s is claimed by %s, previously %s",
				ip, newMAC, previousMAC,
			),

			IP: ip,

			PreviousMAC: previousMAC,
			NewMAC:      newMAC,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)
	}

	alert.LastSeen = now
	alert.Count++
}
