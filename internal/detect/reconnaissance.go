package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// startReconnaissanceWatch consumes core.EventPacketParsed to detect a
// source IP scanning the network — see handleReconnaissance.
func (e *Engine) startReconnaissanceWatch(bus *core.EventBus) {

	if !e.reconnaissanceEnabled {
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

			e.handleReconnaissance(packet)

		}

	}()

}

// handleReconnaissance tracks, per source IP, how many distinct
// destination hosts it's contacted (host/network scan) and, per source
// IP + destination IP pair, how many distinct ports on that one
// destination (port scan) — both within the last reconWindow. Pruned
// on every access rather than by a separate background sweep: an entry
// older than reconWindow is deleted the next time that source IP's
// tracker is touched at all, so memory use tracks actual recent
// activity without needing its own goroutine. A source that's
// legitimately supposed to talk to many hosts (a monitoring server, a
// DNS resolver) will trip this — see the rule's own comment in
// alert.go for how to handle that.
func (e *Engine) handleReconnaissance(packet core.Packet) {

	if !e.reconnaissanceEnabled || packet.SrcIP == "" || packet.DstIP == "" {
		return
	}

	now := time.Now()

	e.scanMutex.Lock()

	if e.hostScanSeen[packet.SrcIP] == nil {
		e.hostScanSeen[packet.SrcIP] = make(map[string]time.Time)
	}
	dstSeen := e.hostScanSeen[packet.SrcIP]
	dstSeen[packet.DstIP] = now
	for ip, t := range dstSeen {
		if now.Sub(t) > e.reconWindow {
			delete(dstSeen, ip)
		}
	}
	hostCount := len(dstSeen)

	var portCount int
	if packet.DstPort > 0 {
		if e.portScanSeen[packet.SrcIP] == nil {
			e.portScanSeen[packet.SrcIP] = make(map[string]map[int]time.Time)
		}
		if e.portScanSeen[packet.SrcIP][packet.DstIP] == nil {
			e.portScanSeen[packet.SrcIP][packet.DstIP] = make(map[int]time.Time)
		}
		portSeen := e.portScanSeen[packet.SrcIP][packet.DstIP]
		portSeen[int(packet.DstPort)] = now
		for p, t := range portSeen {
			if now.Sub(t) > e.reconWindow {
				delete(portSeen, p)
			}
		}
		portCount = len(portSeen)
	}

	e.scanMutex.Unlock()

	if hostCount >= e.hostScanThreshold {
		e.raiseReconnaissanceAlert(
			"hostscan|"+packet.SrcIP, packet.SrcIP,
			fmt.Sprintf("%s contacted %d distinct hosts within %s — possible network/host scan", packet.SrcIP, hostCount, e.reconWindow),
		)
	}
	if portCount >= e.portScanThreshold {
		e.raiseReconnaissanceAlert(
			"portscan|"+packet.SrcIP+"|"+packet.DstIP, packet.SrcIP,
			fmt.Sprintf("%s contacted %d distinct ports on %s within %s — possible port scan", packet.SrcIP, portCount, packet.DstIP, e.reconWindow),
		)
	}
}

func (e *Engine) raiseReconnaissanceAlert(key, ip, message string) {

	if !e.isRuleEnabled(string(AlertReconnaissance)) {
		return
	}

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

			Type:     AlertReconnaissance,
			Severity: "high",
			Message:  message,

			IP: ip,

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
