package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func (e *Engine) startLateralMovementWatch(bus *core.EventBus) {
	if !e.lateral.Enabled {
		return
	}
	ch := bus.Subscribe(core.EventPacketParsed)
	go func() {
		for ev := range ch {
			if p, ok := ev.Data.(core.Packet); ok {
				e.handleLateralMovement(p)
			}
		}
	}()
}
func (e *Engine) isAdminPort(p uint16) bool {
	for _, x := range e.lateral.AdminPorts {
		if p == x {
			return true
		}
	}
	return false
}
func (e *Engine) handleLateralMovement(p core.Packet) {
	if p.SrcIP == "" || p.DstIP == "" || !isPrivateIP(p.SrcIP) || !isPrivateIP(p.DstIP) || p.SrcIP == p.DstIP {
		return
	}
	if !e.isAdminPort(p.DstPort) {
		return
	}
	now := p.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	e.lateralData.mutex.Lock()
	if e.lateralData.fanout[p.SrcIP] == nil {
		e.lateralData.fanout[p.SrcIP] = map[string]time.Time{}
	}
	fo := e.lateralData.fanout[p.SrcIP]
	fo[p.DstIP] = now
	cut := now.Add(-e.lateral.Window)
	for k, t := range fo {
		if t.Before(cut) {
			delete(fo, k)
		}
	}
	fanout := len(fo)
	transferKey := fmt.Sprintf("%s|%s|%d", p.SrcIP, p.DstIP, p.DstPort)
	tw := e.lateralData.transfers[transferKey]
	if tw == nil || now.Sub(tw.LastSeen) > e.lateral.Window {
		tw = &trafficWindow{FirstSeen: now}
		e.lateralData.transfers[transferKey] = tw
	}
	tw.LastSeen = now
	tw.Bytes += uint64(maxInt(p.Length, 0))
	bytes := tw.Bytes
	if e.lateralData.inboundAdmin[p.DstIP] == nil {
		e.lateralData.inboundAdmin[p.DstIP] = map[string]time.Time{}
	}
	e.lateralData.inboundAdmin[p.DstIP][p.SrcIP] = now
	pivots := []string{}
	if incoming := e.lateralData.inboundAdmin[p.SrcIP]; incoming != nil {
		for origin, t := range incoming {
			if origin != p.DstIP && now.Sub(t) <= e.lateral.PivotWindow {
				pivots = append(pivots, origin)
			}
		}
	}
	e.lateralData.mutex.Unlock()
	if e.behaviorDetectionsSuppressed() {
		return
	}
	if fanout >= e.lateral.FanOutThreshold {
		e.raiseLateral("admin_fanout", p.SrcIP, p.DstIP, p.DstPort, 85, fmt.Sprintf("%s contacted %d internal hosts over administrative services within %s", p.SrcIP, fanout, e.lateral.Window), map[string]interface{}{"lateral_movement_score": 85, "lateral_movement_confidence": 80, "fanout_hosts": fanout, "destination_port": p.DstPort})
	}
	if bytes >= e.lateral.LargeTransferBytes {
		e.raiseLateral("large_admin_transfer", p.SrcIP, p.DstIP, p.DstPort, 75, fmt.Sprintf("%s transferred at least %d bytes to %s over administrative port %d", p.SrcIP, bytes, p.DstIP, p.DstPort), map[string]interface{}{"lateral_movement_score": 75, "lateral_movement_confidence": 65, "bytes": bytes, "destination_port": p.DstPort})
	}
	for _, origin := range pivots {
		e.raiseLateral("sequential_pivot", p.SrcIP, p.DstIP, p.DstPort, 90, fmt.Sprintf("observed sequential administrative pivot %s → %s → %s", origin, p.SrcIP, p.DstIP), map[string]interface{}{"lateral_movement_score": 90, "lateral_movement_confidence": 80, "origin_ip": origin, "pivot_ip": p.SrcIP, "destination_ip": p.DstIP, "destination_port": p.DstPort})
	}
}
func (e *Engine) raiseLateral(kind, src, dst string, port uint16, score int, message string, evidence map[string]interface{}) {
	if !e.isRuleEnabled(string(AlertLateralMovement)) {
		return
	}
	id := fmt.Sprintf("lateral|%s|%s|%s|%d", kind, src, dst, port)
	if kind == "admin_fanout" {
		// Fan-out is a source-host behavior, not one finding per destination.
		// Keying it by the latest destination multiplied one scan into hundreds
		// of distinct alerts. Keep the current destination in evidence instead.
		id = fmt.Sprintf("lateral|%s|%s", kind, src)
	}
	now := time.Now()
	evidence["signal"] = kind
	evidence["source_ip"] = src
	evidence["destination_ip"] = dst
	e.mutex.Lock()
	defer e.mutex.Unlock()
	a, exists := e.alerts[id]
	if exists && a.Status == AlertStatusApproved {
		return
	}
	sev := "high"
	if score >= 90 {
		sev = "critical"
	}
	if !exists {
		a = &Alert{ID: id, Type: AlertLateralMovement, Severity: sev, Message: message, IP: src, FirstSeen: now, Status: AlertStatusNew, Evidence: evidence}
		e.alerts[id] = a
		e.logNewAlert(a)
	} else {
		a.Message = message
		a.Evidence = evidence
		if sev == "critical" {
			a.Severity = sev
		}
	}
	e.recordEpisodeAlertLocked(a, now, e.lateral.Window)
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
