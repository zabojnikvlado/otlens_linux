package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/ics"
)

// handleICS promotes ics parser findings already flagged
// security-relevant (S7 PLCStop/PLCControl, block download — see
// internal/ics/s7comm.go) into a proper deduplicated Alert. The ics
// engine and store engine both log these via logger.Log.Warn as they
// happen; this is what makes them queryable/counted over time rather
// than just scrolling past in the log.
func (e *Engine) handleICS(msg ics.Message) {

	if !e.isRuleEnabled(string(AlertICSCriticalOperation)) {
		return
	}

	relevant, _ := msg.Details["security_relevant"].(bool)

	if !relevant {
		return
	}

	// Deduplicated per (protocol, function, target device): repeated
	// PLCStop attempts against the same PLC update one alert's
	// Count/LastSeen rather than creating a new one each time, but a
	// PLCStop against a *different* PLC is its own finding.
	key := fmt.Sprintf(
		"ics|%s|%s|%s:%d",
		msg.Protocol,
		msg.FunctionName,
		msg.DstIP,
		msg.DstPort,
	)

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

			Type:     AlertICSCriticalOperation,
			Severity: "critical",
			Message: fmt.Sprintf(
				"%s %s directed at %s:%d",
				msg.Protocol, msg.FunctionName, msg.DstIP, msg.DstPort,
			),

			IP: msg.DstIP,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)
	}

	alert.LastSeen = now
	alert.Count++
}
