package detect

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// builtinRuleIDForAlert returns the canonical product rule ID for typed
// detectors whose historical rule ID is not the same as their alert type.
// Existing alert-type IDs remain unchanged for backward compatibility.
func builtinRuleIDForAlert(t AlertType) string {
	switch t {
	case AlertGatewayMACChanged:
		return "builtin.gateway_mac_changed"
	case AlertDuplicateIP:
		return "builtin.duplicate_ip"
	case AlertGratuitousARPStorm:
		return "builtin.gratuitous_arp_storm"
	case AlertUnauthorizedOTCommand:
		return "builtin.unauthorized_ot_command"
	case AlertControllerProgramChange:
		return "builtin.controller_program_change"
	case AlertControllerModeChange:
		return "builtin.controller_mode_change"
	case AlertControllerConfigChange:
		return "builtin.controller_configuration_change"
	case AlertUnauthorizedOTWrite:
		return "builtin.unauthorized_ot_write"
	case AlertNewEngineeringWorkstation:
		return "builtin.new_engineering_workstation"
	case AlertSMBToolTransfer:
		return "builtin.smb_tool_transfer"
	case AlertBruteForceIO:
		return "builtin.brute_force_io"
	case AlertAssetIdentityDrift:
		return "builtin.asset_identity_drift"
	case AlertDNSTunneling:
		return "builtin.dns_tunneling"
	case AlertUnexpectedOTProtocol:
		return "builtin.unexpected_ot_protocol"
	case AlertFirmwareChange:
		return "builtin.firmware_change"
	case AlertUnauthorizedTimeChange:
		return "builtin.unauthorized_time_change"
	case AlertProcessSequenceViolation:
		return "builtin.process_sequence_violation"
	case AlertOTReportingLoss:
		return "builtin.ot_reporting_loss"
	case AlertMalformedOTBurst:
		return "builtin.malformed_ot_burst"
	case AlertFirstSeenRemoteManagement:
		return "builtin.first_seen_remote_management"
	case AlertRemoteAdminIntoOT:
		return "builtin.remote_management_into_ot"
	case AlertDirectOTProtocolAccess:
		return "builtin.direct_ot_protocol_access"
	case AlertSMBIntoOT:
		return "builtin.smb_into_ot"
	case AlertUnexpectedEngineeringAccess:
		return "builtin.unexpected_engineering_access"
	case AlertLargeControllerTransfer:
		return "builtin.large_controller_transfer"
	default:
		return string(t)
	}
}

// scheduleAllows is intentionally small and deterministic. "always" is the
// default. Operators may also use UTC windows such as "08:00-18:00" or
// "mon,tue,wed@08:00-18:00". This makes the Schedule policy knob real for
// built-ins/custom rules without pretending to be a full cron implementation.
func scheduleAllows(schedule string, now time.Time) bool {
	schedule = strings.TrimSpace(strings.ToLower(schedule))
	if schedule == "" || schedule == "always" {
		return true
	}
	dayPart, window := "", schedule
	if i := strings.Index(schedule, "@"); i >= 0 {
		dayPart, window = schedule[:i], schedule[i+1:]
		allowed := false
		wd := strings.ToLower(now.UTC().Weekday().String()[:3])
		for _, d := range strings.Split(dayPart, ",") {
			d = strings.TrimSpace(d)
			if d == wd || (d == "weekday" && wd != "sat" && wd != "sun") || (d == "weekend" && (wd == "sat" || wd == "sun")) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	parts := strings.Split(window, "-")
	if len(parts) != 2 {
		// Unknown schedule syntax is fail-closed for alert generation.
		return false
	}
	parse := func(v string) (int, bool) {
		x := strings.Split(strings.TrimSpace(v), ":")
		if len(x) != 2 {
			return 0, false
		}
		h, e1 := strconv.Atoi(x[0])
		m, e2 := strconv.Atoi(x[1])
		if e1 != nil || e2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
			return 0, false
		}
		return h*60 + m, true
	}
	start, ok1 := parse(parts[0])
	end, ok2 := parse(parts[1])
	if !ok1 || !ok2 {
		return false
	}
	minute := now.UTC().Hour()*60 + now.UTC().Minute()
	if start <= end {
		return minute >= start && minute < end
	}
	return minute >= start || minute < end
}

// builtinParameter returns a per-sensor operator override or the product
// default. Detectors use this for numeric thresholds while rule definitions
// remain immutable.
func (e *Engine) builtinParameter(ruleID, key string, fallback float64) float64 {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	if r := e.rules[ruleID]; r != nil && r.Parameters != nil {
		if value, ok := r.Parameters[key]; ok {
			return value
		}
	}
	return fallback
}

// raiseBuiltinAlert is the common product-rule execution path. It applies the
// operator policy layer (enabled, severity override, simulation, schedule and
// suppression) while keeping detector logic/product metadata immutable.
func (e *Engine) raiseBuiltinAlert(ruleID string, alertType AlertType, fallbackSeverity, key, message, ip string, evidence map[string]interface{}, now time.Time, episodeGap time.Duration) bool {
	if ruleID == "" {
		ruleID = builtinRuleIDForAlert(alertType)
	}
	if now.IsZero() {
		now = time.Now()
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.raiseBuiltinAlertLocked(ruleID, alertType, fallbackSeverity, key, message, ip, evidence, now, episodeGap)
}

// raiseBuiltinAlertLocked is the same policy path for detectors such as the
// communication baseline that already hold e.mutex while evaluating state.
func (e *Engine) raiseBuiltinAlertLocked(ruleID string, alertType AlertType, fallbackSeverity, key, message, ip string, evidence map[string]interface{}, now time.Time, episodeGap time.Duration) bool {
	rule := e.rules[ruleID]
	if rule == nil {
		// Built-ins are product definitions and are not removable. Defensively
		// restore a missing local definition so a partial/older persisted rule
		// snapshot cannot silently disable a detector. NewEngine normally seeds
		// all built-ins, but this also keeps direct Engine test fixtures safe.
		if product := builtinRules()[ruleID]; product != nil {
			if e.rules == nil {
				e.rules = make(map[string]*Rule)
			}
			rule = cloneRule(product)
			e.rules[ruleID] = rule
		}
	}
	if rule == nil || !rule.Enabled || !scheduleAllows(rule.Schedule, now) {
		return false
	}
	if rule.Simulation {
		rule.SimulationHits++
		rule.LastSimulationHit = now
		return false
	}

	severity := strings.ToLower(strings.TrimSpace(fallbackSeverity))
	if severity == "" {
		severity = strings.ToLower(strings.TrimSpace(rule.Severity))
	}
	// Product defaults must not flatten detector-computed severities (for
	// example an NBA score that legitimately evaluates to critical). Only an
	// explicit operator severity override replaces the detector result.
	if rule.SeverityOverride && strings.TrimSpace(rule.Severity) != "" {
		severity = strings.ToLower(strings.TrimSpace(rule.Severity))
	}
	if severity == "" {
		severity = "medium"
	}

	mode := strings.ToLower(strings.TrimSpace(rule.Suppression.Mode))
	if mode == "" {
		mode = "aggregate"
	}
	if mode == "once" && !rule.LastTriggered.IsZero() {
		return false
	}
	if mode == "interval" && !rule.LastTriggered.IsZero() {
		interval := time.Duration(rule.Suppression.IntervalSeconds) * time.Second
		if interval <= 0 {
			interval = episodeGap
		}
		if interval <= 0 {
			interval = alertEpisodeGap
		}
		if now.Sub(rule.LastTriggered) < interval {
			return false
		}
	}
	if mode == "every" {
		key = fmt.Sprintf("%s|%d", key, now.UnixNano())
	}

	a, exists := e.alerts[key]
	if exists && a.Status == AlertStatusApproved {
		return false
	}
	if !exists {
		a = &Alert{ID: key, Type: alertType, Severity: severity, Message: message, IP: ip, FirstSeen: now, Status: AlertStatusNew, Evidence: evidence}
		e.alerts[key] = a
		e.logNewAlert(a)
	} else {
		a.Type = alertType
		a.Message = message
		a.Evidence = evidence
		a.Severity = severity
		if ip != "" {
			a.IP = ip
		}
	}

	rule.LastTriggered = now
	if mode == "every" || mode == "once" || mode == "interval" {
		if a.Status == AlertStatusConfirmed {
			a.Status = AlertStatusNew
			a.StatusChangedAt = now
		}
		a.Count++
		a.LastSeen = now
		a.Synced = false
		a.lastSyncTouch = now
		return true
	}
	return e.recordEpisodeAlertLocked(a, now, episodeGap)
}

func (e *Engine) builtinSeverity(ruleID, fallback string) string {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	if r := e.rules[ruleID]; r != nil && strings.TrimSpace(r.Severity) != "" {
		return strings.ToLower(strings.TrimSpace(r.Severity))
	}
	return fallback
}
