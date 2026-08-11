package detect

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/ics"
)

func detailBool(m ics.Message, key string) bool {
	v, _ := m.Details[key].(bool)
	return v
}

func detailString(m ics.Message, key string) string {
	v, _ := m.Details[key].(string)
	return strings.ToLower(strings.TrimSpace(v))
}

func icsEndpoints(m ics.Message) (src, target string, service uint16) {
	if m.IsResponse {
		return m.DstIP, m.SrcIP, m.SrcPort
	}
	return m.SrcIP, m.DstIP, m.DstPort
}

func (e *Engine) baselineLearning() bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.baselineEnabled && e.baselineMode != BaselineModeMonitoring
}

func (e *Engine) learnOTProtocol(dst, protocol string, servicePort uint16) {
	// Compatibility helper for explicit/manual learning. Live traffic should
	// call learnOTProtocolForRelation so quarantined relationships cannot poison
	// a target's protocol baseline.
	if dst == "" {
		return
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if e.trustedOTProtocols[dst] == nil {
		e.trustedOTProtocols[dst] = map[string]bool{}
	}
	e.trustedOTProtocols[dst][fmt.Sprintf("%s/%d", strings.ToLower(protocol), servicePort)] = true
}

func (e *Engine) learnOTProtocolForRelation(src, dst, protocol string, servicePort uint16) {
	if dst == "" {
		return
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if !e.policyLearningAllowedLocked(src, dst, time.Now()) {
		return
	}
	if e.trustedOTProtocols[dst] == nil {
		e.trustedOTProtocols[dst] = map[string]bool{}
	}
	e.trustedOTProtocols[dst][fmt.Sprintf("%s/%d", strings.ToLower(protocol), servicePort)] = true
}

func (e *Engine) learnOTMaster(src, dst string) {
	if src == "" || dst == "" {
		return
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if !e.policyLearningAllowedLocked(src, dst, time.Now()) {
		return
	}
	if e.trustedOTMasters[dst] == nil {
		e.trustedOTMasters[dst] = map[string]bool{}
	}
	e.trustedOTMasters[dst][src] = true
}

func (e *Engine) learnOTTimeSource(src, dst string) {
	if src == "" || dst == "" {
		return
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if !e.policyLearningAllowedLocked(src, dst, time.Now()) {
		return
	}
	if e.trustedOTTimeSources[dst] == nil {
		e.trustedOTTimeSources[dst] = map[string]bool{}
	}
	e.trustedOTTimeSources[dst][src] = true
}

func (e *Engine) sourceRoleIsExplicitlyUntrusted(src string) bool {
	if ip := net.ParseIP(strings.TrimSpace(src)); ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
		return true
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	c, ok := e.assetContexts[src]
	if !ok || c.Role == "" {
		return false
	}
	return isEnterpriseRole(c.Role) || (!isControlMasterRole(c.Role) && !strings.Contains(c.Role, "time") && !strings.Contains(c.Role, "ntp") && !strings.Contains(c.Role, "gps"))
}

func (e *Engine) sourceCanSetTime(src, dst string) bool {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if c, ok := e.assetContexts[src]; ok {
		role := strings.ToLower(c.Role)
		// Explicit time-source roles are operator policy. Engineering/HMI roles
		// are not implicitly authorized to change time merely because they can
		// control a device; time authority is learned from actual time operations.
		if strings.Contains(role, "time") || strings.Contains(role, "ntp") || strings.Contains(role, "gps") {
			if t, tok := e.assetContexts[dst]; !tok || c.Zone == "" || t.Zone == "" || c.Zone == t.Zone {
				return true
			}
		}
	}
	return e.trustedOTTimeSources[dst] != nil && e.trustedOTTimeSources[dst][src]
}

// handleICSPolicy evaluates normalized operation semantics emitted by every OT
// parser. It deliberately does not depend on a numeric process value: writes,
// mode changes and commands remain visible even when the payload cannot be
// decoded into a scalar.
func (e *Engine) handleICSPolicy(m ics.Message) {
	src, target, service := icsEndpoints(m)
	if target == "" {
		return
	}
	e.markOTAsset(target)

	// Responses establish reporting cadence and may carry exception/error
	// status. Command policy itself is request-direction only.
	if m.IsResponse {
		if !m.FromAnalysis {
			e.observeOTReporting(target, m.Timestamp)
		}
		if m.IsException {
			e.observeICSError(target, src, m)
		}
		return
	}

	class := detailString(m, "operation_class")
	isWrite := detailBool(m, "is_write")
	isCommand := detailBool(m, "is_command") || isWrite
	isProgramming := detailBool(m, "is_programming")
	isModeChange := detailBool(m, "is_mode_change")
	isConfigChange := detailBool(m, "is_config_change")
	isTimeChange := detailBool(m, "is_time_change")
	hardSecuritySemantic := isProgramming || isModeChange || isConfigChange
	learning := e.baselineLearning()
	trustedAccess := e.isTrustedOTAccess(src, target)
	trustedSource := e.isTrustedOTMaster(src, target)

	if learning && !e.sourceRoleIsExplicitlyUntrusted(src) && !hardSecuritySemantic {
		e.learnOTProtocolForRelation(src, target, m.Protocol, service)
		// Read/discovery access does not grant write/operate authority. Only an
		// actual command observed during commissioning can establish master
		// authority (or an explicit Central control-master role). Time changes are
		// learned through a separate time-source relationship.
		e.learnOTAccess(src, target)
		trustedAccess = true
		if isCommand && !isTimeChange {
			e.learnOTMaster(src, target)
			trustedSource = true
		}
	}

	if !learning && !e.isExpectedOTProtocol(target, m.Protocol, service) {
		e.raiseBuiltinAlert("builtin.unexpected_ot_protocol", AlertUnexpectedOTProtocol, "high",
			fmt.Sprintf("unexpected-ot-protocol|%s|%s|%d", target, strings.ToLower(m.Protocol), service),
			fmt.Sprintf("%s used unexpected OT protocol %s on service port %d toward %s", src, m.Protocol, service, target), target,
			map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": m.Protocol, "service_port": service, "function": m.FunctionName}, m.Timestamp, alertEpisodeGap)
	}

	// Decoded protocol visibility catches direct OT access even when a site uses
	// a non-standard configured service port that the packet-only port catalogue
	// cannot identify. This relationship rule starts in simulation by default.
	if !learning && !trustedAccess {
		e.raiseBuiltinAlert("builtin.direct_ot_protocol_access", AlertDirectOTProtocolAccess, "high",
			fmt.Sprintf("direct-ot-decoded|%s|%s|%s|%d", src, target, strings.ToLower(m.Protocol), service),
			fmt.Sprintf("%s directly accessed %s on OT asset %s without a learned/approved relationship", src, m.Protocol, target), src,
			map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": m.Protocol, "service_port": service, "function": m.FunctionName}, m.Timestamp, alertEpisodeGap)
	}

	// Intrinsically dangerous operations always remain visible, including
	// during learning. They are semantic alerts, not behavioral deviations.
	if isProgramming {
		e.excludeICSFromLearning(m, "controller programming operation")
		e.raiseBuiltinAlert("builtin.controller_program_change", AlertControllerProgramChange, "critical",
			fmt.Sprintf("program|%s|%s|%s", target, src, m.FunctionName),
			fmt.Sprintf("%s performed controller programming operation %s on %s (%s)", src, m.FunctionName, target, m.Protocol), target,
			map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": m.Protocol, "function": m.FunctionName, "operation_class": class}, m.Timestamp, alertEpisodeGap)
	}
	if isModeChange {
		e.excludeICSFromLearning(m, "controller mode change")
		e.raiseBuiltinAlert("builtin.controller_mode_change", AlertControllerModeChange, "critical",
			fmt.Sprintf("mode|%s|%s|%s", target, src, m.FunctionName),
			fmt.Sprintf("%s issued controller mode/stop/restart operation %s to %s (%s)", src, m.FunctionName, target, m.Protocol), target,
			map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": m.Protocol, "function": m.FunctionName, "operation_class": class}, m.Timestamp, alertEpisodeGap)
	}
	if isConfigChange {
		e.excludeICSFromLearning(m, "controller/device configuration change")
		e.raiseBuiltinAlert("builtin.controller_configuration_change", AlertControllerConfigChange, "high",
			fmt.Sprintf("configuration|%s|%s|%s|%s", target, src, m.Protocol, m.FunctionName),
			fmt.Sprintf("%s changed controller/device configuration using %s on %s (%s)", src, m.FunctionName, target, m.Protocol), target,
			map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": m.Protocol, "function": m.FunctionName, "operation_class": class}, m.Timestamp, alertEpisodeGap)
	}

	if isTimeChange {
		trustedTime := e.sourceCanSetTime(src, target)
		if learning && !e.sourceRoleIsExplicitlyUntrusted(src) {
			e.learnOTTimeSource(src, target)
			trustedTime = true
		}
		if !trustedTime {
			e.excludeICSFromLearning(m, "unauthorized OT time change")
			e.raiseBuiltinAlert("builtin.unauthorized_time_change", AlertUnauthorizedTimeChange, "high",
				fmt.Sprintf("time|%s|%s|%s", target, src, m.Protocol),
				fmt.Sprintf("unauthorized time synchronization/change %s from %s to %s (%s)", m.FunctionName, src, target, m.Protocol), target,
				map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": m.Protocol, "function": m.FunctionName}, m.Timestamp, alertEpisodeGap)
		}
	}

	if isCommand {
		// During commissioning, an unknown internal source may become a trusted
		// master unless Central has explicitly classified it as a non-control
		// role. Explicitly suspicious role/context still alerts during learning.
		if !trustedSource {
			e.excludeICSFromLearning(m, "unauthorized OT command")
			e.raiseBuiltinAlert("builtin.unauthorized_ot_command", AlertUnauthorizedOTCommand, "critical",
				fmt.Sprintf("unauthorized-command|%s|%s|%s|%s", target, src, m.Protocol, m.FunctionName),
				fmt.Sprintf("unapproved source %s issued OT command %s to %s (%s)", src, m.FunctionName, target, m.Protocol), target,
				map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": m.Protocol, "function": m.FunctionName, "operation_class": class}, m.Timestamp, alertEpisodeGap)
			if isWrite {
				e.raiseBuiltinAlert("builtin.unauthorized_ot_write", AlertUnauthorizedOTWrite, "critical",
					fmt.Sprintf("unauthorized-write|%s|%s|%s|%s", target, src, m.Protocol, m.FunctionName),
					fmt.Sprintf("unapproved source %s issued OT write/operate %s to %s (%s)", src, m.FunctionName, target, m.Protocol), target,
					map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": m.Protocol, "function": m.FunctionName, "operation_class": class}, m.Timestamp, alertEpisodeGap)
			}
		}

		e.observeEngineeringSource(src, target, m, learning)
		e.observeIOBurst(src, target, m)
		e.observeCommandSequence(src, target, m)
	}
}

func (e *Engine) observeEngineeringSource(src, target string, m ics.Message, learning bool) {
	now := m.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	e.policyMutex.Lock()
	if e.engineeringTargets[src] == nil {
		e.engineeringTargets[src] = map[string]time.Time{}
	}
	mset := e.engineeringTargets[src]
	mset[target] = now
	window := time.Duration(e.builtinParameter("builtin.new_engineering_workstation", "window_hours", 24) * float64(time.Hour))
	if window <= 0 {
		window = 24 * time.Hour
	}
	controllerThreshold := int(e.builtinParameter("builtin.new_engineering_workstation", "controller_threshold", 3))
	if controllerThreshold < 1 {
		controllerThreshold = 1
	}
	cut := now.Add(-window)
	for ip, t := range mset {
		if t.Before(cut) {
			delete(mset, ip)
		}
	}
	count := len(mset)
	ctx, hasContext := e.assetContexts[src]
	trustedTarget := e.trustedOTMasters[target] != nil && e.trustedOTMasters[target][src]
	e.policyMutex.Unlock()

	if learning {
		return
	}
	if hasContext && isEngineeringRole(ctx.Role) && !trustedTarget {
		e.raiseBuiltinAlert("builtin.unexpected_engineering_access", AlertUnexpectedEngineeringAccess, "high",
			fmt.Sprintf("engineering-access|%s|%s", src, target),
			fmt.Sprintf("engineering source %s accessed controller %s outside its learned relationship (%s %s)", src, target, m.Protocol, m.FunctionName), src,
			map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": m.Protocol, "function": m.FunctionName}, now, alertEpisodeGap)
	}
	if (!hasContext || !isEngineeringRole(ctx.Role)) && count >= controllerThreshold {
		e.raiseBuiltinAlert("builtin.new_engineering_workstation", AlertNewEngineeringWorkstation, "high",
			"new-engineering|"+src,
			fmt.Sprintf("%s performed engineering/control operations against %d controllers within %s", src, count, window), src,
			map[string]interface{}{"source_ip": src, "controller_count": count, "controller_threshold": controllerThreshold, "window_hours": window.Hours(), "latest_target": target, "protocol": m.Protocol, "function": m.FunctionName}, now, 30*time.Minute)
	}
}

func (e *Engine) observeIOBurst(src, target string, m ics.Message) {
	now := m.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	key := src + "|" + target
	window := time.Duration(e.builtinParameter("builtin.brute_force_io", "window_seconds", 10)) * time.Second
	if window <= 0 {
		window = 10 * time.Second
	}
	threshold := int(e.builtinParameter("builtin.brute_force_io", "commands_threshold", 50))
	if threshold < 1 {
		threshold = 1
	}
	e.policyMutex.Lock()
	xs := append(e.ioBursts[key], now)
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
	e.ioBursts[key] = xs
	count := len(xs)
	e.policyMutex.Unlock()
	if count >= threshold {
		e.raiseBuiltinAlert("builtin.brute_force_io", AlertBruteForceIO, "high",
			"io-burst|"+key,
			fmt.Sprintf("%s issued %d OT commands/writes to %s within %s", src, count, target, window), target,
			map[string]interface{}{"source_ip": src, "target_ip": target, "commands_in_window": count, "window_seconds": window.Seconds(), "threshold": threshold, "protocol": m.Protocol, "function": m.FunctionName}, now, maxDuration(time.Minute, window))
	}
}

func (e *Engine) observeCommandSequence(src, target string, m ics.Message) {
	if !strings.EqualFold(m.Protocol, "DNP3") {
		return
	}
	now := m.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	key := src + "|" + target
	class := detailString(m, "operation_class")
	e.policyMutex.Lock()
	if class == "select" {
		e.dnpSelect[key] = now
		e.policyMutex.Unlock()
		return
	}
	selectedAt := e.dnpSelect[key]
	if class == "operate" && m.FunctionCode == 4 {
		delete(e.dnpSelect, key)
	}
	e.policyMutex.Unlock()
	if class == "operate" && m.FunctionCode == 4 && (selectedAt.IsZero() || now.Sub(selectedAt) > 30*time.Second) {
		e.raiseBuiltinAlert("builtin.process_sequence_violation", AlertProcessSequenceViolation, "high",
			"dnp3-operate-without-select|"+key,
			fmt.Sprintf("DNP3 Operate from %s to %s was not preceded by a recent Select", src, target), target,
			map[string]interface{}{"source_ip": src, "target_ip": target, "protocol": "DNP3", "function": m.FunctionName}, now, alertEpisodeGap)
	}
}

func (e *Engine) startICSParseErrorWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventICSParseError)
	go func() {
		for event := range ch {
			if parseErr, ok := event.Data.(core.ICSParseError); ok {
				e.observeICSParseError(parseErr)
			}
		}
	}()
}

func (e *Engine) observeICSParseError(parseErr core.ICSParseError) {
	p := parseErr.Packet
	controller, peer := p.DstIP, p.SrcIP
	// For a response, the well-known OT service normally appears as source
	// port. Use the product port catalogue first, then a conservative
	// well-known-vs-ephemeral heuristic for configured non-standard ports.
	if _, known := otServicePorts[p.SrcPort]; known || (p.SrcPort != 0 && p.DstPort > 49151 && p.SrcPort < p.DstPort) {
		controller, peer = p.SrcIP, p.DstIP
	}
	m := ics.Message{Timestamp: p.Timestamp, Protocol: parseErr.Parser, FunctionName: "malformed/decode-error frame"}
	e.observeICSError(controller, peer, m)
}

func (e *Engine) observeICSError(controller, peer string, m ics.Message) {
	now := m.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	window := time.Duration(e.builtinParameter("builtin.malformed_ot_burst", "window_seconds", 60)) * time.Second
	if window <= 0 {
		window = time.Minute
	}
	threshold := int(e.builtinParameter("builtin.malformed_ot_burst", "errors_threshold", 10))
	if threshold < 1 {
		threshold = 1
	}
	e.policyMutex.Lock()
	xs := append(e.icsErrors[controller], now)
	cut := now.Add(-window)
	j := 0
	for _, t := range xs {
		if !t.Before(cut) {
			xs[j] = t
			j++
		}
	}
	xs = xs[:j]
	e.icsErrors[controller] = xs
	count := len(xs)
	e.policyMutex.Unlock()
	if count >= threshold {
		e.raiseBuiltinAlert("builtin.malformed_ot_burst", AlertMalformedOTBurst, "high",
			"ics-errors|"+controller,
			fmt.Sprintf("%s produced %d OT protocol exceptions/decode errors within %s", controller, count, window), controller,
			map[string]interface{}{"controller_ip": controller, "peer_ip": peer, "protocol": m.Protocol, "function": m.FunctionName, "errors_in_window": count, "window_seconds": window.Seconds(), "threshold": threshold}, now, maxDuration(time.Minute, window))
	}
}

func (e *Engine) observeOTReporting(controller string, now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}
	e.policyMutex.Lock()
	st := e.reporting[controller]
	if st == nil {
		st = &reportingState{}
		e.reporting[controller] = st
	}
	if !st.LastSeen.IsZero() {
		gap := now.Sub(st.LastSeen)
		if gap > 0 && gap < 24*time.Hour {
			st.LastGap = gap
			if st.TypicalGap == 0 {
				st.TypicalGap = gap
			} else {
				st.TypicalGap = time.Duration(float64(st.TypicalGap)*0.9 + float64(gap)*0.1)
			}
		}
	}
	st.LastSeen = now
	st.Samples++
	e.policyMutex.Unlock()
}

func (e *Engine) startOTReportingWatch(_ *core.EventBus) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for now := range ticker.C {
			if e.behaviorDetectionsSuppressed() {
				continue
			}
			e.policyMutex.Lock()
			lastPacket := e.lastPacketObserved
			e.policyMutex.Unlock()
			if lastPacket.IsZero() || now.Sub(lastPacket) > 2*time.Minute {
				continue
			}
			type missing struct {
				ip        string
				last      time.Time
				typical   time.Duration
				samples   int
				threshold time.Duration
			}
			var misses []missing
			minSamples := int(e.builtinParameter("builtin.ot_reporting_loss", "min_samples", 10))
			if minSamples < 1 {
				minSamples = 1
			}
			cadenceMultiplier := e.builtinParameter("builtin.ot_reporting_loss", "cadence_multiplier", 5)
			if cadenceMultiplier < 1 {
				cadenceMultiplier = 1
			}
			minMissing := time.Duration(e.builtinParameter("builtin.ot_reporting_loss", "min_missing_seconds", 600)) * time.Second
			maxMissing := time.Duration(e.builtinParameter("builtin.ot_reporting_loss", "max_missing_seconds", 21600)) * time.Second
			if minMissing <= 0 {
				minMissing = 10 * time.Minute
			}
			if maxMissing < minMissing {
				maxMissing = minMissing
			}
			e.policyMutex.Lock()
			for ip, st := range e.reporting {
				if st == nil || st.Samples < minSamples || st.LastSeen.IsZero() || st.TypicalGap <= 0 {
					continue
				}
				threshold := time.Duration(cadenceMultiplier * float64(st.TypicalGap))
				if threshold < minMissing {
					threshold = minMissing
				}
				if threshold > maxMissing {
					threshold = maxMissing
				}
				if now.Sub(st.LastSeen) > threshold {
					misses = append(misses, missing{ip: ip, last: st.LastSeen, typical: st.TypicalGap, samples: st.Samples, threshold: threshold})
					st.AlertedAt = now
				}
			}
			e.policyMutex.Unlock()
			for _, x := range misses {
				e.raiseBuiltinAlert("builtin.ot_reporting_loss", AlertOTReportingLoss, "high",
					"reporting-loss|"+x.ip,
					fmt.Sprintf("OT reporting from %s is missing for %s (learned cadence about %s)", x.ip, now.Sub(x.last).Round(time.Minute), x.typical.Round(time.Second)), x.ip,
					map[string]interface{}{"controller_ip": x.ip, "last_report_at": x.last, "typical_gap_seconds": x.typical.Seconds(), "missing_threshold_seconds": x.threshold.Seconds(), "samples": x.samples}, now, x.threshold)
			}
		}
	}()
}
