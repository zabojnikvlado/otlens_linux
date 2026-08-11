package detect

import (
	"fmt"

	"github.com/zabojnikvlado/otlens_linux/internal/ics"
)

// handleICS first executes the protocol-aware built-in policy layer for every
// decoded ICS message, then preserves the historical ics_critical_operation
// alert only for operations the parser classified as intrinsically high-impact.
// Routine writes, ClockSync and OPC UA secure-channel lifecycle are no longer
// collapsed into a blanket CRITICAL finding.
func (e *Engine) handleICS(msg ics.Message) {
	e.handleICSPolicy(msg)

	relevant, _ := msg.Details["security_relevant"].(bool)
	if !relevant || msg.IsResponse {
		return
	}
	// Programming, mode and configuration changes now have dedicated
	// semantic built-ins. Do not emit the legacy generic critical alert for
	// the same operation as well; this path remains only as a safety net for
	// future parser operations marked intrinsically security-relevant without
	// a dedicated semantic detector.
	if detailBool(msg, "is_programming") || detailBool(msg, "is_mode_change") || detailBool(msg, "is_config_change") {
		return
	}
	e.excludeICSFromLearning(msg, "intrinsically critical ICS operation")
	_, target, _ := icsEndpoints(msg)
	key := fmt.Sprintf("ics|%s|%s|%s", msg.Protocol, msg.FunctionName, target)
	e.raiseBuiltinAlert(string(AlertICSCriticalOperation), AlertICSCriticalOperation, "critical", key,
		fmt.Sprintf("%s %s directed at %s", msg.Protocol, msg.FunctionName, target), target,
		map[string]interface{}{"source_ip": msg.SrcIP, "target_ip": target, "protocol": msg.Protocol, "function": msg.FunctionName, "operation_class": msg.Details["operation_class"]}, msg.Timestamp, alertEpisodeGap)
}
