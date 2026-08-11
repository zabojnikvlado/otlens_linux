package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

type RuleKind string

const (
	RuleKindBuiltin RuleKind = "builtin"
	RuleKindCustom  RuleKind = "custom"
)

type RuleField string

const (
	RuleFieldSrcIP      RuleField = "src_ip"
	RuleFieldDstIP      RuleField = "dst_ip"
	RuleFieldEitherIP   RuleField = "either_ip"
	RuleFieldSrcMAC     RuleField = "src_mac"
	RuleFieldDstMAC     RuleField = "dst_mac"
	RuleFieldProtocol   RuleField = "protocol"
	RuleFieldSrcPort    RuleField = "src_port"
	RuleFieldDstPort    RuleField = "dst_port"
	RuleFieldPort       RuleField = "port"
	RuleFieldVLAN       RuleField = "vlan"
	RuleFieldPacketSize RuleField = "packet_size"
	RuleFieldTCPFlags   RuleField = "tcp_flags"
)

type RuleCondition struct {
	Field    RuleField `json:"field"`
	Operator string    `json:"operator"`
	Value    string    `json:"value"`
}

type RuleGroup struct {
	Operator   string          `json:"operator"` // AND or OR
	Conditions []RuleCondition `json:"conditions"`
}

type RuleAction struct {
	Type string `json:"type"` // alert, audit, siem
}

type RuleSuppression struct {
	Mode            string `json:"mode"` // every, once, interval, aggregate
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
}

type Rule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description,omitempty"`
	Category         string          `json:"category,omitempty"`
	Kind             RuleKind        `json:"kind"`
	Enabled          bool            `json:"enabled"`
	Severity         string          `json:"severity,omitempty"`
	SeverityOverride bool            `json:"severity_override,omitempty"`
	Priority         int             `json:"priority,omitempty"`
	Simulation       bool            `json:"simulation,omitempty"`
	Version          int             `json:"version,omitempty"`
	Groups           []RuleGroup     `json:"groups,omitempty"`
	GroupOperator    string          `json:"group_operator,omitempty"`
	Actions          []RuleAction    `json:"actions,omitempty"`
	Suppression      RuleSuppression `json:"suppression,omitempty"`
	Schedule         string          `json:"schedule,omitempty"`

	// Product-owned metadata for built-in rules. Operators can override policy
	// knobs (enabled/severity/simulation/suppression/schedule), while detector
	// identity and ATT&CK/prerequisite metadata remain product-managed.
	Detector        string             `json:"detector,omitempty"`
	MITRETactics    []string           `json:"mitre_tactics,omitempty"`
	MITRETechniques []string           `json:"mitre_techniques,omitempty"`
	Prerequisites   []string           `json:"prerequisites,omitempty"`
	Protocols       []string           `json:"protocols,omitempty"`
	Parameters      map[string]float64 `json:"parameters,omitempty"`

	// Legacy compatibility with Phase 3.5 rules.
	Field     RuleField `json:"field,omitempty"`
	Value     string    `json:"value,omitempty"`
	AlertType AlertType `json:"alert_type,omitempty"`

	LastTriggered     time.Time `json:"-"`
	SimulationHits    uint64    `json:"-"`
	LastSimulationHit time.Time `json:"-"`
}

type RuleView struct {
	Rule
	HitCount          uint64    `json:"HitCount"`
	LastHit           time.Time `json:"LastHit"`
	LastHitIP         string    `json:"LastHitIP"`
	SimulationHits    uint64    `json:"SimulationHits"`
	LastSimulationHit time.Time `json:"LastSimulationHit"`
}

func builtinRules() map[string]*Rule {
	// Keep the product definition here rather than in Central. Sensors are the
	// execution point and must always know the complete detector catalogue even
	// when Central is reset/offline. Central may send policy overrides, but not
	// replace descriptions, detector identity or ATT&CK metadata.
	seed := []*Rule{
		builtin(string(AlertARPSpoof), AlertARPSpoof, "ARP Spoofing / MAC Conflict", "security", "high", "arp_identity", "Detect conflicting IP/MAC identity claims without automatically trusting the claimant.", []string{"Credential Access", "Discovery"}, []string{"ARP spoofing"}, nil),
		builtin("builtin.gateway_mac_changed", AlertGatewayMACChanged, "Default Gateway MAC Changed", "security", "critical", "arp_identity", "A gateway/router IP changed its trusted MAC identity.", []string{"Impair Process Control"}, []string{"Network MITM"}, []string{"gateway inference or explicit asset context"}),
		builtin("builtin.duplicate_ip", AlertDuplicateIP, "Duplicate IP Address", "security", "high", "arp_identity", "Multiple MAC addresses are actively claiming the same IP.", []string{"Discovery"}, []string{"Network Service Scanning"}, nil),
		builtin("builtin.gratuitous_arp_storm", AlertGratuitousARPStorm, "Gratuitous ARP Storm", "network", "medium", "arp_identity", "Excessive gratuitous ARP announcements may indicate failover loops, spoofing or address instability.", nil, nil, nil),

		builtin(string(AlertNewCommunication), AlertNewCommunication, "New Communication (baseline)", "baseline", "medium", "communication_baseline", "A communication relationship/service was not present in the trusted baseline.", []string{"Discovery"}, []string{"Network Service Scanning"}, []string{"mature baseline"}),
		builtin(string(AlertNewAsset), AlertNewAsset, "New Asset (baseline)", "asset", "medium", "asset_baseline", "An asset appeared after baseline learning and is not yet trusted.", []string{"Discovery"}, []string{"Remote System Discovery"}, []string{"mature baseline"}),
		builtin(string(AlertValueOutOfRange), AlertValueOutOfRange, "Value Out of Range", "ot_tag", "medium", "tag_baseline", "An OT process value left its robust learned range.", []string{"Impact"}, []string{"Manipulation of Control"}, []string{"OT tag decoding", "mature value baseline"}),
		builtin(string(AlertOTValueAnomaly), AlertOTValueAnomaly, "OT Value Anomaly", "ot_tag", "high", "ot_value_behavior", "Rate, toggle, stuck or missing-value behavior deviated from learned OT process behavior.", []string{"Impact"}, []string{"Manipulation of Control"}, []string{"OT tag decoding"}),

		// Protocol-aware command semantics. The legacy critical rule remains for
		// compatibility, but only truly high-impact parser classifications feed it.
		builtin(string(AlertICSCriticalOperation), AlertICSCriticalOperation, "Critical ICS Operation (legacy compatibility)", "ics", "critical", "ics_semantics", "High-impact OT operations retained under the legacy alert type for compatibility.", []string{"Inhibit Response Function", "Impair Process Control"}, []string{"T0806", "T0843", "T0858"}, []string{"decoded ICS protocol"}),
		builtin("builtin.unauthorized_ot_command", AlertUnauthorizedOTCommand, "Unauthorized OT Command / Rogue Master", "ics", "critical", "ics_policy", "A control command originated from a source that is not an approved or learned controller master for the target.", []string{"Execution", "Impair Process Control"}, []string{"T0848", "T0855"}, []string{"decoded ICS request", "asset context or mature command relationship"}),
		builtin("builtin.controller_program_change", AlertControllerProgramChange, "Controller Program Download / Online Edit", "ics", "critical", "ics_semantics", "Controller program download, block transfer or online program modification was observed.", []string{"Persistence", "Impact"}, []string{"T0843", "T0843.001"}, []string{"decoded controller programming operation"}),
		builtin("builtin.controller_mode_change", AlertControllerModeChange, "Controller Mode Change / Stop / Restart", "ics", "critical", "ics_semantics", "Controller operating mode, stop or restart operation was observed.", []string{"Inhibit Response Function", "Impact"}, []string{"T0858"}, []string{"decoded controller control operation"}),
		builtin("builtin.controller_configuration_change", AlertControllerConfigChange, "Controller / Device Configuration Change", "ics", "high", "ics_semantics", "Controller or field-device configuration was modified using a decoded OT management operation.", []string{"Persistence", "Impact"}, []string{"T0836"}, []string{"decoded OT configuration-change operation"}),
		builtin("builtin.unauthorized_ot_write", AlertUnauthorizedOTWrite, "OT Write From Unauthorized Source", "ics", "critical", "ics_policy", "A write/operate/set-point operation came from an unapproved source, independent of whether a numeric value was decoded.", []string{"Execution", "Impact"}, []string{"T0855", "T0836"}, []string{"decoded OT write/command"}),
		builtin("builtin.brute_force_io", AlertBruteForceIO, "Brute Force I/O / Command Burst", "ics", "high", "ics_rate", "Rapid repeated write/operate commands target the same controller or point set.", []string{"Impact"}, []string{"T0806"}, []string{"decoded OT write/command"}),
		builtin("builtin.unauthorized_time_change", AlertUnauthorizedTimeChange, "Unauthorized OT Time Change", "ics", "high", "ics_policy", "An OT clock/time synchronization command originated from an unapproved source or unexpected context.", []string{"Impact"}, []string{"T0832"}, []string{"decoded OT time synchronization operation"}),
		builtin("builtin.process_sequence_violation", AlertProcessSequenceViolation, "Process Command Sequence Violation", "ics", "high", "ics_sequence", "A stateful control sequence violated expected protocol semantics (for example DNP3 Operate without Select).", []string{"Execution", "Impact"}, []string{"T0855"}, []string{"decoded stateful OT protocol"}),
		builtin("builtin.malformed_ot_burst", AlertMalformedOTBurst, "Malformed / Exception Burst Against Controller", "ics", "high", "ics_error_rate", "A controller is receiving a burst of malformed, exception or protocol-error traffic.", []string{"Discovery", "Impact"}, []string{"T0814"}, []string{"decoded ICS protocol"}),
		builtin("builtin.ot_reporting_loss", AlertOTReportingLoss, "Loss of OT Reporting / Telemetry", "ics", "high", "ot_reporting", "A controller/field device that normally reports OT data stopped reporting while the sensor remains healthy.", []string{"Inhibit Response Function"}, []string{"T0827"}, []string{"learned OT reporting cadence"}),

		builtin("builtin.new_engineering_workstation", AlertNewEngineeringWorkstation, "New Engineering Workstation", "asset", "high", "engineering_role", "A new or previously non-engineering asset starts performing engineering/control operations against controllers.", []string{"Initial Access", "Execution"}, []string{"T0886"}, []string{"asset context or engineering-operation inference"}),
		builtin("builtin.asset_identity_drift", AlertAssetIdentityDrift, "Asset Identity Drift", "asset", "high", "identity_drift", "Hostname, vendor/model/serial, role or stable network identity changed unexpectedly.", []string{"Defense Evasion"}, []string{"T0878"}, []string{"passive identity and/or reconnaissance profile"}),
		builtin("builtin.firmware_change", AlertFirmwareChange, "Controller / Device Firmware Change", "asset", "critical", "recon_change", "A reconnaissance profile reports a firmware version change on an established asset.", []string{"Persistence", "Impact"}, []string{"T0857"}, []string{"reconnaissance profile with firmware evidence"}),
		builtin("builtin.unexpected_ot_protocol", AlertUnexpectedOTProtocol, "Unexpected OT Protocol / Unexpected Port", "ics", "high", "ics_protocol_baseline", "An asset uses an OT protocol/port relationship not present in its trusted behavior.", []string{"Discovery", "Execution"}, []string{"T0846"}, []string{"mature baseline"}),

		builtin(string(AlertHoneypotProbed), AlertHoneypotProbed, "Honeypot Probed", "security", "medium", "deception", "Traffic reached a configured deception endpoint.", []string{"Discovery"}, []string{"T0846"}, []string{"deception station configuration"}),
		builtin(string(AlertHoneypotLateralMovement), AlertHoneypotLateralMovement, "Honeypot Lateral Movement", "security", "critical", "deception", "A deception endpoint initiated outbound traffic.", []string{"Lateral Movement"}, []string{"T0866"}, []string{"deception station configuration"}),
		builtin(string(AlertExternalCommunication), AlertExternalCommunication, "External Communication", "security", "medium", "external_communication", "An internal asset communicates with a public Internet unicast endpoint; direction follows the connection initiator so replies to outbound sessions are not duplicated as inbound findings.", []string{"Command and Control", "Exfiltration"}, []string{"T0885"}, nil),
		builtin(string(AlertSegmentationViolation), AlertSegmentationViolation, "Network Segmentation Policy Violation", "network", "high", "segmentation_policy", "Observed traffic violates explicit zone/Purdue policy; max-level-jump remains a conservative fallback.", []string{"Lateral Movement"}, []string{"T0866"}, []string{"VLAN/Purdue or asset zone policy"}),
		builtin(string(AlertReconnaissance), AlertReconnaissance, "Reconnaissance / Discovery", "network", "high", "reconnaissance", "Host, port, ICMP, broadcast, multicast and OT protocol discovery patterns.", []string{"Discovery"}, []string{"T0846"}, nil),
		builtin(string(AlertC2Beacon), AlertC2Beacon, "C2 Beaconing", "security", "high", "beacon", "Suspiciously regular external connection timing.", []string{"Command and Control"}, []string{"T0885"}, []string{"mature behavior"}),
		builtin(string(AlertC2Correlated), AlertC2Correlated, "Correlated C2 Detection", "security", "high", "c2_correlation", "Correlates DNS and threat-intelligence indicators into C2 evidence.", []string{"Command and Control"}, []string{"T0885"}, []string{"DNS visibility"}),
		builtin("builtin.dns_tunneling", AlertDNSTunneling, "DNS Tunneling", "security", "high", "dns_tunnel", "High-entropy labels, TXT-heavy traffic, unique-subdomain growth and query-size asymmetry indicate possible DNS tunneling.", []string{"Command and Control", "Exfiltration"}, []string{"T0885"}, []string{"DNS visibility"}),
		builtin(string(AlertMaliciousIP), AlertMaliciousIP, "Threat Intelligence — Malicious IP", "security", "critical", "threat_intel", "Observed IP matched configured threat intelligence.", []string{"Command and Control"}, []string{"T0885"}, []string{"threat intelligence"}),
		builtin(string(AlertMaliciousDomain), AlertMaliciousDomain, "Threat Intelligence — Malicious Domain", "security", "critical", "threat_intel", "Observed DNS name matched configured threat intelligence.", []string{"Command and Control"}, []string{"T0885"}, []string{"threat intelligence", "DNS visibility"}),
		builtin(string(AlertLateralMovement), AlertLateralMovement, "Lateral Movement Heuristics", "security", "high", "lateral_movement", "Administrative fan-out, pivots and large administrative transfers.", []string{"Lateral Movement"}, []string{"T0866", "T0867"}, []string{"mature behavior"}),
		builtin("builtin.smb_tool_transfer", AlertSMBToolTransfer, "SMB Tool / Executable Transfer Into OT", "security", "critical", "smb_semantics", "Executable/script transfer or suspicious remote-execution named pipe over SMB toward OT.", []string{"Lateral Movement", "Execution"}, []string{"T0867"}, []string{"SMB visibility", "OT asset context"}),

		// Stable packet/context built-ins previously documented but not executed.
		builtin("builtin.first_seen_remote_management", AlertFirstSeenRemoteManagement, "First-Seen Remote Management Relationship", "security", "medium", "remote_management", "A new remote-management source→target relationship appears after baseline.", []string{"Lateral Movement"}, []string{"T0886"}, []string{"mature baseline"}),
		builtin("builtin.remote_management_into_ot", AlertRemoteAdminIntoOT, "Remote Management Into OT", "security", "high", "remote_management", "Remote-management traffic enters an OT asset from outside its trusted management relationships.", []string{"Lateral Movement"}, []string{"T0886"}, []string{"OT asset context"}),
		builtin("builtin.direct_ot_protocol_access", AlertDirectOTProtocolAccess, "Direct OT Protocol Access", "ics", "high", "ics_policy", "A source directly accesses an OT controller protocol without a learned/approved relationship.", []string{"Execution"}, []string{"T0855"}, []string{"OT protocol visibility"}),
		builtin("builtin.smb_into_ot", AlertSMBIntoOT, "SMB Into OT", "security", "medium", "remote_management", "SMB traffic crosses into an OT asset from a non-OT or unapproved source.", []string{"Lateral Movement"}, []string{"T0867"}, []string{"OT asset context"}),
		builtin("builtin.unexpected_engineering_access", AlertUnexpectedEngineeringAccess, "Unexpected Engineering Access", "ics", "high", "engineering_role", "Engineering-style access to a controller comes from a source not known for that target.", []string{"Execution"}, []string{"T0855"}, []string{"mature ICS relationship"}),
		builtin("builtin.large_controller_transfer", AlertLargeControllerTransfer, "Large Transfer To Controller", "ics", "high", "controller_transfer", "A large transfer is observed toward a controller/OT service outside normal behavior.", []string{"Lateral Movement", "Impact"}, []string{"T0843", "T0867"}, []string{"OT protocol visibility"}),

		builtin(string(AlertBehaviorFinding), AlertBehaviorFinding, "Network Behavior Finding", "behavior", "high", "nba", "Network Behavior Analytics finding above configured risk threshold.", []string{"Discovery", "Command and Control"}, nil, []string{"mature behavior baseline"}),
		builtin(string(AlertBehaviorIncident), AlertBehaviorIncident, "Network Behavior Incident Candidate", "behavior", "high", "nba", "Correlated NBA finding that meets incident-candidate threshold.", []string{"Discovery", "Command and Control"}, nil, []string{"mature behavior baseline"}),
	}
	out := map[string]*Rule{}
	for _, r := range seed {
		r.Kind = RuleKindBuiltin
		r.Enabled = true
		r.Version = 1
		r.Priority = 100
		if r.Suppression.Mode == "" {
			r.Suppression = RuleSuppression{Mode: "aggregate"}
		}
		if r.Schedule == "" {
			r.Schedule = "always"
		}
		out[r.ID] = r
	}
	// Context-heavy relationship rules start in simulation so an upgrade does
	// not suddenly alert on every site whose asset roles/zones are not yet
	// curated. Operators can promote them to enforcement after observing hits.
	for _, id := range []string{
		"builtin.first_seen_remote_management", "builtin.remote_management_into_ot",
		"builtin.direct_ot_protocol_access", "builtin.smb_into_ot",
		"builtin.unexpected_engineering_access", "builtin.large_controller_transfer",
	} {
		if r := out[id]; r != nil {
			r.Simulation = true
		}
	}

	icsProtocols := []string{"Modbus/TCP", "S7comm", "DNP3", "IEC 60870-5-104", "BACnet/IP", "EtherNet/IP", "OPC UA", "PROFINET DCP"}
	for _, id := range []string{
		"builtin.unauthorized_ot_command", "builtin.controller_program_change", "builtin.controller_mode_change",
		"builtin.controller_configuration_change", "builtin.unauthorized_ot_write", "builtin.brute_force_io",
		"builtin.unauthorized_time_change", "builtin.process_sequence_violation", "builtin.malformed_ot_burst",
		"builtin.ot_reporting_loss", "builtin.unexpected_ot_protocol", "builtin.direct_ot_protocol_access",
		"builtin.unexpected_engineering_access", "builtin.large_controller_transfer",
	} {
		if r := out[id]; r != nil {
			r.Protocols = append([]string(nil), icsProtocols...)
		}
	}
	if r := out["builtin.smb_tool_transfer"]; r != nil {
		r.Protocols = []string{"SMB2", "SMB3 metadata"}
	}
	if r := out["builtin.smb_into_ot"]; r != nil {
		r.Protocols = []string{"SMB2", "SMB3 metadata"}
	}
	if r := out["builtin.dns_tunneling"]; r != nil {
		r.Protocols = []string{"DNS"}
	}

	// Product defaults for detector-specific thresholds. These are policy
	// parameters: operators may override them per sensor without replacing the
	// detector definition. Unknown parameters are retained for forward
	// compatibility but ignored until a detector consumes them.
	setBuiltinParameters(out, "builtin.brute_force_io", map[string]float64{"commands_threshold": 50, "window_seconds": 10})
	setBuiltinParameters(out, "builtin.malformed_ot_burst", map[string]float64{"errors_threshold": 10, "window_seconds": 60})
	setBuiltinParameters(out, "builtin.ot_reporting_loss", map[string]float64{"min_samples": 10, "cadence_multiplier": 5, "min_missing_seconds": 600, "max_missing_seconds": 21600})
	setBuiltinParameters(out, "builtin.new_engineering_workstation", map[string]float64{"controller_threshold": 3, "window_hours": 24})
	setBuiltinParameters(out, "builtin.large_controller_transfer", map[string]float64{"bytes_threshold": 10485760, "window_seconds": 300})
	setBuiltinParameters(out, "builtin.dns_tunneling", map[string]float64{"min_queries": 20, "window_seconds": 600, "score_threshold": 60})
	setBuiltinParameters(out, "builtin.gratuitous_arp_storm", map[string]float64{"events_threshold": 20, "window_seconds": 60})
	return out
}

func setBuiltinParameters(rules map[string]*Rule, id string, values map[string]float64) {
	if r := rules[id]; r != nil {
		r.Parameters = cloneRuleParameters(values)
	}
}

func cloneRule(rule *Rule) *Rule {
	if rule == nil {
		return nil
	}
	clone := *rule
	clone.MITRETactics = append([]string(nil), rule.MITRETactics...)
	clone.MITRETechniques = append([]string(nil), rule.MITRETechniques...)
	clone.Prerequisites = append([]string(nil), rule.Prerequisites...)
	clone.Protocols = append([]string(nil), rule.Protocols...)
	clone.Parameters = cloneRuleParameters(rule.Parameters)
	clone.Actions = append([]RuleAction(nil), rule.Actions...)
	if len(rule.Groups) > 0 {
		clone.Groups = make([]RuleGroup, len(rule.Groups))
		for i, group := range rule.Groups {
			clone.Groups[i] = group
			clone.Groups[i].Conditions = append([]RuleCondition(nil), group.Conditions...)
		}
	}
	return &clone
}

func cloneRuleParameters(values map[string]float64) map[string]float64 {
	if values == nil {
		return nil
	}
	out := make(map[string]float64, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}

func builtin(id string, alertType AlertType, name, category, severity, detector, description string, tactics, techniques, prerequisites []string) *Rule {
	return &Rule{ID: id, Name: name, Description: description, Category: category, Severity: severity, AlertType: alertType, Detector: detector, MITRETactics: tactics, MITRETechniques: techniques, Prerequisites: prerequisites}
}

func (e *Engine) isRuleEnabled(id string) bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.isRuleEnabledLocked(id)
}
func (e *Engine) isRuleEnabledLocked(id string) bool {
	r, ok := e.rules[id]
	if !ok {
		return true
	}
	return r.Enabled
}

func (e *Engine) GetRules() []RuleView {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	result := make([]RuleView, 0, len(e.rules))
	for _, rule := range e.rules {
		cloned := cloneRule(rule)
		view := RuleView{Rule: *cloned, SimulationHits: rule.SimulationHits, LastSimulationHit: rule.LastSimulationHit}
		for _, a := range e.alerts {
			if a.Type == rule.AlertType {
				view.HitCount += a.Count
				if a.LastSeen.After(view.LastHit) {
					view.LastHit = a.LastSeen
					view.LastHitIP = a.IP
				}
			}
		}
		result = append(result, view)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Priority == result[j].Priority {
			return result[i].Name < result[j].Name
		}
		return result[i].Priority < result[j].Priority
	})
	return result
}
func (e *Engine) GetRuleConfigs() []*Rule {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	out := make([]*Rule, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, cloneRule(r))
	}
	return out
}
func (e *Engine) RestoreRules(rules []*Rule) { e.ReplaceManagedRules(rules) }

func normalizeRule(r *Rule) error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name must not be empty")
	}
	if r.Severity == "" {
		r.Severity = "medium"
	}
	switch r.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("unrecognized severity %q", r.Severity)
	}
	if r.Priority == 0 {
		r.Priority = 100
	}
	if r.Version == 0 {
		r.Version = 1
	}
	if r.GroupOperator == "" {
		r.GroupOperator = "AND"
	}
	r.GroupOperator = strings.ToUpper(r.GroupOperator)
	if r.GroupOperator != "AND" && r.GroupOperator != "OR" {
		return fmt.Errorf("group_operator must be AND or OR")
	}
	if len(r.Groups) == 0 && r.Field != "" {
		r.Groups = []RuleGroup{{Operator: "AND", Conditions: []RuleCondition{{Field: r.Field, Operator: "eq", Value: r.Value}}}}
	}
	if len(r.Groups) == 0 {
		return fmt.Errorf("at least one condition is required")
	}
	for gi := range r.Groups {
		g := &r.Groups[gi]
		g.Operator = strings.ToUpper(g.Operator)
		if g.Operator == "" {
			g.Operator = "AND"
		}
		if g.Operator != "AND" && g.Operator != "OR" {
			return fmt.Errorf("group operator must be AND or OR")
		}
		if len(g.Conditions) == 0 {
			return fmt.Errorf("condition group is empty")
		}
		for _, c := range g.Conditions {
			if strings.TrimSpace(c.Value) == "" {
				return fmt.Errorf("condition value must not be empty")
			}
			if !validField(c.Field) {
				return fmt.Errorf("unsupported field %q", c.Field)
			}
			if !validOperator(c.Operator) {
				return fmt.Errorf("unsupported operator %q", c.Operator)
			}
			if c.Operator == "regex" {
				if _, err := regexp.Compile(c.Value); err != nil {
					return fmt.Errorf("invalid regex: %w", err)
				}
			}
		}
	}
	if len(r.Actions) == 0 {
		r.Actions = []RuleAction{{Type: "alert"}}
	}
	if r.Suppression.Mode == "" {
		r.Suppression.Mode = "aggregate"
	}
	switch r.Suppression.Mode {
	case "every", "once", "interval", "aggregate":
	default:
		return fmt.Errorf("unsupported suppression mode %q", r.Suppression.Mode)
	}
	if r.Suppression.Mode == "interval" && r.Suppression.IntervalSeconds <= 0 {
		return fmt.Errorf("interval_seconds must be positive")
	}
	return nil
}
func validField(f RuleField) bool {
	switch f {
	case RuleFieldSrcIP, RuleFieldDstIP, RuleFieldEitherIP, RuleFieldSrcMAC, RuleFieldDstMAC, RuleFieldProtocol, RuleFieldSrcPort, RuleFieldDstPort, RuleFieldPort, RuleFieldVLAN, RuleFieldPacketSize, RuleFieldTCPFlags:
		return true
	}
	return false
}
func validOperator(o string) bool {
	switch strings.ToLower(o) {
	case "eq", "neq", "gt", "gte", "lt", "lte", "contains", "starts_with", "ends_with", "in", "not_in", "regex", "between":
		return true
	}
	return false
}

func (e *Engine) AddCustomRule(name string, field RuleField, value, severity string) (*Rule, error) {
	return e.AddPolicyRule(&Rule{Name: name, Kind: RuleKindCustom, Enabled: true, Field: field, Value: value, Severity: severity})
}
func (e *Engine) AddPolicyRule(rule *Rule) (*Rule, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is nil")
	}
	clone := *rule
	clone.Kind = RuleKindCustom
	if err := normalizeRule(&clone); err != nil {
		return nil, err
	}
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.customRuleSeq++
	if clone.ID == "" {
		clone.ID = fmt.Sprintf("custom-%d", e.customRuleSeq)
	}
	clone.AlertType = AlertType("custom:" + clone.ID)
	e.rules[clone.ID] = &clone
	c := clone
	return &c, nil
}
func (e *Engine) UpsertPolicyRule(rule *Rule) error {
	if rule == nil || rule.ID == "" {
		return fmt.Errorf("rule id required")
	}
	clone := *rule
	if clone.Kind == "" {
		clone.Kind = RuleKindCustom
	}
	if clone.Kind == RuleKindCustom {
		if err := normalizeRule(&clone); err != nil {
			return err
		}
		clone.AlertType = AlertType("custom:" + clone.ID)
	}
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if old, ok := e.rules[clone.ID]; ok {
		if old.Kind == RuleKindBuiltin {
			old.Enabled = clone.Enabled
			if clone.Severity != "" {
				old.Severity = clone.Severity
			}
			old.SeverityOverride = clone.SeverityOverride
			if clone.Priority > 0 {
				old.Priority = clone.Priority
			}
			old.Simulation = clone.Simulation
			if clone.Suppression.Mode != "" {
				old.Suppression = clone.Suppression
			}
			if clone.Schedule != "" {
				old.Schedule = clone.Schedule
			}
			if clone.Parameters != nil {
				old.Parameters = cloneRuleParameters(clone.Parameters)
			}
			if clone.Version <= old.Version {
				old.Version++
			} else {
				old.Version = clone.Version
			}
			return nil
		}
		if clone.Version <= old.Version {
			clone.Version = old.Version + 1
		}
	}
	e.rules[clone.ID] = &clone
	return nil
}

type RulePolicyPatch struct {
	ID               string              `json:"id"`
	Enabled          *bool               `json:"enabled,omitempty"`
	Severity         *string             `json:"severity,omitempty"`
	SeverityOverride *bool               `json:"severity_override,omitempty"`
	Priority         *int                `json:"priority,omitempty"`
	Simulation       *bool               `json:"simulation,omitempty"`
	Suppression      *RuleSuppression    `json:"suppression,omitempty"`
	Schedule         *string             `json:"schedule,omitempty"`
	Parameters       *map[string]float64 `json:"parameters,omitempty"`
}

func (e *Engine) ApplyRulePolicyPatch(p RulePolicyPatch) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	r := e.rules[p.ID]
	if r == nil {
		return fmt.Errorf("rule %q not found", p.ID)
	}
	if p.Enabled != nil {
		r.Enabled = *p.Enabled
	}
	if p.Severity != nil {
		v := strings.ToLower(strings.TrimSpace(*p.Severity))
		switch v {
		case "info", "low", "medium", "high", "critical":
			r.Severity = v
			r.SeverityOverride = true
		default:
			return fmt.Errorf("unrecognized severity %q", v)
		}
	}
	if p.SeverityOverride != nil {
		r.SeverityOverride = *p.SeverityOverride
		if !r.SeverityOverride && r.Kind == RuleKindBuiltin {
			if product := builtinRules()[r.ID]; product != nil {
				r.Severity = product.Severity
			}
		}
	}
	if p.Priority != nil {
		if *p.Priority <= 0 {
			return fmt.Errorf("priority must be positive")
		}
		r.Priority = *p.Priority
	}
	if p.Simulation != nil {
		r.Simulation = *p.Simulation
	}
	if p.Suppression != nil {
		v := strings.ToLower(strings.TrimSpace(p.Suppression.Mode))
		if v == "" {
			v = "aggregate"
		}
		switch v {
		case "every", "once", "interval", "aggregate":
		default:
			return fmt.Errorf("unsupported suppression mode %q", v)
		}
		if v == "interval" && p.Suppression.IntervalSeconds <= 0 {
			return fmt.Errorf("interval_seconds must be positive")
		}
		r.Suppression = *p.Suppression
		r.Suppression.Mode = v
	}
	if p.Schedule != nil {
		v := strings.TrimSpace(*p.Schedule)
		if v == "" {
			v = "always"
		}
		r.Schedule = v
	}
	if p.Parameters != nil {
		for k, v := range *p.Parameters {
			if strings.TrimSpace(k) == "" || v < 0 {
				return fmt.Errorf("invalid built-in parameter %q", k)
			}
		}
		r.Parameters = cloneRuleParameters(*p.Parameters)
	}
	r.Version++
	return nil
}

func (e *Engine) ToggleRule(id string, enabled bool) bool {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	r, ok := e.rules[id]
	if !ok {
		return false
	}
	r.Enabled = enabled
	r.Version++
	return true
}
func (e *Engine) DeleteRule(id string) bool {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	r, ok := e.rules[id]
	if !ok || r.Kind == RuleKindBuiltin {
		return false
	}
	delete(e.rules, id)
	return true
}

func (e *Engine) startCustomRuleWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventPacketParsed)
	go func() {
		for ev := range ch {
			p, ok := ev.Data.(core.Packet)
			if ok {
				e.handleCustomRules(p)
			}
		}
	}()
}
func (e *Engine) handleCustomRules(packet core.Packet) {
	e.mutex.RLock()
	rules := make([]*Rule, 0)
	for _, r := range e.rules {
		if r.Kind == RuleKindCustom && r.Enabled && ruleMatches(r, packet) {
			c := *r
			rules = append(rules, &c)
		}
	}
	e.mutex.RUnlock()
	now := time.Now()
	for _, r := range rules {
		if r.Simulation {
			e.mutex.Lock()
			if live := e.rules[r.ID]; live != nil {
				live.SimulationHits++
				live.LastSimulationHit = now
			}
			e.mutex.Unlock()
			continue
		}
		// A live custom rule is an explicit operator policy/signature. Matching
		// traffic is therefore never allowed to become trusted baseline during
		// commissioning, even if alert suppression later coalesces the finding.
		e.excludePacketFromLearning(packet, "custom policy rule "+r.ID)
		if r.Suppression.Mode == "once" && !r.LastTriggered.IsZero() {
			continue
		}
		if r.Suppression.Mode == "interval" && !r.LastTriggered.IsZero() && now.Sub(r.LastTriggered) < time.Duration(r.Suppression.IntervalSeconds)*time.Second {
			continue
		}
		key := fmt.Sprintf("%s|%s|%s", r.ID, packet.SrcIP, packet.DstIP)
		if r.Suppression.Mode == "every" {
			key = fmt.Sprintf("%s|%d", key, now.UnixNano())
		}
		msg := fmt.Sprintf("Policy rule %q matched: %s -> %s", r.Name, packet.SrcIP, packet.DstIP)
		e.raiseCustomRuleAlert(r, key, msg, packet.SrcIP)
		e.mutex.Lock()
		if live := e.rules[r.ID]; live != nil {
			live.LastTriggered = now
		}
		e.mutex.Unlock()
	}
}
func ruleMatches(r *Rule, p core.Packet) bool {
	results := make([]bool, 0, len(r.Groups))
	for _, g := range r.Groups {
		m := g.Operator == "AND"
		for i, c := range g.Conditions {
			v := conditionMatches(c, p)
			if i == 0 {
				m = v
			} else if g.Operator == "AND" {
				m = m && v
			} else {
				m = m || v
			}
		}
		results = append(results, m)
	}
	out := r.GroupOperator == "AND"
	for i, v := range results {
		if i == 0 {
			out = v
		} else if r.GroupOperator == "AND" {
			out = out && v
		} else {
			out = out || v
		}
	}
	return out
}
func conditionMatches(c RuleCondition, p core.Packet) bool {
	var actual string
	switch c.Field {
	case RuleFieldSrcIP:
		actual = p.SrcIP
	case RuleFieldDstIP:
		actual = p.DstIP
	case RuleFieldEitherIP:
		return compare(p.SrcIP, c.Operator, c.Value) || compare(p.DstIP, c.Operator, c.Value)
	case RuleFieldSrcMAC:
		actual = p.SrcMAC
	case RuleFieldDstMAC:
		actual = p.DstMAC
	case RuleFieldProtocol:
		actual = p.L4Protocol
	case RuleFieldSrcPort:
		actual = strconv.Itoa(int(p.SrcPort))
	case RuleFieldDstPort:
		actual = strconv.Itoa(int(p.DstPort))
	case RuleFieldPort:
		return compare(strconv.Itoa(int(p.SrcPort)), c.Operator, c.Value) || compare(strconv.Itoa(int(p.DstPort)), c.Operator, c.Value)
	case RuleFieldVLAN:
		actual = strconv.Itoa(int(p.VLANID))
	case RuleFieldPacketSize:
		actual = strconv.Itoa(p.Length)
	case RuleFieldTCPFlags:
		actual = p.TCPFlags
	}
	return compare(actual, c.Operator, c.Value)
}
func compare(actual, op, want string) bool {
	switch strings.ToLower(op) {
	case "eq":
		return strings.EqualFold(actual, want)
	case "neq":
		return !strings.EqualFold(actual, want)
	case "contains":
		return strings.Contains(strings.ToLower(actual), strings.ToLower(want))
	case "starts_with":
		return strings.HasPrefix(strings.ToLower(actual), strings.ToLower(want))
	case "ends_with":
		return strings.HasSuffix(strings.ToLower(actual), strings.ToLower(want))
	case "in", "not_in":
		found := false
		for _, x := range strings.Split(want, ",") {
			if strings.EqualFold(strings.TrimSpace(x), actual) {
				found = true
			}
		}
		if op == "not_in" {
			return !found
		}
		return found
	case "regex":
		ok, _ := regexp.MatchString(want, actual)
		return ok
	case "between":
		parts := strings.Split(want, ",")
		if len(parts) != 2 {
			return false
		}
		a, e1 := strconv.ParseFloat(actual, 64)
		lo, e2 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		hi, e3 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		return e1 == nil && e2 == nil && e3 == nil && a >= lo && a <= hi
	case "gt", "gte", "lt", "lte":
		a, e1 := strconv.ParseFloat(actual, 64)
		b, e2 := strconv.ParseFloat(want, 64)
		if e1 != nil || e2 != nil {
			return false
		}
		switch op {
		case "gt":
			return a > b
		case "gte":
			return a >= b
		case "lt":
			return a < b
		default:
			return a <= b
		}
	}
	return false
}
func (e *Engine) raiseCustomRuleAlert(rule *Rule, key, message, ip string) {
	now := time.Now()
	e.mutex.Lock()
	defer e.mutex.Unlock()
	a, ok := e.alerts[key]
	if ok && !e.allowAlertOccurrenceLocked(a) {
		return
	}
	if !ok {
		a = &Alert{ID: key, Type: rule.AlertType, Severity: rule.Severity, Message: message, IP: ip, FirstSeen: now, Status: AlertStatusNew}
		e.alerts[key] = a
		e.logNewAlert(a)
	}
	a.LastSeen = now
	a.Count++
	a.Synced = false
}
func (e *Engine) ReplaceManagedRules(rules []*Rule) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	for id, r := range e.rules {
		if r.Kind == RuleKindCustom {
			delete(e.rules, id)
		}
	}
	for _, r := range rules {
		if r == nil {
			continue
		}
		clone := *r
		if clone.Kind == RuleKindBuiltin {
			if x := e.rules[clone.ID]; x != nil {
				// Product definition/metadata (name, detector, description, ATT&CK,
				// prerequisites and alert type) stays local and upgrade-controlled.
				// Only the documented policy layer is operator-controlled.
				x.Enabled = clone.Enabled
				if clone.Severity != "" {
					x.Severity = clone.Severity
				}
				x.SeverityOverride = clone.SeverityOverride
				if clone.Priority > 0 {
					x.Priority = clone.Priority
				}
				x.Simulation = clone.Simulation
				if clone.Suppression.Mode != "" {
					x.Suppression = clone.Suppression
				}
				if clone.Schedule != "" {
					x.Schedule = clone.Schedule
				}
				if clone.Parameters != nil {
					x.Parameters = cloneRuleParameters(clone.Parameters)
				}
				if clone.Version > 0 {
					x.Version = clone.Version
				}
			}
			continue
		}
		if normalizeRule(&clone) == nil {
			clone.AlertType = AlertType("custom:" + clone.ID)
			e.rules[clone.ID] = &clone
		}
	}
}
