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
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description,omitempty"`
	Category      string          `json:"category,omitempty"`
	Kind          RuleKind        `json:"kind"`
	Enabled       bool            `json:"enabled"`
	Severity      string          `json:"severity,omitempty"`
	Priority      int             `json:"priority,omitempty"`
	Simulation    bool            `json:"simulation,omitempty"`
	Version       int             `json:"version,omitempty"`
	Groups        []RuleGroup     `json:"groups,omitempty"`
	GroupOperator string          `json:"group_operator,omitempty"`
	Actions       []RuleAction    `json:"actions,omitempty"`
	Suppression   RuleSuppression `json:"suppression,omitempty"`
	Schedule      string          `json:"schedule,omitempty"`

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
	seed := []*Rule{
		{ID: string(AlertARPSpoof), Name: "ARP Spoofing", Category: "security", AlertType: AlertARPSpoof},
		{ID: string(AlertNewCommunication), Name: "New Communication (baseline)", Category: "baseline", AlertType: AlertNewCommunication},
		{ID: string(AlertICSCriticalOperation), Name: "Critical ICS Operation", Category: "ics", AlertType: AlertICSCriticalOperation},
		{ID: string(AlertNewAsset), Name: "New Asset (baseline)", Category: "asset", AlertType: AlertNewAsset},
		{ID: string(AlertValueOutOfRange), Name: "Value Out of Range", Category: "ot_tag", AlertType: AlertValueOutOfRange},
		{ID: string(AlertHoneypotProbed), Name: "Honeypot Probed", Category: "security", AlertType: AlertHoneypotProbed},
		{ID: string(AlertHoneypotLateralMovement), Name: "Honeypot Lateral Movement", Category: "security", AlertType: AlertHoneypotLateralMovement},
	}
	out := map[string]*Rule{}
	for _, r := range seed {
		r.Kind = RuleKindBuiltin
		r.Enabled = true
		r.Version = 1
		r.Priority = 100
		out[r.ID] = r
	}
	return out
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
		view := RuleView{Rule: *rule, SimulationHits: rule.SimulationHits, LastSimulationHit: rule.LastSimulationHit}
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
		c := *r
		out = append(out, &c)
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
	if old, ok := e.rules[clone.ID]; ok && clone.Version <= old.Version {
		clone.Version = old.Version + 1
	}
	e.rules[clone.ID] = &clone
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
				x.Enabled = clone.Enabled
				x.Version = clone.Version
			}
			continue
		}
		if normalizeRule(&clone) == nil {
			clone.AlertType = AlertType("custom:" + clone.ID)
			e.rules[clone.ID] = &clone
		}
	}
}
