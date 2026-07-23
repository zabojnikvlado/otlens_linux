package detect

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// RuleKind distinguishes a built-in detection rule (hardcoded logic
// elsewhere in this package — arpspoof.go, honeypot.go, etc. —
// toggleable here but never deletable) from a user-created custom
// rule (a simple field/value match, fully deletable).
type RuleKind string

const (
	RuleKindBuiltin RuleKind = "builtin"
	RuleKindCustom  RuleKind = "custom"
)

// RuleField is which packet attribute a custom rule matches against.
// Deliberately a small, fixed set rather than an open-ended
// expression language — this covers the common "alert me if this
// specific IP/port/protocol shows up" need without building a whole
// rule DSL for a first version of user-defined rules.
type RuleField string

const (
	RuleFieldSrcIP    RuleField = "src_ip"
	RuleFieldDstIP    RuleField = "dst_ip"
	RuleFieldEitherIP RuleField = "either_ip"
	RuleFieldProtocol RuleField = "protocol"
	RuleFieldPort     RuleField = "port"
)

// Rule is one configured rule, built-in or custom. For a built-in
// rule, Field/Value/Severity are unused (the actual match logic
// lives in that rule's own file — arpspoof.go, honeypot.go, etc.);
// this struct only carries whether it's toggled on and which
// AlertType its hits are counted under.
type Rule struct {
	ID      string
	Name    string
	Kind    RuleKind
	Enabled bool

	// Custom rules only.
	Field    RuleField
	Value    string
	Severity string

	// AlertType is what a hit from this rule is filed under in
	// e.alerts — for a built-in rule, one of the existing AlertType
	// constants; for a custom rule, a synthetic "custom:<id>" type
	// used by nothing else. GetRules aggregates Count/LastSeen/IP
	// from e.alerts by matching on this field, rather than this
	// package tracking hit stats a second, separate way.
	AlertType AlertType
}

// RuleView is a Rule plus its current hit stats, as returned by
// GetRules and the /rules API — never persisted itself (Count/
// LastHit/LastHitIP are recomputed from e.alerts on every call, not
// stored state).
type RuleView struct {
	Rule

	HitCount  uint64
	LastHit   time.Time
	LastHitIP string
}

// builtinRules seeds the fixed set of hardcoded detection rules —
// see each rule's own file for the actual matching logic; this is
// only the toggle/metadata layer over it.
func builtinRules() map[string]*Rule {

	seed := []*Rule{
		{ID: string(AlertARPSpoof), Name: "ARP Spoofing", AlertType: AlertARPSpoof},
		{ID: string(AlertNewCommunication), Name: "New Communication (baseline)", AlertType: AlertNewCommunication},
		{ID: string(AlertICSCriticalOperation), Name: "Critical ICS Operation", AlertType: AlertICSCriticalOperation},
		{ID: string(AlertNewAsset), Name: "New Asset (baseline)", AlertType: AlertNewAsset},
		{ID: string(AlertValueOutOfRange), Name: "Value Out of Range", AlertType: AlertValueOutOfRange},
		{ID: string(AlertHoneypotProbed), Name: "Honeypot Probed", AlertType: AlertHoneypotProbed},
		{ID: string(AlertHoneypotLateralMovement), Name: "Honeypot Lateral Movement", AlertType: AlertHoneypotLateralMovement},
	}

	rules := make(map[string]*Rule, len(seed))

	for _, r := range seed {
		r.Kind = RuleKindBuiltin
		r.Enabled = true
		rules[r.ID] = r
	}

	return rules
}

// isRuleEnabled reports whether the rule with this ID is currently
// enabled. Defaults to true for an unrecognized ID — a rule handler
// should never silently stop working because of a typo'd/stale ID
// rather than an actual, deliberate toggle-off.
//
// Only for callers that do NOT already hold e.mutex — see
// isRuleEnabledLocked for the version used from inside an
// already-locked section (baseline.go's handleBaseline holds the
// write lock for its whole body, so calling this lock-acquiring
// version from partway through it would deadlock against itself).
func (e *Engine) isRuleEnabled(id string) bool {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return e.isRuleEnabledLocked(id)
}

// isRuleEnabledLocked is isRuleEnabled's logic without acquiring the
// lock itself — caller must already hold e.mutex (read or write).
func (e *Engine) isRuleEnabledLocked(id string) bool {

	rule, exists := e.rules[id]

	if !exists {
		return true
	}

	return rule.Enabled
}

// GetRules returns every configured rule (built-in and custom) with
// current hit stats aggregated from e.alerts — Alert already tracks
// Count/LastSeen/IP for exactly this purpose, so no separate stats-
// tracking mechanism exists here, just a grouping pass over what's
// already there.
func (e *Engine) GetRules() []RuleView {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]RuleView, 0, len(e.rules))

	for _, rule := range e.rules {

		view := RuleView{Rule: *rule}

		for _, alert := range e.alerts {

			if alert.Type != rule.AlertType {
				continue
			}

			view.HitCount += alert.Count

			if alert.LastSeen.After(view.LastHit) {
				view.LastHit = alert.LastSeen
				view.LastHitIP = alert.IP
			}
		}

		result = append(result, view)
	}

	return result
}

// GetRuleConfigs returns the raw, persistable rule configuration
// (no aggregated stats — those are recomputed live from e.alerts,
// which is itself already persisted separately, so persisting them
// again here would be redundant). Used by internal/persist.
func (e *Engine) GetRuleConfigs() []*Rule {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]*Rule, 0, len(e.rules))

	for _, rule := range e.rules {

		clone := *rule

		result = append(result, &clone)
	}

	return result
}

// RestoreRules rehydrates rule configuration from disk at startup —
// built-in rules keep their seeded identity/AlertType but take the
// persisted Enabled value; custom rules are restored as-is. Also
// advances the custom-rule ID sequence past every restored custom
// rule's numeric suffix, so a newly-created rule after a restart
// can't collide with a restored one's ID.
func (e *Engine) RestoreRules(rules []*Rule) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	for _, r := range rules {

		if r.Kind == RuleKindBuiltin {

			if existing, ok := e.rules[r.ID]; ok {
				existing.Enabled = r.Enabled
			}

			continue
		}

		e.rules[r.ID] = r

		var seq int

		if _, err := fmt.Sscanf(r.ID, "custom-%d", &seq); err == nil && seq > e.customRuleSeq {
			e.customRuleSeq = seq
		}
	}
}

// AddCustomRule creates a new custom rule, rejecting an unrecognized
// field/severity or an empty value outright — better to fail loudly
// at creation than to silently create a rule that can never match
// anything.
func (e *Engine) AddCustomRule(name string, field RuleField, value string, severity string) (*Rule, error) {

	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("value must not be empty")
	}

	switch field {
	case RuleFieldSrcIP, RuleFieldDstIP, RuleFieldEitherIP, RuleFieldProtocol, RuleFieldPort:
	default:
		return nil, fmt.Errorf("unrecognized field %q", field)
	}

	switch severity {
	case "low", "medium", "high", "critical":
	default:
		return nil, fmt.Errorf("unrecognized severity %q", severity)
	}

	if field == RuleFieldPort {

		if _, err := strconv.Atoi(value); err != nil {
			return nil, fmt.Errorf("port value %q is not a number", value)
		}
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.customRuleSeq++
	id := fmt.Sprintf("custom-%d", e.customRuleSeq)

	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("%s = %s", field, value)
	}

	rule := &Rule{
		ID:        id,
		Name:      name,
		Kind:      RuleKindCustom,
		Enabled:   true,
		Field:     field,
		Value:     value,
		Severity:  severity,
		AlertType: AlertType("custom:" + id),
	}

	e.rules[id] = rule

	clone := *rule

	return &clone, nil
}

// ToggleRule flips Enabled for the rule with this ID — works for
// both built-in and custom rules. Returns false if no such rule
// exists.
func (e *Engine) ToggleRule(id string, enabled bool) bool {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	rule, exists := e.rules[id]

	if !exists {
		return false
	}

	rule.Enabled = enabled

	return true
}

// DeleteRule removes a custom rule. Built-in rules can't be deleted,
// only toggled off (see ToggleRule) — returns false for that case
// exactly the same as "not found", since from the API's point of
// view both are equally "nothing was deleted."
func (e *Engine) DeleteRule(id string) bool {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	rule, exists := e.rules[id]

	if !exists || rule.Kind == RuleKindBuiltin {
		return false
	}

	delete(e.rules, id)

	return true
}

// startCustomRuleWatch evaluates every enabled custom rule against
// each parsed packet — same event, same per-packet dispatch pattern
// as every built-in rule in this package.
func (e *Engine) startCustomRuleWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok {
				continue
			}

			e.handleCustomRules(packet)
		}

	}()

}

func (e *Engine) handleCustomRules(packet core.Packet) {

	e.mutex.RLock()

	matched := make([]*Rule, 0)

	for _, rule := range e.rules {

		if rule.Kind != RuleKindCustom || !rule.Enabled {
			continue
		}

		if customRuleMatches(rule, packet) {
			matched = append(matched, rule)
		}
	}

	e.mutex.RUnlock()

	for _, rule := range matched {

		key := fmt.Sprintf("%s|%s|%s", rule.ID, packet.SrcIP, packet.DstIP)

		message := fmt.Sprintf(
			"Custom rule %q matched (%s = %s): %s -> %s",
			rule.Name, rule.Field, rule.Value, packet.SrcIP, packet.DstIP,
		)

		e.raiseCustomRuleAlert(rule, key, message, packet.SrcIP)
	}
}

func customRuleMatches(rule *Rule, packet core.Packet) bool {

	switch rule.Field {

	case RuleFieldSrcIP:
		return packet.SrcIP != "" && packet.SrcIP == rule.Value

	case RuleFieldDstIP:
		return packet.DstIP != "" && packet.DstIP == rule.Value

	case RuleFieldEitherIP:
		return (packet.SrcIP != "" && packet.SrcIP == rule.Value) ||
			(packet.DstIP != "" && packet.DstIP == rule.Value)

	case RuleFieldProtocol:
		return packet.L4Protocol != "" && strings.EqualFold(packet.L4Protocol, rule.Value)

	case RuleFieldPort:

		port, err := strconv.Atoi(rule.Value)

		if err != nil {
			return false
		}

		return int(packet.SrcPort) == port || int(packet.DstPort) == port
	}

	return false
}

// raiseCustomRuleAlert follows the exact same dedup/logNewAlert
// pattern as every built-in rule's raise* function in this package.
func (e *Engine) raiseCustomRuleAlert(rule *Rule, key, message, ip string) {

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[key]

	if !exists {

		alert = &Alert{
			ID: key,

			Type:     rule.AlertType,
			Severity: rule.Severity,
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
}

// ReplaceManagedRules applies a centrally managed rule set while preserving
// the built-in rule identities. Custom rules not present in the central set
// are removed, making the central rule set authoritative for the sensor.
func (e *Engine) ReplaceManagedRules(rules []*Rule) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	for id, existing := range e.rules {
		if existing.Kind == RuleKindCustom {
			delete(e.rules, id)
		}
	}
	for _, incoming := range rules {
		if incoming == nil {
			continue
		}
		if incoming.Kind == RuleKindBuiltin {
			if existing, ok := e.rules[incoming.ID]; ok {
				existing.Enabled = incoming.Enabled
			}
			continue
		}
		clone := *incoming
		e.rules[clone.ID] = &clone
	}
}
