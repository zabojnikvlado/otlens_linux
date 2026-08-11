package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	passivedns "github.com/zabojnikvlado/otlens_linux/internal/dns"
)

func (e *Engine) startC2CorrelationWatch(bus *core.EventBus) {
	if !e.c2Correlation.Enabled {
		return
	}
	ch := bus.Subscribe(core.EventDNSObservation)
	go func() {
		for ev := range ch {
			if o, ok := ev.Data.(passivedns.Observation); ok {
				e.handleC2DNS(o)
			}
		}
	}()
}
func (e *Engine) handleC2DNS(o passivedns.Observation) {
	if o.ClientIP == "" || o.QueryName == "" {
		return
	}
	now := o.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	name := strings.TrimSuffix(strings.ToLower(o.QueryName), ".")
	score := 0
	signals := []string{}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if len(l) >= e.c2Correlation.LongLabelLength {
			score += 25
			signals = append(signals, "long_dns_label")
			break
		}
	}
	base := registrableApprox(name)
	e.c2DNSMutex.Lock()
	if o.ResponseCode != 0 {
		xs := append(e.c2NXDomains[o.ClientIP], now)
		cut := now.Add(-e.c2Correlation.DNSWindow)
		j := 0
		for _, t := range xs {
			if !t.Before(cut) {
				xs[j] = t
				j++
			}
		}
		xs = xs[:j]
		e.c2NXDomains[o.ClientIP] = xs
		if len(xs) >= e.c2Correlation.NXDomainThreshold {
			score += 35
			signals = append(signals, "nxdomain_burst")
		}
	}
	if e.c2Subdomains[o.ClientIP] == nil {
		e.c2Subdomains[o.ClientIP] = map[string]time.Time{}
	}
	subs := e.c2Subdomains[o.ClientIP]
	subs[name] = now
	cut := now.Add(-e.c2Correlation.DNSWindow)
	for k, t := range subs {
		if t.Before(cut) {
			delete(subs, k)
		}
	}
	unique := 0
	for n := range subs {
		if registrableApprox(n) == base {
			unique++
		}
	}
	if unique >= e.c2Correlation.UniqueSubdomainThreshold {
		score += 35
		signals = append(signals, "many_unique_subdomains")
	}
	e.c2DNSMutex.Unlock()
	if e.threatIntel != nil {
		if i, ok := e.threatIntel.MatchDomain(name); ok {
			score += minInt(50, i.Confidence/2+10)
			signals = append(signals, "threat_intel_match")
		}
	}
	if e.behaviorDetectionsSuppressed() {
		return
	}
	if score < e.c2Correlation.MinScore {
		return
	}
	if score > 100 {
		score = 100
	}
	confidence := minInt(95, 55+len(signals)*10)
	e.raiseC2Correlated(o.ClientIP, name, score, confidence, signals, map[string]interface{}{"query_name": name, "base_domain": base, "unique_subdomains": unique})
}
func registrableApprox(name string) string {
	p := strings.Split(name, ".")
	if len(p) < 2 {
		return name
	}
	return p[len(p)-2] + "." + p[len(p)-1]
}
func (e *Engine) raiseC2Correlated(ip, target string, score, confidence int, signals []string, extra map[string]interface{}) {
	if !e.isRuleEnabled(string(AlertC2Correlated)) {
		return
	}
	id := "c2_correlated|" + ip + "|" + target
	now := time.Now()
	extra["c2_score"] = score
	extra["c2_confidence"] = confidence
	extra["c2_signals"] = signals
	e.mutex.Lock()
	defer e.mutex.Unlock()
	a, exists := e.alerts[id]
	if exists && a.Status == AlertStatusApproved {
		return
	}
	if !exists {
		sev := "high"
		if score >= 85 {
			sev = "critical"
		}
		a = &Alert{ID: id, Type: AlertC2Correlated, Severity: sev, Message: fmt.Sprintf("possible C2 activity from %s via %s (score %d): %s", ip, target, score, strings.Join(signals, ", ")), IP: ip, FirstSeen: now, Status: AlertStatusNew, Evidence: extra}
		e.alerts[id] = a
		e.logNewAlert(a)
	}
	e.recordEpisodeAlertLocked(a, now, e.c2Correlation.DNSWindow)
}
