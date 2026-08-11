package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	passivedns "github.com/zabojnikvlado/otlens_linux/internal/dns"
	"github.com/zabojnikvlado/otlens_linux/internal/threatintel"
)

func (e *Engine) startThreatIntelWatch(bus *core.EventBus) {
	if e.threatIntel == nil {
		return
	}
	packets := bus.Subscribe(core.EventPacketParsed)
	go func() {
		for event := range packets {
			if p, ok := event.Data.(core.Packet); ok {
				e.handleThreatIP(p)
			}
		}
	}()
	dnsEvents := bus.Subscribe(core.EventDNSObservation)
	go func() {
		for event := range dnsEvents {
			if o, ok := event.Data.(passivedns.Observation); ok {
				e.handleThreatDomain(o)
			}
		}
	}()
}

func (e *Engine) handleThreatIP(p core.Packet) {
	if p.SrcIP == "" || p.DstIP == "" {
		return
	}
	for _, candidate := range []struct{ observed, local string }{{p.SrcIP, p.DstIP}, {p.DstIP, p.SrcIP}} {
		indicator, ok := e.threatIntel.MatchIP(candidate.observed)
		if !ok {
			continue
		}
		e.excludePacketFromLearning(p, "threat-intelligence IP match")
		e.raiseThreatAlert(AlertMaliciousIP, candidate.local, candidate.observed, indicator, "IP")
	}
}

func (e *Engine) handleThreatDomain(o passivedns.Observation) {
	values := append([]string{o.QueryName}, o.CNAMEs...)
	for _, v := range values {
		if indicator, ok := e.threatIntel.MatchDomain(v); ok {
			e.raiseThreatAlert(AlertMaliciousDomain, o.ClientIP, v, indicator, "domain")
			return
		}
	}
	for _, ip := range o.Answers {
		if indicator, ok := e.threatIntel.MatchIP(ip); ok {
			e.raiseThreatAlert(AlertMaliciousIP, o.ClientIP, ip, indicator, "DNS answer IP")
			return
		}
	}
}

func (e *Engine) raiseThreatAlert(kind AlertType, local, matched string, indicator threatintel.Indicator, label string) {
	key := fmt.Sprintf("%s|%s|%s", kind, local, matched)
	now := time.Now()
	severity := "high"
	if indicator.Confidence >= 90 {
		severity = "critical"
	} else if indicator.Confidence < 60 {
		severity = "medium"
	}
	evidence := map[string]interface{}{
		"indicator_type": indicator.Type, "indicator_value": indicator.Value, "provider": indicator.Provider,
		"threat_type": indicator.ThreatType, "threat_intel_confidence": indicator.Confidence, "matched": matched,
	}
	e.raiseBuiltinAlert(string(kind), kind, severity, key,
		fmt.Sprintf("%s observed %s matching threat-intelligence indicator %s (%s, confidence %d%%)", local, label, matched, indicator.Provider, indicator.Confidence),
		local, evidence, now, alertEpisodeGap)
}
