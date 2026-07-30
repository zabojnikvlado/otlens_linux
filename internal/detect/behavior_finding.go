package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/nba"
)

func (e *Engine) startBehaviorFindingWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventBehaviorFinding)
	go func() {
		for event := range ch {
			finding, ok := event.Data.(nba.Finding)
			if !ok || !finding.AlertCandidate || finding.State == nba.FindingExpired {
				continue
			}
			e.handleBehaviorFinding(finding)
		}
	}()
}

func (e *Engine) handleBehaviorFinding(finding nba.Finding) {
	alertType := AlertBehaviorFinding
	if finding.IncidentCandidate {
		alertType = AlertBehaviorIncident
	}
	ip, peer := "", finding.PeerID
	if len(finding.Assessments) > 0 {
		ip = finding.Assessments[0].Anomaly.SrcIP
		if peer == "" {
			peer = finding.Assessments[0].Anomaly.PeerID
		}
	}
	now := finding.LastSeen
	if now.IsZero() {
		now = time.Now()
	}
	key := "nba|" + finding.ID
	evidence := map[string]interface{}{
		"finding_id": finding.ID, "risk_score": finding.Score, "confidence": finding.Confidence,
		"reasons": finding.Reasons, "peer_id": peer, "alert_candidate": finding.AlertCandidate,
		"incident_candidate": finding.IncidentCandidate, "assessment_count": finding.AssessmentCount,
	}
	e.mutex.Lock()
	defer e.mutex.Unlock()
	alert := e.alerts[key]
	if alert != nil && !e.allowAlertOccurrenceLocked(alert) {
		return
	}
	created := false
	if alert == nil {
		alert = &Alert{ID: key, Type: alertType, FirstSeen: finding.FirstSeen, Status: AlertStatusNew}
		if alert.FirstSeen.IsZero() {
			alert.FirstSeen = now
		}
		e.alerts[key] = alert
		created = true
	}
	alert.Type = alertType
	alert.Severity = finding.Severity
	alert.Message = fmt.Sprintf("Network behavior finding on %s: score %.1f, %d correlated assessment(s)", finding.AssetID, finding.Score, finding.AssessmentCount)
	alert.IP = ip
	alert.Evidence = evidence
	alert.LastSeen = now
	alert.Count = finding.AssessmentCount
	if alert.Count == 0 {
		alert.Count = 1
	}
	alert.Synced = false
	if created {
		e.logNewAlert(alert)
	}
}
