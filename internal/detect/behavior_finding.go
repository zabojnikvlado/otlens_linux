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
	if e.behaviorDetectionsSuppressed() {
		return
	}
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
	evidence := map[string]interface{}{"finding_id": finding.ID, "risk_score": finding.Score, "confidence": finding.Confidence, "reasons": finding.Reasons, "peer_id": peer, "alert_candidate": finding.AlertCandidate, "incident_candidate": finding.IncidentCandidate, "assessment_count": finding.AssessmentCount}
	e.raiseBuiltinAlert(string(alertType), alertType, finding.Severity, "nba|"+finding.ID,
		fmt.Sprintf("Network behavior finding on %s: score %.1f, %d correlated assessment(s)", finding.AssetID, finding.Score, finding.AssessmentCount), ip, evidence, now, alertEpisodeGap)
}
