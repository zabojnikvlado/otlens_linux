package nba

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

type FindingState string

const (
	FindingOpen    FindingState = "open"
	FindingUpdated FindingState = "updated"
	FindingExpired FindingState = "expired"
)

type Finding struct {
	ID                string           `json:"id"`
	SensorID          string           `json:"sensor_id"`
	AssetID           string           `json:"asset_id"`
	PeerID            string           `json:"peer_id,omitempty"`
	FirstSeen         time.Time        `json:"first_seen"`
	LastSeen          time.Time        `json:"last_seen"`
	ExpiresAt         time.Time        `json:"expires_at"`
	Score             float64          `json:"score"`
	Confidence        float64          `json:"confidence"`
	Severity          string           `json:"severity"`
	State             FindingState     `json:"state"`
	AlertCandidate    bool             `json:"alert_candidate"`
	IncidentCandidate bool             `json:"incident_candidate"`
	AssessmentCount   uint64           `json:"assessment_count"`
	AnomalyIDs        []string         `json:"anomaly_ids"`
	Reasons           []string         `json:"reasons"`
	Assessments       []RiskAssessment `json:"assessments"`
}

type CorrelationTelemetry struct {
	AssessmentsTotal    uint64  `json:"assessments_total"`
	FindingsCreated     uint64  `json:"findings_created_total"`
	FindingsUpdated     uint64  `json:"findings_updated_total"`
	FindingsExpired     uint64  `json:"findings_expired_total"`
	Deduplicated        uint64  `json:"deduplicated_total"`
	ActiveFindings      int     `json:"active_findings"`
	AlertCandidates     uint64  `json:"alert_candidates_total"`
	IncidentCandidates  uint64  `json:"incident_candidates_total"`
	AverageFindingScore float64 `json:"average_finding_score"`
}

type CorrelationSnapshot struct {
	Version   uint32               `json:"version"`
	Findings  []Finding            `json:"findings"`
	Telemetry CorrelationTelemetry `json:"telemetry"`
}

type CorrelationConfig struct {
	Enabled                  bool
	Window                   time.Duration
	ExpireAfter              time.Duration
	MaxFindings              int
	MaxAssessmentsPerFinding int
	MinFindingScore          float64
	AlertThreshold           float64
	IncidentThreshold        float64
}

type CorrelationEngine struct {
	bus       *core.EventBus
	config    CorrelationConfig
	mu        sync.RWMutex
	findings  map[string]*Finding
	order     []string
	telemetry CorrelationTelemetry
	stop      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

func NewCorrelationEngine(bus *core.EventBus, config CorrelationConfig) *CorrelationEngine {
	if config.Window <= 0 {
		config.Window = 15 * time.Minute
	}
	if config.ExpireAfter <= 0 {
		config.ExpireAfter = 30 * time.Minute
	}
	if config.MaxFindings <= 0 {
		config.MaxFindings = 10000
	}
	if config.MaxAssessmentsPerFinding <= 0 {
		config.MaxAssessmentsPerFinding = 256
	}
	if config.MinFindingScore <= 0 {
		config.MinFindingScore = 40
	}
	if config.AlertThreshold <= 0 {
		config.AlertThreshold = 70
	}
	if config.IncidentThreshold <= 0 {
		config.IncidentThreshold = 85
	}
	return &CorrelationEngine{bus: bus, config: config, findings: make(map[string]*Finding), stop: make(chan struct{})}
}

func (e *CorrelationEngine) Start() {
	if !e.config.Enabled || e.bus == nil {
		return
	}
	events := e.bus.Subscribe(core.EventBehaviorRisk)
	interval := min(e.config.ExpireAfter/2, time.Minute)
	if interval <= 0 {
		interval = time.Second
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-e.stop:
				return
			case event := <-events:
				if assessment, ok := event.Data.(RiskAssessment); ok {
					e.Observe(assessment)
				}
			case now := <-ticker.C:
				e.Expire(now)
			}
		}
	}()
}
func (e *CorrelationEngine) Stop() { e.stopOnce.Do(func() { close(e.stop) }); e.wg.Wait() }

func (e *CorrelationEngine) Observe(assessment RiskAssessment) *Finding {
	if assessment.Timestamp.IsZero() {
		assessment.Timestamp = time.Now().UTC()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.telemetry.AssessmentsTotal++
	id := findingID(assessment)
	finding := e.findings[id]
	if finding != nil && (finding.State == FindingExpired || assessment.Timestamp.Sub(finding.LastSeen) > e.config.Window) {
		id = fmt.Sprintf("%s|%d", id, assessment.Timestamp.UnixNano())
		finding = nil
	}
	if finding != nil {
		for _, anomalyID := range finding.AnomalyIDs {
			if anomalyID == assessment.AnomalyID {
				e.telemetry.Deduplicated++
				return nil
			}
		}
	}
	if finding == nil {
		if assessment.RiskScore < e.config.MinFindingScore {
			return nil
		}
		finding = &Finding{ID: id, SensorID: assessment.SensorID, AssetID: assessment.AssetID, PeerID: assessment.Anomaly.PeerID, FirstSeen: assessment.Timestamp, State: FindingOpen}
		e.findings[id] = finding
		e.order = append(e.order, id)
		e.telemetry.FindingsCreated++
		if len(e.order) > e.config.MaxFindings {
			oldest := e.order[0]
			e.order = e.order[1:]
			delete(e.findings, oldest)
		}
	} else {
		finding.State = FindingUpdated
		e.telemetry.FindingsUpdated++
	}
	previousAlert, previousIncident := finding.AlertCandidate, finding.IncidentCandidate
	finding.LastSeen = assessment.Timestamp
	finding.ExpiresAt = assessment.Timestamp.Add(e.config.ExpireAfter)
	finding.AssessmentCount++
	finding.AnomalyIDs = append(finding.AnomalyIDs, assessment.AnomalyID)
	finding.Assessments = append(finding.Assessments, assessment)
	if len(finding.Assessments) > e.config.MaxAssessmentsPerFinding {
		finding.Assessments = append([]RiskAssessment(nil), finding.Assessments[len(finding.Assessments)-e.config.MaxAssessmentsPerFinding:]...)
	}
	finding.Score = combineScores(finding.Assessments)
	finding.Confidence = combineConfidence(finding.Assessments)
	finding.Reasons = correlationReasons(finding.Assessments)
	finding.Severity = severityFor(finding.Score)
	finding.AlertCandidate = finding.Score >= e.config.AlertThreshold
	finding.IncidentCandidate = finding.Score >= e.config.IncidentThreshold
	if finding.AlertCandidate && !previousAlert {
		e.telemetry.AlertCandidates++
	}
	if finding.IncidentCandidate && !previousIncident {
		e.telemetry.IncidentCandidates++
	}
	total := e.telemetry.FindingsCreated + e.telemetry.FindingsUpdated
	e.telemetry.AverageFindingScore = (e.telemetry.AverageFindingScore*float64(total-1) + finding.Score) / float64(total)
	result := cloneFinding(finding)
	if e.bus != nil {
		e.bus.Publish(core.Event{Type: core.EventBehaviorFinding, Timestamp: assessment.Timestamp, Data: result})
	}
	return &result
}

func (e *CorrelationEngine) Expire(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	count := 0
	for _, finding := range e.findings {
		if finding.State != FindingExpired && !finding.ExpiresAt.After(now) {
			finding.State = FindingExpired
			count++
			e.telemetry.FindingsExpired++
			if e.bus != nil {
				copyFinding := cloneFinding(finding)
				e.bus.Publish(core.Event{Type: core.EventBehaviorFinding, Timestamp: now, Data: copyFinding})
			}
		}
	}
	return count
}
func (e *CorrelationEngine) GetFindings(includeExpired bool) []Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Finding, 0, len(e.findings))
	for _, id := range e.order {
		if finding := e.findings[id]; finding != nil && (includeExpired || finding.State != FindingExpired) {
			out = append(out, cloneFinding(finding))
		}
	}
	return out
}
func (e *CorrelationEngine) Telemetry() CorrelationTelemetry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := e.telemetry
	for _, finding := range e.findings {
		if finding.State != FindingExpired {
			result.ActiveFindings++
		}
	}
	return result
}
func (e *CorrelationEngine) Snapshot() CorrelationSnapshot {
	return CorrelationSnapshot{Version: 1, Findings: e.GetFindings(true), Telemetry: e.Telemetry()}
}
func (e *CorrelationEngine) Restore(snapshot CorrelationSnapshot) error {
	if snapshot.Version > 1 {
		return fmt.Errorf("unsupported correlation snapshot version %d", snapshot.Version)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(snapshot.Findings) > e.config.MaxFindings {
		snapshot.Findings = snapshot.Findings[len(snapshot.Findings)-e.config.MaxFindings:]
	}
	e.findings = make(map[string]*Finding, len(snapshot.Findings))
	e.order = e.order[:0]
	for _, finding := range snapshot.Findings {
		copyFinding := cloneFinding(&finding)
		e.findings[finding.ID] = &copyFinding
		e.order = append(e.order, finding.ID)
	}
	e.telemetry = snapshot.Telemetry
	e.telemetry.ActiveFindings = 0
	return nil
}

func findingID(a RiskAssessment) string {
	peer := a.Anomaly.PeerID
	if peer == "" {
		peer = "*"
	}
	return a.SensorID + "|" + a.AssetID + "|" + peer
}
func combineScores(items []RiskAssessment) float64 {
	remaining := 1.0
	for _, item := range items {
		remaining *= 1 - math.Max(0, math.Min(100, item.RiskScore))/100
	}
	return 100 * (1 - remaining)
}
func combineConfidence(items []RiskAssessment) float64 {
	remaining := 1.0
	for _, item := range items {
		remaining *= 1 - math.Max(0, math.Min(1, item.Anomaly.Confidence))
	}
	return 1 - remaining
}
func severityFor(score float64) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}
func correlationReasons(items []RiskAssessment) []string {
	set := map[string]struct{}{}
	for _, item := range items {
		for _, reason := range item.Anomaly.Reasons {
			set[string(reason.Kind)] = struct{}{}
		}
		for _, factor := range item.Factors {
			set[factor.Kind] = struct{}{}
		}
	}
	if has(set, string(KindNewPeer)) && has(set, string(KindNewProtocol)) {
		set["correlation:new_peer_and_protocol"] = struct{}{}
	}
	if has(set, string(KindNewPeer)) && has(set, "external_destination") {
		set["correlation:new_external_peer"] = struct{}{}
	}
	if has(set, string(KindUnusualTime)) && has(set, string(KindNewPort)) {
		set["correlation:unusual_time_and_port"] = struct{}{}
	}
	if has(set, string(KindDirection)) && (has(set, "asset_criticality") || has(set, "honeypot")) {
		set["correlation:risky_direction_change"] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
func has(values map[string]struct{}, key string) bool { _, ok := values[key]; return ok }
func cloneFinding(finding *Finding) Finding {
	result := *finding
	result.AnomalyIDs = append([]string(nil), finding.AnomalyIDs...)
	result.Reasons = append([]string(nil), finding.Reasons...)
	result.Assessments = make([]RiskAssessment, len(finding.Assessments))
	for index, assessment := range finding.Assessments {
		result.Assessments[index] = cloneRiskAssessment(assessment)
	}
	return result
}
