package nba

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

type RiskContext struct {
	AssetCriticality    float64
	PurdueLevel         *int
	Honeypot            bool
	ExternalDestination bool
	InterVLAN           bool
	MaintenanceWindow   bool
	ApprovedPeer        bool
}

type RiskFactor struct {
	Kind       string  `json:"kind"`
	Multiplier float64 `json:"multiplier"`
	Reason     string  `json:"reason"`
}

type RiskAssessment struct {
	AnomalyID      string       `json:"anomaly_id"`
	Timestamp      time.Time    `json:"timestamp"`
	SensorID       string       `json:"sensor_id"`
	AssetID        string       `json:"asset_id"`
	AnomalyScore   float64      `json:"anomaly_score"`
	RiskMultiplier float64      `json:"risk_multiplier"`
	RiskScore      float64      `json:"risk_score"`
	Factors        []RiskFactor `json:"factors"`
	Anomaly        Anomaly      `json:"anomaly"`
}

type RiskTelemetry struct {
	AssessmentsTotal  uint64  `json:"assessments_total"`
	ActiveAssessments int     `json:"active_assessments"`
	ElevatedTotal     uint64  `json:"elevated_total"`
	ReducedTotal      uint64  `json:"reduced_total"`
	AverageRiskScore  float64 `json:"average_risk_score"`
	AverageMultiplier float64 `json:"average_multiplier"`
}

type RiskSnapshot struct {
	Version   uint32           `json:"version"`
	Items     []RiskAssessment `json:"items"`
	Telemetry RiskTelemetry    `json:"telemetry"`
}

type RiskResolver func(Anomaly) RiskContext

type RiskConfig struct {
	Enabled        bool
	MaxAssessments int
}

type RiskEngine struct {
	bus       *core.EventBus
	resolver  RiskResolver
	config    RiskConfig
	mu        sync.RWMutex
	items     []RiskAssessment
	telemetry RiskTelemetry
	stop      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

func NewRiskEngine(bus *core.EventBus, resolver RiskResolver, config RiskConfig) *RiskEngine {
	if config.MaxAssessments <= 0 {
		config.MaxAssessments = 10_000
	}
	return &RiskEngine{bus: bus, resolver: resolver, config: config, stop: make(chan struct{})}
}

func (e *RiskEngine) Start() {
	if !e.config.Enabled || e.bus == nil {
		return
	}
	events := e.bus.Subscribe(core.EventBehaviorAnomaly)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			select {
			case <-e.stop:
				return
			case event := <-events:
				anomaly, ok := event.Data.(Anomaly)
				if !ok {
					continue
				}
				context := RiskContext{}
				if e.resolver != nil {
					context = e.resolver(anomaly)
				}
				assessment := AssessRisk(anomaly, context)
				e.mu.Lock()
				e.items = append(e.items, assessment)
				previousTotal := e.telemetry.AssessmentsTotal
				e.telemetry.AssessmentsTotal++
				e.telemetry.AverageRiskScore = (e.telemetry.AverageRiskScore*float64(previousTotal) + assessment.RiskScore) / float64(e.telemetry.AssessmentsTotal)
				e.telemetry.AverageMultiplier = (e.telemetry.AverageMultiplier*float64(previousTotal) + assessment.RiskMultiplier) / float64(e.telemetry.AssessmentsTotal)
				if assessment.RiskMultiplier > 1 {
					e.telemetry.ElevatedTotal++
				} else if assessment.RiskMultiplier < 1 {
					e.telemetry.ReducedTotal++
				}
				if len(e.items) > e.config.MaxAssessments {
					e.items = append([]RiskAssessment(nil), e.items[len(e.items)-e.config.MaxAssessments:]...)
				}
				e.mu.Unlock()
				e.bus.Publish(core.Event{Type: core.EventBehaviorRisk, Timestamp: assessment.Timestamp, Data: assessment})
			}
		}
	}()
}

func (e *RiskEngine) Stop() {
	e.stopOnce.Do(func() { close(e.stop) })
	e.wg.Wait()
}

func (e *RiskEngine) GetAssessments() []RiskAssessment {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]RiskAssessment, len(e.items))
	for index, item := range e.items {
		result[index] = cloneRiskAssessment(item)
	}
	return result
}

func (e *RiskEngine) Telemetry() RiskTelemetry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := e.telemetry
	result.ActiveAssessments = len(e.items)
	return result
}

func (e *RiskEngine) Snapshot() RiskSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	items := make([]RiskAssessment, len(e.items))
	for index, item := range e.items {
		items[index] = cloneRiskAssessment(item)
	}
	telemetry := e.telemetry
	telemetry.ActiveAssessments = len(items)
	return RiskSnapshot{Version: 1, Items: items, Telemetry: telemetry}
}

func (e *RiskEngine) Restore(snapshot RiskSnapshot) error {
	if snapshot.Version > 1 {
		return fmt.Errorf("unsupported risk snapshot version %d", snapshot.Version)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(snapshot.Items) > e.config.MaxAssessments {
		snapshot.Items = snapshot.Items[len(snapshot.Items)-e.config.MaxAssessments:]
	}
	e.items = make([]RiskAssessment, len(snapshot.Items))
	for index, item := range snapshot.Items {
		e.items[index] = cloneRiskAssessment(item)
	}
	e.telemetry = snapshot.Telemetry
	e.telemetry.ActiveAssessments = len(e.items)
	return nil
}

func cloneRiskAssessment(value RiskAssessment) RiskAssessment {
	value.Factors = append([]RiskFactor(nil), value.Factors...)
	value.Anomaly = cloneAnomaly(value.Anomaly)
	return value
}

func AssessRisk(anomaly Anomaly, context RiskContext) RiskAssessment {
	factors := make([]RiskFactor, 0, 8)
	add := func(kind string, multiplier float64, reason string) {
		factors = append(factors, RiskFactor{Kind: kind, Multiplier: multiplier, Reason: reason})
	}
	criticality := math.Max(0, math.Min(100, context.AssetCriticality))
	if criticality > 0 {
		add("asset_criticality", 1+criticality/200, "Anomaly affects a critical asset")
	}
	if context.PurdueLevel != nil {
		switch *context.PurdueLevel {
		case 0:
			add("purdue_level", 1.30, "Asset is in Purdue level 0")
		case 1:
			add("purdue_level", 1.25, "Asset is in Purdue level 1")
		case 2:
			add("purdue_level", 1.15, "Asset is in Purdue level 2")
		}
	}
	if context.Honeypot {
		add("honeypot", 1.50, "Communication involves a honeypot")
	}
	if context.ExternalDestination {
		add("external_destination", 1.20, "Destination is outside private network ranges")
	}
	if context.InterVLAN {
		add("inter_vlan", 1.10, "Communication crosses VLAN boundaries")
	}
	if anomaly.Confidence < .25 {
		add("low_baseline_confidence", .70, "Baseline has limited supporting samples")
	}
	if context.MaintenanceWindow {
		add("maintenance_window", .30, "Activity occurs in an approved maintenance window")
	}
	if context.ApprovedPeer {
		add("approved_peer", .50, "Peer is explicitly approved")
	}
	multiplier := 1.0
	for _, factor := range factors {
		multiplier *= factor.Multiplier
	}
	multiplier = math.Max(.10, math.Min(3, multiplier))
	score := math.Max(0, math.Min(100, anomaly.Score*multiplier))
	return RiskAssessment{AnomalyID: anomaly.ID, Timestamp: anomaly.Timestamp, SensorID: anomaly.SensorID, AssetID: anomaly.AssetID, AnomalyScore: anomaly.Score, RiskMultiplier: multiplier, RiskScore: score, Factors: factors, Anomaly: anomaly}
}
