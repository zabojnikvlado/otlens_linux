package nba

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/behaviorbaseline"
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/protocolobs"
)

type Config struct {
	Enabled      bool
	MinScore     float64
	MaxAnomalies int
	Cooldown     time.Duration
}

type Engine struct {
	bus               *core.EventBus
	baseline          *behaviorbaseline.Engine
	config            Config
	mu                sync.RWMutex
	evaluator         *Evaluator
	evaluatorRevision uint64
	evaluatorBuiltAt  time.Time
	previewEvaluator  *Evaluator
	previewBuiltAt    time.Time
	anomalies         []Anomaly
	last              map[string]time.Time
	telemetry         Telemetry
	learningSkipped   atomic.Uint64
	stop              chan struct{}
	stopOnce          sync.Once
	wg                sync.WaitGroup
}

func New(bus *core.EventBus, baseline *behaviorbaseline.Engine, config Config) *Engine {
	if config.MinScore <= 0 {
		config.MinScore = 40
	}
	if config.MaxAnomalies <= 0 {
		config.MaxAnomalies = 10000
	}
	if config.Cooldown <= 0 {
		config.Cooldown = 5 * time.Minute
	}
	return &Engine{bus: bus, baseline: baseline, config: config, last: make(map[string]time.Time), stop: make(chan struct{})}
}
func (e *Engine) Start() {
	if !e.config.Enabled || e.bus == nil || e.baseline == nil {
		return
	}
	packets := e.bus.Subscribe(core.EventPacketParsed)
	apps := e.bus.Subscribe(core.EventProtocolObservation)
	e.wg.Add(2)
	go e.consumePackets(packets)
	go e.consumeApps(apps)
}
func (e *Engine) Stop() { e.stopOnce.Do(func() { close(e.stop) }); e.wg.Wait() }
func (e *Engine) consumePackets(events <-chan core.Event) {
	defer e.wg.Done()
	for {
		select {
		case <-e.stop:
			return
		case event := <-events:
			p, ok := event.Data.(core.Packet)
			if !ok || p.SrcIP == "" || p.DstIP == "" {
				continue
			}
			src := "ip:" + p.SrcIP
			dst := "ip:" + p.DstIP
			if p.SrcMAC != "" {
				src = "mac:" + strings.ToLower(p.SrcMAC)
			}
			if p.DstMAC != "" {
				dst = "mac:" + strings.ToLower(p.DstMAC)
			}
			e.evaluate(Input{At: p.Timestamp, Key: e.baseline.NetworkKey(p), SrcAssetID: src, DstAssetID: dst, PacketBytes: uint64(max(p.Length, 0))})
		}
	}
}
func (e *Engine) consumeApps(events <-chan core.Event) {
	defer e.wg.Done()
	for {
		select {
		case <-e.stop:
			return
		case event := <-events:
			o, ok := event.Data.(protocolobs.Observation)
			if !ok || o.SrcIP == "" || o.DstIP == "" {
				continue
			}
			e.evaluate(Input{At: o.Timestamp, Key: e.baseline.ApplicationKey(o), RTTMillis: o.RTTMillis})
		}
	}
}
func (e *Engine) evaluate(input Input) {
	if input.At.IsZero() {
		input.At = time.Now().UTC()
	}
	status := e.baseline.Status(input.At)
	if status.Mode != behaviorbaseline.ModeMonitoring {
		e.learningSkipped.Add(1)
		e.evaluatePreview(input)
		return
	}

	// A newly-seen asset after global learning gets its own candidate/grace
	// phase. The explicit new_asset detector can still notify the operator, but
	// NBA does not pile behavior findings onto an asset that has not accumulated
	// enough observations to be statistically meaningful yet.
	trusted := false
	if input.SrcAssetID != "" {
		trusted = e.baseline.IsTrustedAsset(input.SrcAssetID, input.At)
	} else {
		trusted = e.baseline.IsTrustedIP(input.Key.SensorID, input.Key.SrcIP, input.At)
	}
	if !trusted {
		e.mu.Lock()
		e.telemetry.CandidateGraceSkipped++
		e.mu.Unlock()
		return
	}

	e.mu.Lock()
	e.telemetry.EvaluatedTotal++
	revision := e.baseline.Revision()
	if e.evaluator == nil || e.evaluatorRevision != revision || input.At.Sub(e.evaluatorBuiltAt) >= time.Minute {
		e.evaluator = NewEvaluator(e.baseline.Snapshot(input.At))
		e.evaluatorRevision = revision
		e.evaluatorBuiltAt = input.At
	}
	anomaly := e.evaluator.Evaluate(input)
	if anomaly == nil || anomaly.Score < e.config.MinScore {
		e.telemetry.BelowThresholdTotal++
		e.mu.Unlock()
		return
	}
	if last := e.last[anomaly.ID]; !last.IsZero() && input.At.Sub(last) < e.config.Cooldown {
		e.telemetry.DeduplicatedTotal++
		e.mu.Unlock()
		return
	}
	e.last[anomaly.ID] = input.At
	e.anomalies = append(e.anomalies, *anomaly)
	previousTotal := e.telemetry.AnomaliesTotal
	e.telemetry.AnomaliesTotal++
	e.telemetry.AverageAnomalyScore = (e.telemetry.AverageAnomalyScore*float64(previousTotal) + anomaly.Score) / float64(e.telemetry.AnomaliesTotal)
	if len(e.anomalies) > e.config.MaxAnomalies {
		e.anomalies = append([]Anomaly(nil), e.anomalies[len(e.anomalies)-e.config.MaxAnomalies:]...)
	}
	e.mu.Unlock()
	e.bus.Publish(core.Event{Type: core.EventBehaviorAnomaly, Timestamp: input.At, Data: *anomaly})
}

// evaluatePreview implements "what would alert now?" during learning without
// publishing any finding. A snapshot is held for 30 seconds so new observations
// are evaluated against the recent learned state rather than immediately
// teaching themselves into the model before they can be previewed.
func (e *Engine) evaluatePreview(input Input) {
	e.mu.Lock()
	if e.previewEvaluator == nil || e.previewBuiltAt.IsZero() || input.At.Sub(e.previewBuiltAt) >= 30*time.Second {
		e.previewEvaluator = NewEvaluator(e.baseline.Snapshot(input.At))
		e.previewBuiltAt = input.At
		e.mu.Unlock()
		return
	}
	e.telemetry.PreviewEvaluatedTotal++
	anomaly := e.previewEvaluator.Evaluate(input)
	if anomaly != nil && anomaly.Score >= e.config.MinScore {
		e.telemetry.PreviewAnomaliesTotal++
		if anomaly.Score > e.telemetry.PreviewTopScore {
			e.telemetry.PreviewTopScore = anomaly.Score
			if len(anomaly.Reasons) > 0 {
				e.telemetry.PreviewTopReason = anomaly.Reasons[0].Message
			}
		}
	}
	e.mu.Unlock()
}

func (e *Engine) GetAnomalies() []Anomaly {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Anomaly, len(e.anomalies))
	for index, anomaly := range e.anomalies {
		out[index] = cloneAnomaly(anomaly)
	}
	return out
}

// Reset clears all anomaly/evaluator state derived from the previous baseline.
func (e *Engine) Reset() {
	e.mu.Lock()
	e.evaluator = nil
	e.evaluatorRevision = 0
	e.evaluatorBuiltAt = time.Time{}
	e.previewEvaluator = nil
	e.previewBuiltAt = time.Time{}
	e.anomalies = nil
	e.last = make(map[string]time.Time)
	e.telemetry = Telemetry{}
	e.mu.Unlock()
	e.learningSkipped.Store(0)
}

func (e *Engine) Telemetry() Telemetry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := e.telemetry
	result.LearningSkippedTotal = e.learningSkipped.Load()
	result.ActiveAnomalies = len(e.anomalies)
	return result
}

func (e *Engine) Snapshot() Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	anomalies := make([]Anomaly, len(e.anomalies))
	for index, anomaly := range e.anomalies {
		anomalies[index] = cloneAnomaly(anomaly)
	}
	last := make(map[string]time.Time, len(e.last))
	for key, value := range e.last {
		last[key] = value
	}
	telemetry := e.telemetry
	telemetry.LearningSkippedTotal = e.learningSkipped.Load()
	telemetry.ActiveAnomalies = len(anomalies)
	return Snapshot{Version: 1, Anomalies: anomalies, Last: last, Telemetry: telemetry}
}

func (e *Engine) Restore(snapshot Snapshot) error {
	if snapshot.Version > 1 {
		return fmt.Errorf("unsupported NBA snapshot version %d", snapshot.Version)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(snapshot.Anomalies) > e.config.MaxAnomalies {
		snapshot.Anomalies = snapshot.Anomalies[len(snapshot.Anomalies)-e.config.MaxAnomalies:]
	}
	e.anomalies = make([]Anomaly, len(snapshot.Anomalies))
	for index, anomaly := range snapshot.Anomalies {
		e.anomalies[index] = cloneAnomaly(anomaly)
	}
	e.last = make(map[string]time.Time, len(snapshot.Last))
	for key, value := range snapshot.Last {
		e.last[key] = value
	}
	e.telemetry = snapshot.Telemetry
	e.learningSkipped.Store(snapshot.Telemetry.LearningSkippedTotal)
	e.telemetry.ActiveAnomalies = len(e.anomalies)
	e.evaluator = nil
	e.evaluatorRevision = 0
	e.evaluatorBuiltAt = time.Time{}
	e.previewEvaluator = nil
	e.previewBuiltAt = time.Time{}
	return nil
}
