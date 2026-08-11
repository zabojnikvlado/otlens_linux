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
	bus             *core.EventBus
	baseline        *behaviorbaseline.Engine
	config          Config
	mu              sync.RWMutex
	evaluator       *Evaluator
	anomalies       []Anomaly
	last            map[string]time.Time
	telemetry       Telemetry
	learningSkipped atomic.Uint64
	stop            chan struct{}
	stopOnce        sync.Once
	wg              sync.WaitGroup
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
	if e.baseline.Status(input.At).Mode != behaviorbaseline.ModeMonitoring {
		e.learningSkipped.Add(1)
		return
	}
	e.mu.Lock()
	e.telemetry.EvaluatedTotal++
	if e.evaluator == nil {
		e.evaluator = NewEvaluator(e.baseline.Snapshot(input.At))
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
	return nil
}
