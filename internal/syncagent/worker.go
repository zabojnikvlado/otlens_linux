package syncagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

type Worker struct {
	Client          *Client
	Detect          *detect.Engine
	Uptime          func() int64
	Health          func() map[string]string
	Metrics         func() map[string]interface{}
	Versions        func() map[string]string
	CaptureInfo     func() map[string]interface{}
	Snapshot        func() (management.TelemetrySnapshot, error)
	ApplyCommand    func(management.Command)
	ProcessAnalysis func(context.Context)

	mu              sync.Mutex
	lastAttempt     time.Time
	lastSuccess     time.Time
	lastDataSent    time.Time
	lastError       string
	failures        int
	sequence        int64
	pending         int64
	analysisMu      sync.Mutex
	analysisRunning bool
}

func (w *Worker) syncHealth() management.SyncHealth {
	w.mu.Lock()
	defer w.mu.Unlock()
	return management.SyncHealth{LastAttemptAt: w.lastAttempt, LastSuccessAt: w.lastSuccess, LastDataSentAt: w.lastDataSent, PendingRecords: w.pending, ConsecutiveFailures: w.failures, LastError: w.lastError, Sequence: w.sequence}
}

func (w *Worker) markAttempt() { w.mu.Lock(); w.lastAttempt = time.Now().UTC(); w.mu.Unlock() }
func (w *Worker) markFailure(err error) {
	w.mu.Lock()
	w.failures++
	w.lastError = err.Error()
	w.mu.Unlock()
}
func (w *Worker) markSuccess(sequence int64) {
	w.mu.Lock()
	w.failures = 0
	w.lastError = ""
	w.lastSuccess = time.Now().UTC()
	w.lastDataSent = w.lastSuccess
	w.sequence = sequence
	w.pending = 0
	w.mu.Unlock()
}

func (w *Worker) Run(ctx context.Context) {
	// Registration is retried on every synchronization cycle. This makes the
	// sensor recover automatically when Central or PostgreSQL was unavailable
	// during the first startup attempt.
	ticker := time.NewTicker(w.Client.cfg.Interval)
	defer ticker.Stop()

	w.sync(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sync(ctx)
		}
	}
}

func (w *Worker) sync(ctx context.Context) {
	if err := w.Client.Register(ctx); err != nil {
		log.Printf("OTLens Central registration failed: %v", err)
		return
	}

	commands, err := w.Client.PullRules(ctx, func(rules []*detect.Rule) error { w.Detect.ReplaceManagedRules(rules); return nil })
	if err != nil {
		log.Printf("OTLens Central rule synchronization failed: %v", err)
	} else if w.ApplyCommand != nil {
		for _, command := range commands {
			w.ApplyCommand(command)
		}
	}

	h := management.Heartbeat{SensorID: w.Client.cfg.SensorID, Version: w.Client.cfg.Version, Hostname: w.Client.cfg.Hostname, Sync: w.syncHealth()}
	if w.Uptime != nil {
		h.Uptime = w.Uptime()
	}
	if w.Health != nil {
		h.Health = w.Health()
	}
	if w.Metrics != nil {
		h.Metrics = w.Metrics()
	}
	if w.Versions != nil {
		h.Versions = w.Versions()
	}
	if w.CaptureInfo != nil {
		h.Capture = w.CaptureInfo()
	}
	if err := w.Client.Heartbeat(ctx, h); err != nil {
		log.Printf("OTLens Central heartbeat failed: %v", err)
	}

	if w.Snapshot != nil {
		snapshot, err := w.Snapshot()
		if err != nil {
			w.markFailure(err)
			log.Printf("OTLens telemetry snapshot failed: %v", err)
			return
		}
		snapshot.SensorID = w.Client.cfg.SensorID
		if snapshot.CapturedAt.IsZero() {
			snapshot.CapturedAt = time.Now().UTC()
		}
		w.mu.Lock()
		nextSequence := w.sequence + 1
		if nowSequence := time.Now().UTC().UnixNano(); nowSequence > nextSequence {
			nextSequence = nowSequence
		}
		w.pending = 1
		w.mu.Unlock()
		snapshot.Sequence = nextSequence
		snapshot.BatchID = fmt.Sprintf("%s-%d", w.Client.cfg.SensorID, nextSequence)
		checksumInput := snapshot
		checksumInput.Checksum = ""
		payload, _ := json.Marshal(checksumInput)
		sum := sha256.Sum256(payload)
		snapshot.Checksum = hex.EncodeToString(sum[:])

		var uploadErr error
		for attempt := 1; attempt <= 3; attempt++ {
			w.markAttempt()
			requestCtx, cancel := context.WithTimeout(ctx, w.Client.cfg.Timeout)
			_, uploadErr = w.Client.PushTelemetry(requestCtx, snapshot)
			cancel()
			if uploadErr == nil {
				w.markSuccess(nextSequence)
				break
			}
			w.markFailure(uploadErr)
			if attempt < 3 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(attempt) * 2 * time.Second):
				}
			}
		}
		if uploadErr != nil {
			log.Printf("OTLens telemetry upload failed after retries: %v", uploadErr)
		}
	}

	// PCAP analysis can take minutes. It must never block heartbeat and telemetry
	// delivery, therefore only one analysis poll/run is allowed asynchronously.
	if w.ProcessAnalysis != nil {
		w.analysisMu.Lock()
		if !w.analysisRunning {
			w.analysisRunning = true
			go func() {
				defer func() { w.analysisMu.Lock(); w.analysisRunning = false; w.analysisMu.Unlock() }()
				w.ProcessAnalysis(ctx)
			}()
		}
		w.analysisMu.Unlock()
	}
}
