package syncagent

import (
	"context"
	"log"
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
	Snapshot        func() (management.TelemetrySnapshot, error)
	ApplyCommand    func(management.Command)
	ProcessAnalysis func(context.Context)
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

	h := management.Heartbeat{SensorID: w.Client.cfg.SensorID, Version: w.Client.cfg.Version, Hostname: w.Client.cfg.Hostname}
	if w.Uptime != nil {
		h.Uptime = w.Uptime()
	}
	if w.Health != nil {
		h.Health = w.Health()
	}
	if w.Metrics != nil {
		h.Metrics = w.Metrics()
	}
	if err := w.Client.Heartbeat(ctx, h); err != nil {
		log.Printf("OTLens Central heartbeat failed: %v", err)
	}

	if w.ProcessAnalysis != nil {
		w.ProcessAnalysis(ctx)
	}

	if w.Snapshot != nil {
		snapshot, err := w.Snapshot()
		if err != nil {
			log.Printf("OTLens telemetry snapshot failed: %v", err)
			return
		}
		snapshot.SensorID = w.Client.cfg.SensorID
		if snapshot.CapturedAt.IsZero() {
			snapshot.CapturedAt = time.Now().UTC()
		}
		if err := w.Client.PushTelemetry(ctx, snapshot); err != nil {
			log.Printf("OTLens telemetry upload failed: %v", err)
		}
	}
}
