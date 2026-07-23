package syncagent

import (
	"context"
	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"time"
)

type Worker struct {
	Client  *Client
	Detect  *detect.Engine
	Uptime  func() int64
	Health  func() map[string]string
	Metrics func() map[string]interface{}
}

func (w *Worker) Run(ctx context.Context) {
	_ = w.Client.Register(ctx)
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
	_ = w.Client.PullRules(ctx, w.Detect.ReplaceManagedRules)
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
	_ = w.Client.Heartbeat(ctx, h)
}
