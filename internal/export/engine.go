// Package export forwards data to an external server as JSON over
// HTTPS, as it happens — plus a one-time backfill of whatever alerts
// already existed at startup, so enabling this doesn't miss findings
// from before it was turned on. Entirely optional (export.enabled in
// config.yaml) and decoupled from the rest of OTLens the same way
// every other engine is: it only knows about core.EventAlertRaised
// and core.EventAuditAction, not about internal/detect's or
// internal/audit's internals.
//
// Two kinds of data go to the same configured URL, distinguished by
// payload.Kind: alerts (detection findings) and audit entries (who
// did what through the API). They're different enough in nature that
// keeping them as separate types made more sense than forcing one
// shared shape, but sending both to one endpoint avoids needing two
// separate URL/TLS configurations for what's operationally the same
// "forward this to my SIEM" need.
package export

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/zabojnikvlado/otlens/internal/core"
	"github.com/zabojnikvlado/otlens/internal/detect"
	"github.com/zabojnikvlado/otlens/internal/logger"
	"go.uber.org/zap"
)

// Config bundles every setting Engine needs — mirrors config.Export
// in internal/config, kept as a separate struct here (rather than
// this package importing internal/config directly) for the same
// reason api.Config exists: a constructor with a growing list of
// same-typed positional parameters is error-prone to call correctly.
type Config struct {
	URL string

	// InsecureSkipVerify disables TLS certificate validation for the
	// export server — only meant for a self-signed/internal server
	// during setup or testing. Leave false for anything that matters;
	// prefer CACertFile (trust one specific CA) over this (trust
	// anything) whenever the export server's certificate isn't from a
	// public CA.
	InsecureSkipVerify bool

	// CACertFile, if set, is a PEM-encoded CA certificate to trust
	// for the export server, in addition to the system's normal CA
	// pool — for an internal server whose certificate chains to a
	// private/internal CA rather than a public one.
	CACertFile string

	// Timeout bounds each individual export HTTP request.
	Timeout time.Duration
}

// Engine POSTs each alert/audit entry it's told about to Config.URL
// as JSON.
type Engine struct {
	cfg    Config
	client *http.Client
}

// New builds an Engine, including the http.Client's TLS
// configuration. Returns an error if CACertFile is set but can't be
// read/parsed — better to fail loudly at startup than silently never
// trust the certificate the operator configured.
func New(cfg Config) (*Engine, error) {

	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	if cfg.CACertFile != "" {

		pem, err := os.ReadFile(cfg.CACertFile)

		if err != nil {
			return nil, fmt.Errorf("reading export.tls.cacertfile %q failed: %w", cfg.CACertFile, err)
		}

		pool := x509.NewCertPool()

		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("export.tls.cacertfile %q contains no usable PEM certificate", cfg.CACertFile)
		}

		tlsConfig.RootCAs = pool
	}

	return &Engine{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}, nil
}

// payload is the JSON envelope actually POSTed — a bare Alert/
// AuditEntry on its own doesn't say where it came from, when it was
// sent, or which of the two kinds it is, all of which matter once a
// receiving server is aggregating data from more than one OTLens
// instance. Exactly one of Alert/Audit is set, per Kind.
type payload struct {
	Source     string    `json:"source"`
	Kind       string    `json:"kind"` // "alert" or "audit"
	ExportedAt time.Time `json:"exported_at"`

	Alert *detect.Alert    `json:"alert,omitempty"`
	Audit *core.AuditEntry `json:"audit,omitempty"`
}

// Start begins forwarding. existingAlerts is exported once
// immediately (in arrival order — oldest FirstSeen first — so a
// receiving server building its own timeline sees them in the order
// they actually happened), covering whatever was already raised
// before export got enabled; every alert raised afterward is
// exported as core.EventAlertRaised delivers it, and every audit
// entry as core.EventAuditAction delivers it (no backfill for audit
// entries — internal/audit's rotated file, not this, is the durable
// historical record; export only ever forwards what happens from
// here on).
func (e *Engine) Start(bus *core.EventBus, existingAlerts []*detect.Alert) {

	logger.Log.Info(
		"Export started",
		zap.String("url", e.cfg.URL),
		zap.Int("alert_backfill_count", len(existingAlerts)),
	)

	go func() {

		sorted := make([]*detect.Alert, len(existingAlerts))
		copy(sorted, existingAlerts)

		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].FirstSeen.Before(sorted[j].FirstSeen)
		})

		for _, alert := range sorted {
			e.exportAlert(alert)
		}
	}()

	alertCh := bus.Subscribe(core.EventAlertRaised)

	go func() {

		for event := range alertCh {

			alert, ok := event.Data.(*detect.Alert)

			if !ok {
				continue
			}

			e.exportAlert(alert)
		}

	}()

	auditCh := bus.Subscribe(core.EventAuditAction)

	go func() {

		for event := range auditCh {

			entry, ok := event.Data.(core.AuditEntry)

			if !ok {
				continue
			}

			e.exportAudit(&entry)
		}

	}()

}

func (e *Engine) exportAlert(alert *detect.Alert) {

	e.post(
		payload{
			Source:     "otlens",
			Kind:       "alert",
			ExportedAt: time.Now(),
			Alert:      alert,
		},
		alert.ID,
	)
}

func (e *Engine) exportAudit(entry *core.AuditEntry) {

	e.post(
		payload{
			Source:     "otlens",
			Kind:       "audit",
			ExportedAt: time.Now(),
			Audit:      entry,
		},
		entry.Action,
	)
}

// post sends one payload. Best-effort: a failure is logged and
// otherwise dropped rather than queued/retried — building a durable
// retry queue (its own persistence, backpressure, ordering
// guarantees) is a meaningfully bigger feature than what was asked
// for here. If the export server is down for a while, whatever
// alerts/audit entries happened during that window are simply not
// sent to it; nothing about local alerting/storage/the audit log
// file is affected either way, since export only ever reads from
// data the rest of the system already created and kept regardless.
//
// logRef is just an identifier for the warning logs below (an alert
// ID or an audit action name) — not part of the payload itself.
func (e *Engine) post(p payload, logRef string) {

	body, err := json.Marshal(p)

	if err != nil {

		logger.Log.Warn(
			"Marshaling export payload failed",
			zap.String("kind", p.Kind),
			zap.String("ref", logRef),
			zap.Error(err),
		)

		return
	}

	req, err := http.NewRequest(http.MethodPost, e.cfg.URL, bytes.NewReader(body))

	if err != nil {

		logger.Log.Warn(
			"Building export request failed",
			zap.String("kind", p.Kind),
			zap.String("ref", logRef),
			zap.Error(err),
		)

		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)

	if err != nil {

		logger.Log.Warn(
			"Export failed",
			zap.String("kind", p.Kind),
			zap.String("ref", logRef),
			zap.String("url", e.cfg.URL),
			zap.Error(err),
		)

		return
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 300 {

		logger.Log.Warn(
			"Export server rejected the payload",
			zap.String("kind", p.Kind),
			zap.String("ref", logRef),
			zap.Int("status", resp.StatusCode),
		)
	}
}
