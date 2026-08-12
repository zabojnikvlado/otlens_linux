package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/central"
)

type Config struct {
	Enabled            bool
	URL                string
	ExportAlerts       bool
	ExportAudit        bool
	BearerToken        string
	Headers            map[string]string
	Timeout            time.Duration
	RetryInterval      time.Duration
	BatchSize          int
	MaxAttempts        int
	InsecureSkipVerify bool
	CACertFile         string
	ClientCertFile     string
	ClientKeyFile      string
	ServerName         string
}

type Exporter struct {
	cfg    Config
	repo   *central.Repository
	client *http.Client
}

func New(cfg Config, repo *central.Repository) (*Exporter, error) {
	if !cfg.Enabled {
		return &Exporter{cfg: cfg, repo: repo}, nil
	}
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("SIEM URL is empty")
	}
	parsedURL, err := url.Parse(cfg.URL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("SIEM URL must be an absolute http(s) URL")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = 15 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify, ServerName: cfg.ServerName, MinVersion: tls.VersionTLS12}
	if cfg.CACertFile != "" {
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read SIEM CA certificate: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("SIEM CA certificate contains no usable PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCertFile != "" || cfg.ClientKeyFile != "" {
		if cfg.ClientCertFile == "" || cfg.ClientKeyFile == "" {
			return nil, fmt.Errorf("both SIEM client certificate and key must be configured")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load SIEM client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &Exporter{
		cfg:  cfg,
		repo: repo,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			// Never allow a 301/302/303 to turn a POST export into a GET and
			// then report success with the event body silently discarded. SIEM
			// endpoints must be configured to their final ingestion URL.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (e *Exporter) Run(ctx context.Context) {
	if !e.cfg.Enabled {
		return
	}
	log.Printf("SIEM export enabled: url=%s alerts=%t audit=%t", e.cfg.URL, e.cfg.ExportAlerts, e.cfg.ExportAudit)
	e.flush(ctx)
	ticker := time.NewTicker(e.cfg.RetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.flush(ctx)
		}
	}
}

func (e *Exporter) flush(ctx context.Context) {
	for {
		events, err := e.repo.PendingSIEM(ctx, e.cfg.BatchSize, e.cfg.MaxAttempts, e.cfg.ExportAlerts, e.cfg.ExportAudit)
		if err != nil {
			log.Printf("SIEM outbox read failed: %v", err)
			return
		}
		if len(events) == 0 {
			return
		}
		for _, event := range events {
			if err := e.post(ctx, event.EventKey, event.Payload); err != nil {
				backoff := e.cfg.RetryInterval * time.Duration(1+event.Attempts)
				if backoff > 10*time.Minute {
					backoff = 10 * time.Minute
				}
				if markErr := e.repo.MarkSIEMFailed(ctx, event.ID, backoff, err.Error()); markErr != nil {
					log.Printf("SIEM outbox failure acknowledgement failed id=%d: %v", event.ID, markErr)
				}
				log.Printf("SIEM export failed kind=%s id=%d attempt=%d: %v", event.Kind, event.ID, event.Attempts+1, err)
				continue
			}
			if err := e.repo.MarkSIEMDelivered(ctx, event.ID); err != nil {
				log.Printf("SIEM outbox acknowledgement failed id=%d: %v", event.ID, err)
			}
		}
		if len(events) < e.cfg.BatchSize {
			return
		}
	}
}

func (e *Exporter) post(ctx context.Context, eventKey string, body []byte) error {
	// The payload is immutable once it enters the outbox. In particular, do not
	// rewrite source here from current runtime config: an event accepted by the
	// receiver and retried after a Central config change must retain identical
	// semantics under the same idempotency key.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OTLens-Central-SIEM/1.0")
	if e.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+e.cfg.BearerToken)
	}
	for key, value := range e.cfg.Headers {
		req.Header.Set(key, value)
	}
	if strings.TrimSpace(eventKey) != "" {
		// Delivery is intentionally at-least-once: if the receiver accepted an
		// event but Central lost the acknowledgement, a retry can occur. Keep
		// this canonical header after operator-supplied headers so it cannot be
		// accidentally overwritten by a static configured value.
		req.Header.Set("X-OTLens-Event-ID", eventKey)
		req.Header.Set("Idempotency-Key", eventKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("SIEM returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
