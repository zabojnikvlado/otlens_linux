package syncagent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Config struct {
	BaseURL, Token, SensorID, Name, SiteID, Version, Hostname, CredentialFile string
	InsecureSkipVerify                                                        bool
	Interval                                                                  time.Duration
	Timeout                                                                   time.Duration
}
type Client struct {
	cfgMu              sync.RWMutex
	cfg                Config
	http               *http.Client
	rulesVersion       int64
	threatIntelVersion int64
}

func New(cfg Config) *Client {
	if strings.TrimSpace(cfg.CredentialFile) == "" {
		safeID := regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(cfg.SensorID, "_")
		cfg.CredentialFile = filepath.Join(".", ".otlens-sensor-"+safeID+".token")
	}
	if token, err := os.ReadFile(cfg.CredentialFile); err == nil && strings.TrimSpace(string(token)) != "" {
		cfg.Token = strings.TrimSpace(string(token))
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout, Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   4,
	}}}
}

// syncErr builds an error from a non-2xx response that includes Central's
// actual response body (typically a JSON {"error":"..."} with the real
// failure reason), not just the HTTP status line. resp.Status alone tells
// you *that* something failed, never *why* — which otherwise means the
// real cause only ever shows up in Central's own logs, not the sensor's,
// even though the sensor is what's reporting the failure. Capped at 2KB
// so a misbehaving proxy returning an HTML error page doesn't flood logs.
func syncErr(prefix string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return fmt.Errorf("%s: %s", prefix, resp.Status)
	}
	return fmt.Errorf("%s: %s: %s", prefix, resp.Status, msg)
}

func (c *Client) headers(r *http.Request) {
	c.cfgMu.RLock()
	token, sensorID := c.cfg.Token, c.cfg.SensorID
	c.cfgMu.RUnlock()
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("X-OTLens-Sensor-ID", sensorID)
	r.Header.Set("Content-Type", "application/json")
}
func (c *Client) Register(ctx context.Context) error {
	b, _ := json.Marshal(management.SensorRegistration{ID: c.cfg.SensorID, Name: c.cfg.Name, SiteID: c.cfg.SiteID, Version: c.cfg.Version, Hostname: c.cfg.Hostname})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/sensors/register", strings.NewReader(string(b)))
	if e != nil {
		return e
	}
	c.headers(req)
	resp, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return syncErr("registration failed", resp)
	}
	var out struct {
		SensorID    string `json:"sensor_id"`
		SensorToken string `json:"sensor_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode sensor enrollment response: %w", err)
	}
	if out.SensorID != c.cfg.SensorID || strings.TrimSpace(out.SensorToken) == "" {
		return fmt.Errorf("central returned an invalid sensor credential")
	}
	c.cfgMu.Lock()
	c.cfg.Token = out.SensorToken
	credentialFile := c.cfg.CredentialFile
	c.cfgMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(credentialFile), 0700); err != nil {
		return fmt.Errorf("create sensor credential directory: %w", err)
	}
	if err := os.WriteFile(credentialFile, []byte(out.SensorToken+"\n"), 0600); err != nil {
		return fmt.Errorf("persist sensor credential: %w", err)
	}
	return nil
}
func (c *Client) Heartbeat(ctx context.Context, h management.Heartbeat) error {
	b, _ := json.Marshal(h)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/sensors/heartbeat", strings.NewReader(string(b)))
	if e != nil {
		return e
	}
	c.headers(req)
	resp, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return syncErr("heartbeat failed", resp)
	}
	return nil
}
func (c *Client) PullRules(ctx context.Context, apply func([]*detect.Rule) error, applyThreatIntel func(management.ThreatIntelSnapshot) error) ([]management.Command, error) {
	syncURL := fmt.Sprintf("%s/v1/sensors/%s/sync?threat_intel_version=%d", strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.SensorID, c.threatIntelVersion)
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, syncURL, nil)
	if e != nil {
		return nil, e
	}
	c.headers(req)
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, syncErr("sync failed", resp)
	}
	var out management.SyncResponse
	if e := json.NewDecoder(resp.Body).Decode(&out); e != nil {
		return nil, e
	}
	if out.RuleSet != nil && out.RulesVersion > c.rulesVersion {
		rules := make([]*detect.Rule, 0, len(out.RuleSet.Rules))
		for _, r := range out.RuleSet.Rules {
			rules = append(rules, &detect.Rule{ID: r.ID, Name: r.Name, Kind: detect.RuleKind(r.Kind), Enabled: r.Enabled, Field: detect.RuleField(r.Field), Value: r.Value, Severity: r.Severity, AlertType: detect.AlertType(r.AlertType)})
		}
		if e := apply(rules); e != nil {
			return nil, e
		}
		c.rulesVersion = out.RulesVersion
	}
	if out.ThreatIntel != nil && out.ThreatIntelVersion > c.threatIntelVersion && applyThreatIntel != nil {
		if e := applyThreatIntel(*out.ThreatIntel); e != nil {
			return nil, e
		}
		c.threatIntelVersion = out.ThreatIntelVersion
	}
	return out.Commands, nil
}

func (c *Client) PushTelemetry(ctx context.Context, snapshot management.TelemetrySnapshot) (management.TelemetryAck, error) {
	b, err := json.Marshal(snapshot)
	if err != nil {
		return management.TelemetryAck{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/sensors/telemetry", strings.NewReader(string(b)))
	if err != nil {
		return management.TelemetryAck{}, err
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return management.TelemetryAck{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return management.TelemetryAck{}, syncErr("telemetry upload failed", resp)
	}
	var ack management.TelemetryAck
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return management.TelemetryAck{}, fmt.Errorf("decode telemetry acknowledgement: %w", err)
	}
	if !ack.Accepted || ack.AcceptedSequence != snapshot.Sequence {
		return management.TelemetryAck{}, fmt.Errorf("invalid telemetry acknowledgement for sequence %d", snapshot.Sequence)
	}
	return ack, nil
}

func (c *Client) NextAnalysisJob(ctx context.Context) (*management.AnalysisJob, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/sensors/"+c.cfg.SensorID+"/analysis/jobs/next", nil)
	if err != nil {
		return nil, err
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		return nil, syncErr("analysis poll failed", resp)
	}
	var job management.AnalysisJob
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (c *Client) DownloadAnalysisPCAP(ctx context.Context, jobID, target string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/sensors/"+c.cfg.SensorID+"/analysis/jobs/"+jobID+"/pcap", nil)
	if err != nil {
		return err
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return syncErr("analysis download failed", resp)
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func (c *Client) PushAnalysisResult(ctx context.Context, jobID string, result management.AnalysisResult) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/sensors/"+c.cfg.SensorID+"/analysis/jobs/"+jobID+"/result", strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return syncErr("analysis result upload failed", resp)
	}
	return nil
}

func (c *Client) PushReconResult(ctx context.Context, jobID string, results []management.ReconResult, runErr string) error {
	body, err := json.Marshal(map[string]interface{}{"results": results, "error": runErr})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/sensors/"+c.cfg.SensorID+"/reconnaissance/jobs/"+jobID+"/result", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return syncErr("reconnaissance result upload failed", resp)
	}
	return nil
}
