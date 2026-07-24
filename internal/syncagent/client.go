package syncagent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	BaseURL, Token, SensorID, Name, SiteID, Version, Hostname string
	InsecureSkipVerify                                        bool
	Interval                                                  time.Duration
	Timeout                                                   time.Duration
}
type Client struct {
	cfg          Config
	http         *http.Client
	rulesVersion int64
}

func New(cfg Config) *Client {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}}}}
}
func (c *Client) headers(r *http.Request) {
	if c.cfg.Token != "" {
		r.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	r.Header.Set("X-OTLens-Sensor-ID", c.cfg.SensorID)
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
		return fmt.Errorf("registration failed: %s", resp.Status)
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
		return fmt.Errorf("heartbeat failed: %s", resp.Status)
	}
	return nil
}
func (c *Client) PullRules(ctx context.Context, apply func([]*detect.Rule) error) ([]management.Command, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/sensors/"+c.cfg.SensorID+"/sync", nil)
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
		return nil, fmt.Errorf("sync failed: %s", resp.Status)
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
	return out.Commands, nil
}

func (c *Client) PushTelemetry(ctx context.Context, snapshot management.TelemetrySnapshot) error {
	b, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/sensors/telemetry", strings.NewReader(string(b)))
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
		return fmt.Errorf("telemetry upload failed: %s", resp.Status)
	}
	return nil
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
		return nil, fmt.Errorf("analysis poll failed: %s", resp.Status)
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
		return fmt.Errorf("analysis download failed: %s", resp.Status)
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
		return fmt.Errorf("analysis result upload failed: %s", resp.Status)
	}
	return nil
}
