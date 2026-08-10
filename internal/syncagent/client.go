package syncagent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
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
	enrollmentToken    string
	sensorToken        string
	http               *http.Client
	telemetryHTTP      *http.Client
	telemetryTimeout   time.Duration
	rulesVersion       int64
	threatIntelVersion int64
}

func New(cfg Config) *Client {
	if strings.TrimSpace(cfg.CredentialFile) == "" {
		safeID := regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(cfg.SensorID, "_")
		cfg.CredentialFile = filepath.Join(".", ".otlens-sensor-"+safeID+".token")
	}
	enrollmentToken := strings.TrimSpace(cfg.Token)
	sensorToken := ""
	if token, err := os.ReadFile(cfg.CredentialFile); err == nil {
		sensorToken = strings.TrimSpace(string(token))
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   4,
	}
	// Telemetry is intentionally allowed longer than the interactive sensor API
	// calls. Central persists topology/contact-tracing ledgers transactionally,
	// and a sensor restoring a backlog from SQLite can legitimately need more
	// than the normal 15s request timeout. A short timeout here creates a
	// pathological loop: heartbeat succeeds, telemetry is cancelled, nothing is
	// acknowledged/marked synced, and the same backlog is retried forever.
	telemetryTimeout := cfg.Timeout * 4
	if telemetryTimeout < 60*time.Second {
		telemetryTimeout = 60 * time.Second
	}
	if telemetryTimeout > 5*time.Minute {
		telemetryTimeout = 5 * time.Minute
	}
	telemetryTransport := transport.Clone()
	telemetryTransport.ResponseHeaderTimeout = telemetryTimeout
	return &Client{
		cfg:              cfg,
		enrollmentToken:  enrollmentToken,
		sensorToken:      sensorToken,
		http:             &http.Client{Timeout: cfg.Timeout, Transport: transport},
		telemetryHTTP:    &http.Client{Timeout: telemetryTimeout, Transport: telemetryTransport},
		telemetryTimeout: telemetryTimeout,
	}
}

// HTTPError preserves Central's structured error response so callers can
// distinguish authentication/enrollment failures from ordinary transport or
// server errors without parsing a human-readable string.
type HTTPError struct {
	Prefix     string
	Status     string
	StatusCode int
	Body       string
	Code       string
}

func (e *HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("%s: %s", e.Prefix, e.Status)
	}
	return fmt.Sprintf("%s: %s: %s", e.Prefix, e.Status, e.Body)
}

// syncErr builds an error from a non-2xx response that includes Central's
// actual response body (typically a JSON {"error":"..."}) and, when
// present, its stable machine-readable error code. The body is capped at 2KB
// so a misbehaving proxy returning an HTML error page cannot flood logs.
func syncErr(prefix string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(body))
	var payload struct {
		Code string `json:"code"`
	}
	if msg != "" {
		_ = json.Unmarshal(body, &payload)
	}
	return &HTTPError{Prefix: prefix, Status: resp.Status, StatusCode: resp.StatusCode, Body: msg, Code: strings.TrimSpace(payload.Code)}
}

// IsSensorAuthError reports whether an authenticated sensor API call was
// rejected because the bearer credential is no longer valid. Worker uses this
// to re-enter enrollment only after Central actually loses/revokes the sensor
// row instead of POSTing /register on every normal synchronization cycle.
func IsSensorAuthError(err error) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized
}

func enrollmentRequired(err error) bool {
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		return false
	}
	if httpErr.Code == "sensor_enrollment_required" {
		return true
	}
	// Backward compatibility with a Central built before machine-readable
	// enrollment codes were added.
	return strings.Contains(httpErr.Body, "valid enrollment credential required") || strings.Contains(httpErr.Body, "sensor is not enrolled")
}

func (c *Client) sensorCredential() string {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.sensorToken
}

// HasSensorCredential reports whether the sensor already has a persisted
// per-sensor credential. A normal process restart should use that credential
// directly for sync/heartbeat instead of calling /register again. Registration
// is enrollment/recovery, not a liveness signal.
func (c *Client) HasSensorCredential() bool {
	return strings.TrimSpace(c.sensorCredential()) != ""
}

func (c *Client) headersWithToken(r *http.Request, token string) {
	c.cfgMu.RLock()
	sensorID := c.cfg.SensorID
	c.cfgMu.RUnlock()
	if strings.TrimSpace(token) != "" {
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	r.Header.Set("X-OTLens-Sensor-ID", sensorID)
	r.Header.Set("Content-Type", "application/json")
}

func (c *Client) headers(r *http.Request) {
	c.headersWithToken(r, c.sensorCredential())
}

type registrationResponse struct {
	SensorID    string `json:"sensor_id"`
	Status      string `json:"status"`
	SensorToken string `json:"sensor_token"`
}

func (c *Client) registerWithToken(ctx context.Context, token string) (registrationResponse, error) {
	c.cfgMu.RLock()
	cfg := c.cfg
	c.cfgMu.RUnlock()
	b, _ := json.Marshal(management.SensorRegistration{ID: cfg.SensorID, Name: cfg.Name, SiteID: cfg.SiteID, Version: cfg.Version, Hostname: cfg.Hostname})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.BaseURL, "/")+"/v1/sensors/register", strings.NewReader(string(b)))
	if err != nil {
		return registrationResponse{}, err
	}
	c.headersWithToken(req, token)
	resp, err := c.http.Do(req)
	if err != nil {
		return registrationResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return registrationResponse{}, syncErr("registration failed", resp)
	}
	var out registrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return registrationResponse{}, fmt.Errorf("decode sensor enrollment response: %w", err)
	}
	if out.SensorID != cfg.SensorID {
		return registrationResponse{}, fmt.Errorf("central returned an invalid sensor identity")
	}
	return out, nil
}

func (c *Client) persistSensorCredential(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("central returned an empty sensor credential")
	}
	c.cfgMu.Lock()
	c.sensorToken = token
	credentialFile := c.cfg.CredentialFile
	c.cfgMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(credentialFile), 0700); err != nil {
		return fmt.Errorf("create sensor credential directory: %w", err)
	}
	if err := os.WriteFile(credentialFile, []byte(token+"\n"), 0600); err != nil {
		return fmt.Errorf("persist sensor credential: %w", err)
	}
	return nil
}

func (c *Client) Register(ctx context.Context) error {
	c.cfgMu.RLock()
	sensorToken := strings.TrimSpace(c.sensorToken)
	enrollmentToken := strings.TrimSpace(c.enrollmentToken)
	c.cfgMu.RUnlock()

	presented := sensorToken
	if presented == "" {
		presented = enrollmentToken
	}
	if presented == "" {
		return fmt.Errorf("sensor registration credential is empty")
	}

	out, err := c.registerWithToken(ctx, presented)
	if err != nil && sensorToken != "" && enrollmentToken != "" && enrollmentToken != sensorToken && enrollmentRequired(err) {
		// Central no longer has this sensor row (for example after an
		// explicit sensor deletion or a PostgreSQL rebuild). The persisted
		// per-sensor credential is intentionally useless once its server-side
		// hash is gone, so retry exactly once with the enrollment credential.
		firstErr := err
		out, err = c.registerWithToken(ctx, enrollmentToken)
		if err != nil {
			var httpErr *HTTPError
			if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized {
				return fmt.Errorf("sensor re-enrollment failed: Central rejected central.token after the persisted per-sensor credential was no longer known; verify sensor central.token against Central auth.sensor_token and any OTLENS_CENTRAL_TOKEN / OTLENS_CENTRAL_AUTH_SENSOR_TOKEN environment overrides: %w", err)
			}
			return fmt.Errorf("sensor re-enrollment failed after Central rejected the persisted credential (%v): %w", firstErr, err)
		}
	}
	if err != nil {
		return err
	}

	if strings.TrimSpace(out.SensorToken) != "" {
		return c.persistSensorCredential(out.SensorToken)
	}
	// An already-enrolled sensor is authenticated by its existing token and
	// Central deliberately does not rotate it on every registration refresh.
	if sensorToken == "" {
		return fmt.Errorf("central did not issue a sensor credential during enrollment")
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

// TelemetryTimeout returns the effective timeout reserved for a telemetry
// transaction. It is longer than Config.Timeout because a backlog flush can
// require many PostgreSQL writes even while heartbeat/authentication remain
// healthy.
func (c *Client) TelemetryTimeout() time.Duration {
	return c.telemetryTimeout
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
	resp, err := c.telemetryHTTP.Do(req)
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
