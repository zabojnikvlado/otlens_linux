package central

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// NotificationConfig mirrors config.CentralConfig.Notifications — kept
// as its own type here for the same reason RetentionConfig is: this
// package doesn't need to import internal/config just for these fields.
type NotificationConfig struct {
	Enabled     bool
	MinSeverity string
	Email       struct {
		Enabled  bool
		SMTPHost string
		SMTPPort int
		Username string
		Password string
		From     string
		To       []string
		UseTLS   bool
	}
	Webhook struct {
		Enabled bool
		URL     string
		Headers map[string]string
	}
}

var severityRank = map[string]int{
	"low": 0, "medium": 1, "high": 2, "critical": 3,
}

// meetsThreshold reports whether severity is at or above the
// configured minimum. An unrecognized severity string is treated as
// below every threshold (fails safe toward *not* notifying on garbage
// input, rather than notifying on everything).
func meetsThreshold(severity, minimum string) bool {
	s, sOK := severityRank[strings.ToLower(severity)]
	m, mOK := severityRank[strings.ToLower(minimum)]
	if !sOK || !mOK {
		return false
	}
	return s >= m
}

// dispatchNotifications sends an out-of-band ping for each newly
// created alert that meets NotificationConfig.MinSeverity — called as
// a goroutine from the telemetry handler, so a slow or failing
// SMTP/webhook target never holds up a sensor's sync. Both delivery
// paths are independently optional and independently logged on
// failure; one failing doesn't stop the other from being tried for the
// same alert.
func (s *Server) dispatchNotifications(ctx context.Context, newAlerts []AlertHistoryEntry) {
	if !s.Notifications.Enabled {
		return
	}
	for _, alert := range newAlerts {
		if !meetsThreshold(alert.Severity, s.Notifications.MinSeverity) {
			continue
		}
		if s.Notifications.Email.Enabled {
			if err := s.sendEmailNotification(alert); err != nil {
				log.Printf("notification: email send failed for alert %s/%s: %v", alert.SensorID, alert.AlertKey, err)
			}
		}
		if s.Notifications.Webhook.Enabled {
			if err := s.sendWebhookNotification(ctx, alert); err != nil {
				log.Printf("notification: webhook send failed for alert %s/%s: %v", alert.SensorID, alert.AlertKey, err)
			}
		}
	}
}

func (s *Server) sendEmailNotification(alert AlertHistoryEntry) error {
	cfg := s.Notifications.Email
	if cfg.SMTPHost == "" || cfg.From == "" || len(cfg.To) == 0 {
		return fmt.Errorf("email notifications enabled but smtp_host/from/to are not fully configured")
	}

	subject := sanitizeMailHeader(fmt.Sprintf("[OTLens] %s alert: %s", strings.ToUpper(alert.Severity), alert.Type))
	body := fmt.Sprintf(
		"Sensor: %s\nSeverity: %s\nType: %s\nIP: %s\nMessage: %s\nFirst seen: %s\n\n— OTLens Central",
		alert.SensorID, alert.Severity, alert.Type, alert.IP, alert.Message, alert.FirstSeen.Format(time.RFC3339),
	)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n",
		sanitizeMailHeader(cfg.From), sanitizeMailHeader(strings.Join(cfg.To, ", ")), subject, body)
	return s.sendEmailRaw(cfg.From, cfg.To, msg)
}

// sendEmailHTML sends an HTML email — used by reports.go, where
// sendEmailNotification's plain-text body wouldn't render the
// generated report's formatting. Recipients (to) are passed in
// separately from Notifications.Email.To, since a report's audience
// (Reports.Recipients) is often not the same list as who gets
// real-time alert pings — but the SMTP *connection* settings
// (host/port/credentials/TLS) always come from Notifications.Email,
// there's no separate copy of those for reports.
func (s *Server) sendEmailHTML(subject, htmlBody string, to []string) error {
	cfg := s.Notifications.Email
	if cfg.SMTPHost == "" || cfg.From == "" || len(to) == 0 {
		return fmt.Errorf("email not fully configured: smtp_host/from (notifications.email) and recipients are all required")
	}
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n",
		sanitizeMailHeader(cfg.From), sanitizeMailHeader(strings.Join(to, ", ")), sanitizeMailHeader(subject), htmlBody,
	)
	return s.sendEmailRaw(cfg.From, to, msg)
}

func sanitizeMailHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func validateEnvelopeAddresses(from string, to []string) error {
	for _, value := range append([]string{from}, to...) {
		if strings.ContainsAny(value, "\r\n") || strings.TrimSpace(value) == "" {
			return fmt.Errorf("invalid SMTP envelope address")
		}
	}
	return nil
}

// sendEmailRaw does the actual SMTP connection/send for both
// sendEmailNotification and sendEmailHTML — see either for the message
// construction that precedes this.
func (s *Server) sendEmailRaw(from string, to []string, msg string) error {
	cfg := s.Notifications.Email
	if err := validateEnvelopeAddresses(from, to); err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if cfg.UseTLS && cfg.SMTPPort == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	// A dial timeout only protects connection establishment. Bound the whole
	// SMTP exchange too, otherwise a server that accepts TCP and then stalls can
	// block the report/notification worker indefinitely.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Close()

	if cfg.SMTPPort != 465 {
		startTLSSupported, _ := client.Extension("STARTTLS")
		if cfg.UseTLS && !startTLSSupported {
			return fmt.Errorf("SMTP server does not advertise STARTTLS")
		}
		// Match net/smtp's safe default: opportunistically upgrade when the
		// server supports STARTTLS, and require the upgrade when UseTLS is set.
		if startTLSSupported {
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}
	return sendSMTP(client, auth, from, to, msg)
}

func sendSMTP(client *smtp.Client, auth smtp.Auth, from string, to []string, msg string) error {
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err := client.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (s *Server) sendWebhookNotification(ctx context.Context, alert AlertHistoryEntry) error {
	cfg := s.Notifications.Webhook
	if cfg.URL == "" {
		return fmt.Errorf("webhook notifications enabled but url is not configured")
	}
	eventID := fmt.Sprintf("alert:%s:%s:%d:%d", alert.SensorID, alert.AlertKey, alert.Count, alert.LastSeen.UTC().UnixNano())
	payload, err := json.Marshal(map[string]interface{}{
		"schema_version": "otlens.notification.v1",
		"event_id":       eventID,
		"sensor_id":      alert.SensorID,
		"alert_key":      alert.AlertKey,
		"severity":       alert.Severity,
		"type":           alert.Type,
		"message":        alert.Message,
		"ip":             alert.IP,
		"status":         alert.Status,
		"count":          alert.Count,
		"first_seen":     alert.FirstSeen,
		"last_seen":      alert.LastSeen,
		"evidence":       alert.Evidence,
	})
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-OTLens-Event-ID", eventID)
	req.Header.Set("Idempotency-Key", eventID)
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("webhook returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
