package central

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
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

	subject := fmt.Sprintf("[OTLens] %s alert: %s", strings.ToUpper(alert.Severity), alert.Type)
	body := fmt.Sprintf(
		"Sensor: %s\nSeverity: %s\nType: %s\nIP: %s\nMessage: %s\nFirst seen: %s\n\n— OTLens Central",
		alert.SensorID, alert.Severity, alert.Type, alert.IP, alert.Message, alert.FirstSeen.Format(time.RFC3339),
	)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n",
		cfg.From, strings.Join(cfg.To, ", "), subject, body)
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
		cfg.From, strings.Join(to, ", "), subject, htmlBody,
	)
	return s.sendEmailRaw(cfg.From, to, msg)
}

// sendEmailRaw does the actual SMTP connection/send for both
// sendEmailNotification and sendEmailHTML — see either for the message
// construction that precedes this.
func (s *Server) sendEmailRaw(from string, to []string, msg string) error {
	cfg := s.Notifications.Email
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)
	}

	if !cfg.UseTLS {
		return smtp.SendMail(addr, auth, from, to, []byte(msg))
	}

	// smtp.SendMail's plaintext path doesn't do STARTTLS/implicit TLS —
	// most providers require one or the other, so this is the explicit
	// STARTTLS flow instead.
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.SMTPHost})
	if err != nil {
		// Fall back to STARTTLS over a plain connection if implicit TLS
		// (port 465-style) isn't what this server speaks.
		client, dialErr := smtp.Dial(addr)
		if dialErr != nil {
			return fmt.Errorf("connect: %w", err)
		}
		defer client.Close()
		if err := client.StartTLS(&tls.Config{ServerName: cfg.SMTPHost}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
		return sendSMTP(client, auth, from, to, msg)
	}
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Close()
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
	payload, err := json.Marshal(map[string]interface{}{
		"sensor_id":  alert.SensorID,
		"severity":   alert.Severity,
		"type":       alert.Type,
		"message":    alert.Message,
		"ip":         alert.IP,
		"first_seen": alert.FirstSeen,
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
	req.Header.Set("Content-Type", "application/json")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
