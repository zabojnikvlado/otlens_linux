package central

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSanitizeMailHeaderRemovesNewlines(t *testing.T) {
	got := sanitizeMailHeader("subject\r\nBcc: attacker@example.invalid")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("header still contains newline: %q", got)
	}
}

func TestWebhookNotificationExportsStableAlertFields(t *testing.T) {
	var gotHeader string
	var got map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-OTLens-Event-ID")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	var cfg NotificationConfig
	cfg.Webhook.Enabled = true
	cfg.Webhook.URL = ts.URL
	srv := &Server{Notifications: cfg}
	last := time.Date(2026, 8, 11, 18, 3, 4, 0, time.UTC)
	alert := AlertHistoryEntry{SensorID: "sensor-001", AlertKey: "a1", Type: "external_communication", Severity: "high", Message: "test", IP: "10.1.2.3", Status: "new", Count: 3, FirstSeen: last.Add(-time.Minute), LastSeen: last, Evidence: map[string]interface{}{"port": 443}}
	if err := srv.sendWebhookNotification(context.Background(), alert); err != nil {
		t.Fatalf("sendWebhookNotification() failed: %v", err)
	}
	if gotHeader == "" || got["event_id"] != gotHeader {
		t.Fatalf("event id mismatch payload=%v header=%q", got["event_id"], gotHeader)
	}
	if got["schema_version"] != "otlens.notification.v1" || got["alert_key"] != "a1" {
		t.Fatalf("unexpected webhook payload: %#v", got)
	}
}
