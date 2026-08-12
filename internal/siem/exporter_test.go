package siem

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostUsesStableIdempotencyHeaders(t *testing.T) {
	var eventID, idempotency, contentType string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eventID = r.Header.Get("X-OTLens-Event-ID")
		idempotency = r.Header.Get("Idempotency-Key")
		contentType = r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	exporter, err := New(Config{Enabled: true, URL: srv.URL, Headers: map[string]string{"Idempotency-Key": "bad-static-value"}}, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if err := exporter.post(context.Background(), "event-123", []byte(`{"kind":"alert"}`)); err != nil {
		t.Fatalf("post() failed: %v", err)
	}
	if eventID != "event-123" || idempotency != "event-123" {
		t.Fatalf("idempotency headers event=%q idempotency=%q", eventID, idempotency)
	}
	if contentType != "application/json" {
		t.Fatalf("content type=%q", contentType)
	}
	if string(body) != `{"kind":"alert"}` {
		t.Fatalf("body=%q", body)
	}
}
