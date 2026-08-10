package syncagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRegisterReenrollsWhenPersistedCredentialNoLongerKnown(t *testing.T) {
	credentialFile := filepath.Join(t.TempDir(), "sensor.token")
	if err := os.WriteFile(credentialFile, []byte("old-sensor-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var presented []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sensors/register" {
			http.NotFound(w, r)
			return
		}
		presented = append(presented, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.Header().Set("Content-Type", "application/json")
		switch len(presented) {
		case 1:
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "valid enrollment credential required",
				"code":  "sensor_enrollment_required",
			})
		case 2:
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sensor_id":    "sensor-1",
				"status":       "registered",
				"sensor_token": "new-sensor-token",
			})
		case 3:
			// A normal refresh authenticated with the per-sensor token must not
			// rotate the credential again.
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sensor_id": "sensor-1",
				"status":    "registered",
			})
		default:
			t.Fatalf("unexpected registration request %d", len(presented))
		}
	}))
	defer server.Close()

	client := New(Config{
		BaseURL:        server.URL,
		Token:          "enrollment-token",
		SensorID:       "sensor-1",
		Name:           "Line 1",
		CredentialFile: credentialFile,
		Timeout:        time.Second,
	})

	if err := client.Register(context.Background()); err != nil {
		t.Fatalf("re-enrollment failed: %v", err)
	}
	if err := client.Register(context.Background()); err != nil {
		t.Fatalf("normal registration refresh failed: %v", err)
	}

	wantPresented := []string{"old-sensor-token", "enrollment-token", "new-sensor-token"}
	if !reflect.DeepEqual(presented, wantPresented) {
		t.Fatalf("presented credentials = %#v, want %#v", presented, wantPresented)
	}
	persisted, err := os.ReadFile(credentialFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(persisted)); got != "new-sensor-token" {
		t.Fatalf("persisted credential = %q, want new-sensor-token", got)
	}
	if client.enrollmentToken != "enrollment-token" {
		t.Fatalf("enrollment credential was overwritten: %q", client.enrollmentToken)
	}
	if client.sensorCredential() != "new-sensor-token" {
		t.Fatalf("active sensor credential = %q, want new-sensor-token", client.sensorCredential())
	}
	if client.cfg.Token != "enrollment-token" {
		t.Fatalf("config enrollment token was overwritten: %q", client.cfg.Token)
	}
}

func TestRegisterDoesNotUseEnrollmentTokenForInvalidExistingCredential(t *testing.T) {
	credentialFile := filepath.Join(t.TempDir(), "sensor.token")
	if err := os.WriteFile(credentialFile, []byte("wrong-sensor-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "existing sensor credential required",
			"code":  "sensor_credential_invalid",
		})
	}))
	defer server.Close()

	client := New(Config{
		BaseURL:        server.URL,
		Token:          "enrollment-token",
		SensorID:       "sensor-1",
		CredentialFile: credentialFile,
		Timeout:        time.Second,
	})

	err := client.Register(context.Background())
	if err == nil {
		t.Fatal("expected registration to fail")
	}
	if calls != 1 {
		t.Fatalf("registration calls = %d, want 1; enrollment token must not bypass an existing sensor credential", calls)
	}
}
