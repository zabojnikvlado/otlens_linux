package central

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestWebRouterHealthAndProtectedAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{}
	r := s.WebRouter()

	t.Run("health is public", func(t *testing.T) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("health status=%d body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("assets require authentication", func(t *testing.T) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/assets", nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("assets status=%d body=%s", w.Code, w.Body.String())
		}
	})
}

func TestSensorRouterProtectsTelemetry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{SensorToken: "expected-token"}
	r := s.SensorRouter()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/sensors/telemetry", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("telemetry status=%d body=%s", w.Code, w.Body.String())
	}
}
