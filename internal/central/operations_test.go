package central

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSensitiveEndpointCatalogIsProtected(t *testing.T) {
	controls := endpointControls()
	if len(controls) < 10 {
		t.Fatalf("expected meaningful endpoint catalog, got %d", len(controls))
	}
	for _, item := range controls {
		if item.Method == "" || item.Path == "" || item.Permission == "" {
			t.Fatalf("incomplete endpoint control: %+v", item)
		}
	}
}

func TestAuditFilterFromRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/v1/audit?actor=alice&action=backup&sensor_id=s-1&success=false&limit=42&offset=7", nil)
	f := auditFilterFromRequest(c)
	if f.Actor != "alice" || f.Action != "backup" || f.SensorID != "s-1" || f.Limit != 42 || f.Offset != 7 {
		t.Fatalf("unexpected filter: %+v", f)
	}
	if f.Success == nil || *f.Success {
		t.Fatalf("expected success=false: %+v", f.Success)
	}
}
