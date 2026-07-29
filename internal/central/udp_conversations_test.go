package central

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

func TestMatchUDPConversationFilters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	conversation := udpconversation.Conversation{
		ID: "dns-conversation", Protocol: "dns", StartedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Key: udpconversation.Key{EndpointAIP: "10.0.0.1", EndpointAPort: 53000, EndpointBIP: "10.0.0.2", EndpointBPort: 53},
	}
	for _, query := range []string{
		"protocol=dns", "src_ip=10.0.0.1", "dst_ip=10.0.0.2", "port=53", "active=true",
		"started_from=2026-01-02T03%3A04%3A04Z", "started_to=2026-01-02T03%3A04%3A06Z",
	} {
		context, _ := gin.CreateTestContext(httptest.NewRecorder())
		context.Request = httptest.NewRequest("GET", "/v1/udp-conversations?"+query, nil)
		if !matchUDPConversation(context, conversation) {
			t.Fatalf("filter %q did not match", query)
		}
	}
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("GET", "/v1/udp-conversations?protocol=snmp", nil)
	if matchUDPConversation(context, conversation) {
		t.Fatal("mismatched protocol was accepted")
	}
}
