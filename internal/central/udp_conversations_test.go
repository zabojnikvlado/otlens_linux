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

func TestPresentUDPConversationStatusAndRTT(t *testing.T) {
	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	conversation := udpconversation.Conversation{
		ID: "dns-conversation", Protocol: "dns", StartedAt: started, LastSeenAt: started.Add(25 * time.Millisecond),
	}
	exchanges := []map[string]any{{
		"conversation_id": "dns-conversation",
		"responded_at":    started.Add(20 * time.Millisecond).Format(time.RFC3339Nano),
		"rtt":             float64(20 * time.Millisecond),
	}}
	result := presentUDPConversation("sensor-a", started.Add(time.Second), conversation, exchanges)
	if result.Status != "closed" {
		t.Fatalf("status = %q, want closed", result.Status)
	}
	if result.RTTMillis != 20 {
		t.Fatalf("RTT = %v ms, want 20", result.RTTMillis)
	}
	if result.DurationMillis != 25 {
		t.Fatalf("duration = %v ms, want 25", result.DurationMillis)
	}
}

func TestPresentUDPConversationTimedOutWins(t *testing.T) {
	now := time.Now()
	conversation := udpconversation.Conversation{ID: "snmp", StartedAt: now, LastSeenAt: now}
	result := presentUDPConversation("sensor-a", now, conversation, []map[string]any{{
		"ConversationID": "snmp", "RespondedAt": now.Format(time.RFC3339Nano), "TimedOut": true,
	}})
	if result.Status != "timed_out" {
		t.Fatalf("status = %q, want timed_out", result.Status)
	}
}

func TestUDPTopologyFallbackFindsLiveTraffic(t *testing.T) {
	capturedAt := time.Date(2026, 8, 12, 8, 0, 0, 0, time.UTC)
	raw := []byte(`{"Edges":[
		{"Protocol":"UDP","SrcPort":53000,"DstPort":53,"Packets":12,"LastSeen":"2026-08-12T07:59:50Z"},
		{"Protocol":"UDP","SrcPort":40000,"DstPort":123,"Packets":3,"LastSeen":"2026-08-12T07:59:40Z"},
		{"Protocol":"TCP","SrcPort":443,"DstPort":50000,"Packets":99,"LastSeen":"2026-08-12T07:59:55Z"}
	]}`)
	got := udpTopologyFallback(raw, capturedAt)
	if got.Active != 2 || got.Packets != 15 {
		t.Fatalf("unexpected fallback totals: %#v", got)
	}
	if got.ProtocolPackets["dns"] != 12 || got.ProtocolPackets["ntp"] != 3 {
		t.Fatalf("unexpected fallback protocols: %#v", got.ProtocolPackets)
	}
}

func TestUDPTopologyFallbackExcludesStaleFromActive(t *testing.T) {
	capturedAt := time.Date(2026, 8, 12, 8, 0, 0, 0, time.UTC)
	raw := []byte(`{"Edges":[{"Protocol":"UDP","SrcPort":1,"DstPort":2,"Packets":7,"LastSeen":"2026-08-12T07:50:00Z"}]}`)
	got := udpTopologyFallback(raw, capturedAt)
	if got.Active != 0 || got.Packets != 7 || got.ProtocolPackets["udp"] != 7 {
		t.Fatalf("unexpected stale fallback: %#v", got)
	}
}
