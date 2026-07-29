package central

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
)

type udpConversationResult struct {
	SensorID string `json:"sensor_id"`
	udpconversation.Conversation
	Status         string           `json:"status"`
	DurationMillis float64          `json:"duration_millis"`
	RTTMillis      float64          `json:"rtt_millis"`
	Timeline       []map[string]any `json:"timeline,omitempty"`
}

func (s *Server) udpConversations(c *gin.Context) {
	snapshots, err := s.Repo.Telemetry(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "loading UDP conversations failed"})
		return
	}
	var result []udpConversationResult
	for _, snapshot := range snapshots {
		if sensor := strings.TrimSpace(c.Query("sensor_id")); sensor != "" && sensor != snapshot.SensorID {
			continue
		}
		var conversations []udpconversation.Conversation
		if json.Unmarshal(snapshot.UDPConversations, &conversations) != nil {
			continue
		}
		exchanges := udpTimelines(snapshot.UDPProtocolExchanges)
		for _, conversation := range conversations {
			if matchUDPConversation(c, conversation) {
				result = append(result, presentUDPConversation(snapshot.SensorID, snapshot.CapturedAt, conversation, exchanges[conversation.ID]))
			}
		}
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) udpConversation(c *gin.Context) {
	id := c.Param("id")
	snapshots, err := s.Repo.Telemetry(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "loading UDP conversation failed"})
		return
	}
	for _, snapshot := range snapshots {
		if sensor := strings.TrimSpace(c.Query("sensor_id")); sensor != "" && sensor != snapshot.SensorID {
			continue
		}
		var conversations []udpconversation.Conversation
		if json.Unmarshal(snapshot.UDPConversations, &conversations) != nil {
			continue
		}
		for _, conversation := range conversations {
			if conversation.ID == id {
				c.JSON(http.StatusOK, presentUDPConversation(snapshot.SensorID, snapshot.CapturedAt, conversation, udpTimeline(snapshot.UDPProtocolExchanges, id)))
				return
			}
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "UDP conversation not found"})
}

func presentUDPConversation(sensorID string, capturedAt time.Time, conversation udpconversation.Conversation, exchanges []map[string]any) udpConversationResult {
	timeline := make([]map[string]any, 0)
	var rttTotal float64
	var rttCount int
	status := "active"
	for _, exchange := range exchanges {
		timeline = append(timeline, exchange)
		if boolValue(exchange, "TimedOut", "timed_out") {
			status = "timed_out"
		} else if status != "timed_out" && exchangeComplete(exchange) {
			status = "closed"
		}
		if value := durationMillis(exchange, "RTT", "rtt", "ResponseTime", "response_time", "TimeToResponse"); value > 0 {
			rttTotal += value
			rttCount++
		}
	}
	if status == "active" && !capturedAt.IsZero() && capturedAt.Sub(conversation.LastSeenAt) >= 10*time.Second {
		status = "idle"
	}
	duration := conversation.LastSeenAt.Sub(conversation.StartedAt).Seconds() * 1000
	result := udpConversationResult{SensorID: sensorID, Conversation: conversation, Status: status, DurationMillis: duration, Timeline: timeline}
	if rttCount > 0 {
		result.RTTMillis = rttTotal / float64(rttCount)
	}
	return result
}

func udpTimelines(raw json.RawMessage) map[string][]map[string]any {
	result := make(map[string][]map[string]any)
	for _, exchange := range udpTimeline(raw, "") {
		if id := exchangeConversationID(exchange); id != "" {
			result[id] = append(result[id], exchange)
		}
	}
	return result
}

func udpTimeline(raw json.RawMessage, id string) []map[string]any {
	var exchanges []map[string]any
	_ = json.Unmarshal(raw, &exchanges)
	if id == "" {
		return exchanges
	}
	result := make([]map[string]any, 0)
	for _, exchange := range exchanges {
		if exchangeConversationID(exchange) == id {
			result = append(result, exchange)
		}
	}
	return result
}

func exchangeConversationID(exchange map[string]any) string {
	for _, key := range []string{"ConversationID", "conversation_id"} {
		if value, ok := exchange[key].(string); ok {
			return value
		}
	}
	return ""
}

func boolValue(exchange map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, ok := exchange[key].(bool); ok && value {
			return true
		}
	}
	return false
}

func exchangeComplete(exchange map[string]any) bool {
	for _, key := range []string{"RespondedAt", "responded_at", "CompletedAt", "EndedAt"} {
		if value, ok := exchange[key].(string); ok && value != "" && !strings.HasPrefix(value, "0001-") {
			return true
		}
	}
	return false
}

func durationMillis(exchange map[string]any, keys ...string) float64 {
	for _, key := range keys {
		if value, ok := exchange[key].(float64); ok && value > 0 {
			return value / float64(time.Millisecond)
		}
	}
	return 0
}

func (s *Server) udpTelemetry(c *gin.Context) {
	snapshots, err := s.Repo.Telemetry(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "loading UDP telemetry failed"})
		return
	}
	totals := map[string]float64{}
	protocols := map[string]uint64{}
	var rttWeighted, durationWeighted float64
	var rttWeight, durationWeight uint64
	for _, snapshot := range snapshots {
		var telemetry map[string]float64
		if json.Unmarshal(snapshot.UDPTelemetry, &telemetry) == nil {
			for key, value := range telemetry {
				switch key {
				case "udp_average_rtt":
					weight := uint64(telemetry["udp_packets_total"])
					rttWeighted += value * float64(weight)
					rttWeight += weight
				case "udp_average_duration":
					weight := uint64(telemetry["udp_conversations_active"])
					durationWeighted += value * float64(weight)
					durationWeight += weight
				default:
					totals[key] += value
				}
			}
		}
		var conversations []udpconversation.Conversation
		_ = json.Unmarshal(snapshot.UDPConversations, &conversations)
		for _, conversation := range conversations {
			protocols[strings.ToLower(conversation.Protocol)]++
		}
	}
	if rttWeight > 0 {
		totals["udp_average_rtt"] = rttWeighted / float64(rttWeight)
	}
	if durationWeight > 0 {
		totals["udp_average_duration"] = durationWeighted / float64(durationWeight)
	}
	topProtocol := ""
	var topCount uint64
	for protocol, count := range protocols {
		if count > topCount {
			topProtocol, topCount = protocol, count
		}
	}
	c.JSON(http.StatusOK, gin.H{"totals": totals, "protocols": protocols, "top_protocol": topProtocol})
}

func matchUDPConversation(c *gin.Context, conversation udpconversation.Conversation) bool {
	if protocol := strings.ToLower(strings.TrimSpace(c.Query("protocol"))); protocol != "" && strings.ToLower(conversation.Protocol) != protocol {
		return false
	}
	if source := strings.TrimSpace(c.Query("src_ip")); source != "" && conversation.Key.EndpointAIP != source && conversation.Key.EndpointBIP != source {
		return false
	}
	if destination := strings.TrimSpace(c.Query("dst_ip")); destination != "" && conversation.Key.EndpointAIP != destination && conversation.Key.EndpointBIP != destination {
		return false
	}
	if value := strings.TrimSpace(c.Query("port")); value != "" {
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || conversation.Key.EndpointAPort != uint16(port) && conversation.Key.EndpointBPort != uint16(port) {
			return false
		}
	}
	if active := strings.TrimSpace(c.Query("active")); active != "" {
		value, err := strconv.ParseBool(active)
		if err != nil || !value { // snapshots contain active conversations only
			return false
		}
	}
	if value := strings.TrimSpace(c.Query("started_from")); value != "" {
		from, err := time.Parse(time.RFC3339, value)
		if err != nil || conversation.StartedAt.Before(from) {
			return false
		}
	}
	if value := strings.TrimSpace(c.Query("started_to")); value != "" {
		to, err := time.Parse(time.RFC3339, value)
		if err != nil || conversation.StartedAt.After(to) {
			return false
		}
	}
	return true
}
