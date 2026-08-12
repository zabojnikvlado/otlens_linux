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
				timeline := udpCurrentSessionExchanges(exchanges[conversation.ID], conversation)
				result = append(result, presentUDPConversation(snapshot.SensorID, snapshot.CapturedAt, conversation, timeline))
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
				timeline := udpCurrentSessionExchanges(udpTimeline(snapshot.UDPProtocolExchanges, id), conversation)
				c.JSON(http.StatusOK, presentUDPConversation(snapshot.SensorID, snapshot.CapturedAt, conversation, timeline))
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

func udpCurrentSessionExchanges(exchanges []map[string]any, conversation udpconversation.Conversation) []map[string]any {
	if conversation.StartedAt.IsZero() {
		return exchanges
	}
	result := make([]map[string]any, 0, len(exchanges))
	for _, exchange := range exchanges {
		at, ok := udpExchangeStartTime(exchange)
		if !ok {
			// Protocol exchanges emitted by the current sensor all carry a request
			// or start timestamp. Omitting undated records is safer than attaching
			// evidence from an older endpoint-reused UDP session.
			continue
		}
		if at.Before(conversation.StartedAt) {
			continue
		}
		result = append(result, exchange)
	}
	return result
}

func udpExchangeStartTime(exchange map[string]any) (time.Time, bool) {
	for _, key := range []string{"RequestedAt", "requested_at", "StartedAt", "started_at", "LastSeenAt", "last_seen_at", "RespondedAt", "responded_at", "CompletedAt", "completed_at", "EndedAt", "ended_at"} {
		value, ok := exchange[key].(string)
		if !ok || strings.TrimSpace(value) == "" || strings.HasPrefix(value, "0001-") {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
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
	protocolPackets := map[string]uint64{}
	var rttTotal, durationWeighted float64
	var rttSamples, durationWeight uint64
	var fallbackSensors, disabledTrackingSensors int
	for _, snapshot := range snapshots {
		activeBefore := totals["udp_conversations_active"]
		packetsBefore := totals["udp_packets_total"]
		protocolPacketBefore := sumUDPProtocolPackets(protocolPackets)

		// RawMessage keeps the endpoint backward compatible with older sensors
		// that only sent numeric fields while allowing newer sensors to include
		// nested cumulative protocol counters and tracking state.
		var telemetry map[string]json.RawMessage
		if json.Unmarshal(snapshot.UDPTelemetry, &telemetry) == nil {
			var activeConversations uint64
			if raw, ok := telemetry["udp_conversation_tracking_enabled"]; ok {
				var enabled bool
				if json.Unmarshal(raw, &enabled) == nil && !enabled {
					disabledTrackingSensors++
				}
			}
			if raw, ok := telemetry["udp_conversations_active"]; ok {
				var value float64
				if json.Unmarshal(raw, &value) == nil && value > 0 {
					activeConversations = uint64(value)
				}
			}
			for key, raw := range telemetry {
				if key == "udp_protocol_packets_total" {
					var values map[string]uint64
					if json.Unmarshal(raw, &values) == nil {
						for protocol, packets := range values {
							protocol = strings.ToLower(strings.TrimSpace(protocol))
							if protocol != "" {
								protocolPackets[protocol] += packets
							}
						}
					}
					continue
				}
				var value float64
				if json.Unmarshal(raw, &value) != nil {
					continue
				}
				switch key {
				case "udp_average_rtt":
					// Recomputed below from actual correlated protocol exchanges. The
					// sensor field historically carried DNS RTT only, which made the
					// dashboard look like an all-UDP metric when it was not.
					continue
				case "udp_average_duration":
					durationWeighted += value * float64(activeConversations)
					durationWeight += activeConversations
				default:
					totals[key] += value
				}
			}
		}
		for _, exchange := range udpTimeline(snapshot.UDPProtocolExchanges, "") {
			if value := durationMillis(exchange, "RTT", "rtt", "ResponseTime", "response_time", "TimeToResponse"); value > 0 {
				rttTotal += value
				rttSamples++
			}
		}
		var conversations []udpconversation.Conversation
		_ = json.Unmarshal(snapshot.UDPConversations, &conversations)
		for _, conversation := range conversations {
			protocols[strings.ToLower(conversation.Protocol)]++
		}

		// A sensor can see and detect UDP even when conversation retention is
		// disabled, when an older binary predates the counters, or when its
		// conversation tracker has been reset. The topology snapshot is produced
		// independently by the flow engine, so use its current UDP edges as a
		// conservative compatibility fallback instead of rendering impossible
		// all-zero UDP KPIs next to live "New UDP communication" alerts.
		fallback := udpTopologyFallback(snapshot.Topology, snapshot.CapturedAt)
		usedFallback := false
		if totals["udp_conversations_active"] == activeBefore {
			if len(conversations) > 0 {
				totals["udp_conversations_active"] += float64(len(conversations))
			} else if fallback.Active > 0 {
				totals["udp_conversations_active"] += float64(fallback.Active)
				usedFallback = true
			}
		}
		if totals["udp_packets_total"] == packetsBefore && fallback.Packets > 0 {
			totals["udp_packets_total"] += float64(fallback.Packets)
			usedFallback = true
		}
		if sumUDPProtocolPackets(protocolPackets) == protocolPacketBefore && len(fallback.ProtocolPackets) > 0 {
			for protocol, packets := range fallback.ProtocolPackets {
				protocolPackets[protocol] += packets
			}
			usedFallback = true
		}
		if usedFallback {
			fallbackSensors++
		}
	}
	if rttSamples > 0 {
		totals["udp_average_rtt"] = rttTotal / float64(rttSamples)
	}
	if durationWeight > 0 {
		totals["udp_average_duration"] = durationWeighted / float64(durationWeight)
	}
	topProtocol := ""
	var topCount uint64
	topSource := protocolPackets
	if len(topSource) == 0 {
		// Compatibility fallback for sensors that predate cumulative protocol
		// packet counters. This may become empty between bursts, but avoids
		// breaking mixed-version deployments during rollout.
		topSource = protocols
	}
	for protocol, count := range topSource {
		if count > topCount || count == topCount && count > 0 && (topProtocol == "" || protocol < topProtocol) {
			topProtocol, topCount = protocol, count
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"totals":           totals,
		"protocols":        protocols,
		"protocol_packets": protocolPackets,
		"top_protocol":     topProtocol,
		"diagnostics": gin.H{
			"flow_fallback_sensors":     fallbackSensors,
			"tracking_disabled_sensors": disabledTrackingSensors,
		},
	})
}

type udpTopologyFallbackStats struct {
	Active          uint64
	Packets         uint64
	ProtocolPackets map[string]uint64
}

func udpTopologyFallback(raw json.RawMessage, capturedAt time.Time) udpTopologyFallbackStats {
	result := udpTopologyFallbackStats{ProtocolPackets: map[string]uint64{}}
	if len(raw) == 0 {
		return result
	}
	var graph struct {
		Edges []struct {
			Protocol string
			SrcPort  uint16
			DstPort  uint16
			Packets  uint64
			LastSeen time.Time
		}
	}
	if json.Unmarshal(raw, &graph) != nil {
		return result
	}
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}
	activeCutoff := capturedAt.Add(-2 * time.Minute)
	for _, edge := range graph.Edges {
		if !strings.EqualFold(strings.TrimSpace(edge.Protocol), "UDP") {
			continue
		}
		packets := edge.Packets
		if packets == 0 {
			packets = 1
		}
		result.Packets += packets
		protocol := classifyUDPPorts(edge.SrcPort, edge.DstPort)
		result.ProtocolPackets[protocol] += packets
		if edge.LastSeen.IsZero() || !edge.LastSeen.Before(activeCutoff) {
			result.Active++
		}
	}
	return result
}

func sumUDPProtocolPackets(values map[string]uint64) uint64 {
	var total uint64
	for _, count := range values {
		total += count
	}
	return total
}

func classifyUDPPorts(source, destination uint16) string {
	for _, port := range []uint16{source, destination} {
		switch port {
		case 53:
			return "dns"
		case 67, 68:
			return "dhcp"
		case 123:
			return "ntp"
		case 161, 162:
			return "snmp"
		case 5060:
			return "sip"
		case 443, 5684:
			return "dtls"
		case 1194:
			return "openvpn"
		case 6969:
			return "bittorrent"
		}
	}
	return "udp"
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
