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
	Timeline []map[string]any `json:"timeline,omitempty"`
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
		for _, conversation := range conversations {
			if matchUDPConversation(c, conversation) {
				result = append(result, udpConversationResult{SensorID: snapshot.SensorID, Conversation: conversation})
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
				var exchanges []map[string]any
				_ = json.Unmarshal(snapshot.UDPProtocolExchanges, &exchanges)
				timeline := make([]map[string]any, 0)
				for _, exchange := range exchanges {
					if value, _ := exchange["ConversationID"].(string); value == id {
						timeline = append(timeline, exchange)
					}
				}
				c.JSON(http.StatusOK, udpConversationResult{SensorID: snapshot.SensorID, Conversation: conversation, Timeline: timeline})
				return
			}
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "UDP conversation not found"})
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
