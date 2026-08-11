package central

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// LiveEvent is the compact browser-facing envelope used by the live
// operations stream. Data intentionally contains summaries/identifiers,
// never packet payloads, secrets, credentials, or session material.
type LiveEvent struct {
	ID       uint64      `json:"id"`
	Type     string      `json:"type"`
	Time     time.Time   `json:"time"`
	SensorID string      `json:"sensor_id,omitempty"`
	EntityID string      `json:"entity_id,omitempty"`
	Severity string      `json:"severity,omitempty"`
	Message  string      `json:"message,omitempty"`
	Data     interface{} `json:"data,omitempty"`
}

type liveSubscriber struct {
	ch chan LiveEvent
}

// LiveHub is a dependency-free SSE fan-out hub. A bounded replay buffer
// lets a reconnecting browser request missed events via Last-Event-ID.
type LiveHub struct {
	mu          sync.RWMutex
	nextID      uint64
	subscribers map[*liveSubscriber]struct{}
	replay      []LiveEvent
	replayLimit int
}

func NewLiveHub(replayLimit int) *LiveHub {
	if replayLimit <= 0 {
		replayLimit = 200
	}
	return &LiveHub{subscribers: make(map[*liveSubscriber]struct{}), replayLimit: replayLimit}
}

func (h *LiveHub) Publish(event LiveEvent) {
	if h == nil || event.Type == "" {
		return
	}
	h.mu.Lock()
	h.nextID++
	event.ID = h.nextID
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	h.replay = append(h.replay, event)
	if len(h.replay) > h.replayLimit {
		h.replay = append([]LiveEvent(nil), h.replay[len(h.replay)-h.replayLimit:]...)
	}
	subscribers := make([]*liveSubscriber, 0, len(h.subscribers))
	for sub := range h.subscribers {
		subscribers = append(subscribers, sub)
	}
	h.mu.Unlock()

	for _, sub := range subscribers {
		select {
		case sub.ch <- event:
		default:
			// A slow browser must not block telemetry ingestion. The next
			// periodic refresh and replay-on-reconnect restore consistency.
		}
	}
}

func (h *LiveHub) ClearReplay() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.replay = nil
	h.mu.Unlock()
}

func (h *LiveHub) subscribe(after uint64) (*liveSubscriber, []LiveEvent) {
	sub := &liveSubscriber{ch: make(chan LiveEvent, 64)}
	h.mu.Lock()
	h.subscribers[sub] = struct{}{}
	replay := make([]LiveEvent, 0)
	for _, event := range h.replay {
		if event.ID > after {
			replay = append(replay, event)
		}
	}
	h.mu.Unlock()
	return sub, replay
}

func (h *LiveHub) unsubscribe(sub *liveSubscriber) {
	h.mu.Lock()
	delete(h.subscribers, sub)
	h.mu.Unlock()
}

func (s *Server) liveHub() *LiveHub {
	s.liveOnce.Do(func() { s.live = NewLiveHub(250) })
	return s.live
}

func (s *Server) publishLive(event LiveEvent) {
	s.liveHub().Publish(event)
}

func liveEventView(event LiveEvent) string {
	t := event.Type
	switch {
	case t == "stream.ready":
		return ""
	case strings.HasPrefix(t, "alert."), strings.HasPrefix(t, "threat-intel."), strings.HasPrefix(t, "malware."):
		return ViewAlerts
	case strings.HasPrefix(t, "incident"), strings.HasPrefix(t, "correlation."), t == "presence.changed":
		return "incidents"
	case strings.HasPrefix(t, "sensor."), strings.HasPrefix(t, "telemetry."):
		return ViewSensors
	case strings.HasPrefix(t, "asset"), strings.HasPrefix(t, "discovery."), strings.HasPrefix(t, "recon"):
		return ViewAssets
	case strings.HasPrefix(t, "topology."), strings.HasPrefix(t, "segmentation."):
		return ViewTopology
	case strings.HasPrefix(t, "rule"):
		return ViewRules
	case strings.HasPrefix(t, "analysis."):
		return ViewAnalysis
	default:
		// Unknown event families are denied by default. New publishers must
		// explicitly classify their event before it can cross an SSE boundary.
		return "__deny__"
	}
}

func canViewLiveEvent(perms Permissions, event LiveEvent) bool {
	view := liveEventView(event)
	return view == "" || (view != "__deny__" && perms.HasView(view))
}

func filterLiveEvents(perms Permissions, events []LiveEvent) []LiveEvent {
	out := make([]LiveEvent, 0, len(events))
	for _, event := range events {
		if canViewLiveEvent(perms, event) {
			out = append(out, event)
		}
	}
	return out
}

func presenceView(entity string) string {
	switch strings.ToLower(strings.TrimSpace(entity)) {
	case "incident", "incidents":
		return "incidents"
	case "asset", "assets":
		return ViewAssets
	case "sensor", "sensors":
		return ViewSensors
	case "topology":
		return ViewTopology
	default:
		return "__deny__"
	}
}

func requirePresenceView(c *gin.Context, entity string) bool {
	view := presenceView(entity)
	if view == "__deny__" || !identityFromContext(c).Permissions.HasView(view) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return false
	}
	return true
}

func writeSSE(c *gin.Context, event LiveEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.Writer, "id: %d\nevent: message\ndata: %s\n\n", event.ID, payload); err != nil {
		return err
	}
	c.Writer.Flush()
	return nil
}

func (s *Server) liveEvents(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache, no-transform")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	var after uint64
	lastEventID := strings.TrimSpace(c.GetHeader("Last-Event-ID"))
	if lastEventID != "" {
		_, _ = fmt.Sscanf(lastEventID, "%d", &after)
	}
	sub, replay := s.liveHub().subscribe(after)
	permissions := identityFromContext(c).Permissions
	// A brand-new browser connection has no Last-Event-ID. Do not replay the
	// in-memory event buffer in that case: the UI loads /live/history separately
	// for its notification center, while replaying here produced stale pop-up
	// toasts such as "Sensor connected" after a page/sensor restart. Replay is
	// only for a real SSE reconnect, where Last-Event-ID tells us what the browser
	// actually missed.
	if lastEventID == "" {
		replay = nil
	} else {
		replay = filterLiveEvents(permissions, replay)
	}
	defer s.liveHub().unsubscribe(sub)

	c.Status(http.StatusOK)
	c.Writer.Flush()
	for _, event := range replay {
		if err := writeSSE(c, event); err != nil {
			return
		}
	}
	// Initial event makes connection state visible immediately without
	// requiring a business event to occur first.
	if err := writeSSE(c, LiveEvent{ID: after, Type: "stream.ready", Time: time.Now().UTC(), Message: "live operations connected"}); err != nil {
		return
	}

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-c.Request.Context().Done():
			return
		case event := <-sub.ch:
			if !canViewLiveEvent(permissions, event) {
				continue
			}
			if err := writeSSE(c, event); err != nil {
				return
			}
		case <-keepalive.C:
			if _, err := fmt.Fprint(c.Writer, ": keepalive\n\n"); err != nil {
				return
			}
			c.Writer.Flush()
		}
	}
}

// LivePresence describes an authenticated browser currently viewing an entity.
type LivePresence struct {
	UserID   string    `json:"user_id"`
	Username string    `json:"username"`
	Entity   string    `json:"entity"`
	EntityID string    `json:"entity_id"`
	LastSeen time.Time `json:"last_seen"`
}

func (h *LiveHub) snapshot(after uint64, limit int) []LiveEvent {
	if h == nil {
		return nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]LiveEvent, 0, limit)
	for i := len(h.replay) - 1; i >= 0 && len(out) < limit; i-- {
		if h.replay[i].ID > after {
			out = append(out, h.replay[i])
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Server) liveHistory(c *gin.Context) {
	var after uint64
	_, _ = fmt.Sscanf(c.Query("after"), "%d", &after)
	limit := 100
	_, _ = fmt.Sscanf(c.Query("limit"), "%d", &limit)
	events := filterLiveEvents(identityFromContext(c).Permissions, s.liveHub().snapshot(after, limit))
	c.JSON(http.StatusOK, gin.H{"events": events})
}

func (s *Server) livePresenceUpdate(c *gin.Context) {
	var body struct {
		Entity   string `json:"entity"`
		EntityID string `json:"entity_id"`
		Active   bool   `json:"active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Entity == "" || body.EntityID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entity and entity_id are required"})
		return
	}
	if !requirePresenceView(c, body.Entity) {
		return
	}
	id := identityFromContext(c)
	key := id.UserID + "|" + body.Entity + "|" + body.EntityID
	s.livePresence.mu.Lock()
	if s.livePresence.items == nil {
		s.livePresence.items = make(map[string]LivePresence)
	}
	if body.Active {
		s.livePresence.items[key] = LivePresence{UserID: id.UserID, Username: id.Username, Entity: body.Entity, EntityID: body.EntityID, LastSeen: time.Now().UTC()}
	} else {
		delete(s.livePresence.items, key)
	}
	cutoff := time.Now().Add(-45 * time.Second)
	for k, p := range s.livePresence.items {
		if p.LastSeen.Before(cutoff) {
			delete(s.livePresence.items, k)
		}
	}
	list := make([]LivePresence, 0)
	for _, p := range s.livePresence.items {
		if p.Entity == body.Entity && p.EntityID == body.EntityID {
			list = append(list, p)
		}
	}
	s.livePresence.mu.Unlock()
	s.publishLive(LiveEvent{Type: "presence.changed", EntityID: body.EntityID, Message: "analyst presence changed", Data: gin.H{"entity": body.Entity, "presence": list}})
	c.JSON(http.StatusOK, gin.H{"presence": list})
}

func (s *Server) livePresenceList(c *gin.Context) {
	entity, entityID := strings.TrimSpace(c.Query("entity")), strings.TrimSpace(c.Query("entity_id"))
	if entity == "" || entityID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entity and entity_id are required"})
		return
	}
	if !requirePresenceView(c, entity) {
		return
	}
	cutoff := time.Now().Add(-45 * time.Second)
	list := make([]LivePresence, 0)
	s.livePresence.mu.Lock()
	for k, p := range s.livePresence.items {
		if p.LastSeen.Before(cutoff) {
			delete(s.livePresence.items, k)
			continue
		}
		if (entity == "" || p.Entity == entity) && (entityID == "" || p.EntityID == entityID) {
			list = append(list, p)
		}
	}
	s.livePresence.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"presence": list})
}
