package central

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"github.com/zabojnikvlado/otlens_linux/internal/topology"
)

type Server struct {
	Repo             *Repository
	ManagementToken  string
	SensorToken      string
	SIEMSource       string
	AuditExport      bool
	AnalysisEnabled  bool
	AnalysisDir      string
	AnalysisMaxBytes int64
	web              *http.Server
	sensorAPI        *http.Server

	// topoCache holds the last built /topology response keyed by a
	// fingerprint of every sensor's telemetry sequence number. As long as
	// no sensor has posted new telemetry, repeated polls (the UI polls
	// every few seconds) are served straight from this cache instead of
	// re-fetching and re-decoding every sensor's topology JSONB blob —
	// which is the expensive part on a large network. See s.topology.
	topoCache struct {
		mu          sync.Mutex
		fingerprint string
		etag        string
		body        []byte
	}
}

func bearerAuth(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if token == "" {
			c.Next()
			return
		}
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		got := strings.TrimPrefix(auth, "Bearer ")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

func (s *Server) auditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
			return
		}
		started := time.Now().UTC()
		c.Next()
		if !s.AuditExport || s.Repo == nil {
			return
		}
		source := s.SIEMSource
		if source == "" {
			source = "otlens-central"
		}
		entry := map[string]interface{}{
			"source":     source,
			"kind":       "audit",
			"event_time": started,
			"audit": map[string]interface{}{
				"action":     method + " " + c.FullPath(),
				"method":     method,
				"path":       c.Request.URL.Path,
				"status":     c.Writer.Status(),
				"success":    c.Writer.Status() < 400,
				"source_ip":  c.ClientIP(),
				"user_agent": c.Request.UserAgent(),
				"sensor_id":  c.Param("id"),
				"rule_id":    c.Param("rule"),
				"ruleset_id": c.Param("ruleset"),
			},
		}
		key := fmt.Sprintf("audit:%d:%s:%s:%d", started.UnixNano(), method, c.Request.URL.Path, c.Writer.Status())
		if err := s.Repo.EnqueueSIEM(c, key, "audit", entry); err != nil {
			fmt.Fprintf(os.Stderr, "OTLens Central audit enqueue failed: %v\n", err)
		}
	}
}

func (s *Server) WebRouter() *gin.Engine {
	r := gin.Default()
	webDir := centralWebDir()
	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/ui/") })
	r.GET("/ui", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/ui/") })
	if info, err := os.Stat(webDir); err == nil && info.IsDir() {
		r.StaticFS("/ui", http.Dir(webDir))
	} else {
		r.GET("/ui/", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "web UI directory not found",
				"web_dir": webDir,
			})
		})
	}
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	api := r.Group("/v1", bearerAuth(s.ManagementToken), s.auditMiddleware())
	api.GET("/sensors", s.sensors)
	api.POST("/sensors/actions", s.sensorActions)
	api.GET("/assets", s.assets)
	api.GET("/topology", s.topology)
	api.GET("/tags", s.tags)
	api.GET("/tags/changes", s.tagChanges)
	api.GET("/tags/events", s.tagEvents)
	api.GET("/alerts", s.alerts)
	api.GET("/baseline", s.baseline)
	api.GET("/rules", s.rules)
	api.POST("/sensors/:id/rules", s.createRule)
	api.PUT("/sensors/:id/rules/:rule", s.replaceRule)
	api.PATCH("/sensors/:id/rules/:rule", s.updateRule)
	api.DELETE("/sensors/:id/rules/:rule", s.deleteRule)
	api.POST("/sensors/:id/rules/test", s.testRule)
	api.POST("/rules/import", s.importRules)
	api.GET("/rules/export", s.exportRules)
	api.POST("/sensors/:id/assets/actions", s.assetActions)
	api.POST("/sensors/:id/alerts/actions", s.alertActions)
	api.POST("/rulesets", s.putRuleset)
	api.PUT("/sensors/:id/ruleset/:ruleset", s.assign)
	api.GET("/analysis/jobs", s.analysisJobs)
	api.POST("/analysis/jobs", s.createAnalysisJob)
	api.DELETE("/analysis/jobs/:job", s.deleteAnalysisJob)
	api.GET("/data/backups", s.listBackups)
	api.POST("/data/backups", s.createBackup)
	api.GET("/data/backups/:backup/download", s.downloadBackup)
	api.DELETE("/data/backups/:backup", s.deleteBackup)
	api.POST("/data/reset", s.resetData)
	return r
}

func (s *Server) SensorRouter() *gin.Engine {
	r := gin.Default()
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	api := r.Group("/v1", bearerAuth(s.SensorToken))
	api.POST("/sensors/register", s.register)
	api.POST("/sensors/heartbeat", s.heartbeat)
	api.POST("/sensors/telemetry", s.telemetry)
	api.GET("/sensors/:id/sync", s.sync)
	api.GET("/sensors/:id/analysis/jobs/next", s.nextAnalysisJob)
	api.GET("/sensors/:id/analysis/jobs/:job/pcap", s.downloadAnalysisPCAP)
	api.POST("/sensors/:id/analysis/jobs/:job/result", s.analysisResult)
	return r
}

func (s *Server) telemetry(c *gin.Context) {
	var x management.TelemetrySnapshot
	// Empty telemetry arrays are valid after a reset or on a newly deployed
	// sensor. Requiring at least one topology node and one tag made Central
	// reject the first post-reset snapshot and left the UI permanently empty.
	if c.ShouldBindJSON(&x) != nil || strings.TrimSpace(x.SensorID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid telemetry snapshot"})
		return
	}
	if headerID := c.GetHeader("X-OTLens-Sensor-ID"); headerID != "" && headerID != x.SensorID {
		c.JSON(http.StatusForbidden, gin.H{"error": "sensor id mismatch"})
		return
	}
	if x.Sequence <= 0 || strings.TrimSpace(x.BatchID) == "" || strings.TrimSpace(x.Checksum) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "telemetry batch metadata is required"})
		return
	}
	checksumInput := x
	checksumInput.Checksum = ""
	payload, err := json.Marshal(checksumInput)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid telemetry payload"})
		return
	}
	sum := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), x.Checksum) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "telemetry checksum mismatch"})
		return
	}
	if err := s.Repo.PutTelemetry(c, x); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, management.TelemetryAck{Accepted: true, BatchID: x.BatchID, AcceptedSequence: x.Sequence, StoredAt: time.Now().UTC()})
}

func (s *Server) assets(c *gin.Context) {
	snapshots, err := s.Repo.Telemetry(c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	out := make([]map[string]interface{}, 0)
	for _, snapshot := range snapshots {
		var graph struct {
			Nodes             []map[string]interface{} `json:"Nodes"`
			HoneypotThreshold int                      `json:"HoneypotThreshold"`
		}
		if json.Unmarshal(snapshot.Topology, &graph) != nil {
			continue
		}
		threshold := graph.HoneypotThreshold
		if threshold <= 0 {
			threshold = 100
		}
		for _, node := range graph.Nodes {
			node["SensorID"] = snapshot.SensorID
			score, _ := strconv.Atoi(fmt.Sprint(node["Score"]))
			node["HoneypotThreshold"] = threshold
			node["IsHoneypot"] = score >= threshold
			out = append(out, node)
		}
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) tags(c *gin.Context) {
	snapshots, err := s.Repo.Telemetry(c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// The main OT Tags table represents current tag state, not individual
	// observations. Keep one row per sensor + stable tag key. Older sensor
	// versions could emit repeated entries for the same register, so Central
	// also deduplicates defensively.
	unique := make(map[string]map[string]interface{})
	order := make([]string, 0)
	for _, snapshot := range snapshots {
		var tags []map[string]interface{}
		if json.Unmarshal(snapshot.Tags, &tags) != nil {
			continue
		}
		for _, tag := range tags {
			tag["SensorID"] = snapshot.SensorID
			stableKey := strings.TrimSpace(fmt.Sprint(tag["Key"]))
			if stableKey == "" {
				stableKey = fmt.Sprintf("%v|%v|%v|%v|%v", tag["DeviceIP"], tag["DevicePort"], tag["Protocol"], tag["AddressSpace"], tag["Address"])
			}
			key := snapshot.SensorID + "::" + stableKey
			if _, exists := unique[key]; !exists {
				order = append(order, key)
			}
			unique[key] = tag
		}
	}
	out := make([]map[string]interface{}, 0, len(order))
	for _, key := range order {
		out = append(out, unique[key])
	}
	c.JSON(http.StatusOK, out)
}

// topologyNode/topologyEdge are the wire shape the Central UI's Topology
// tab consumes. They embed the sensor's own topology.Node/Edge (typed
// structs, not map[string]interface{} — decoding straight into concrete
// types is materially cheaper than generic-map decoding once a graph has
// more than a few hundred nodes/edges) plus the handful of fields Central
// adds on aggregation across sensors.
type topologyNode struct {
	topology.Node
	SensorID          string `json:"SensorID"`
	HoneypotThreshold int    `json:"HoneypotThreshold"`
	IsHoneypot        bool   `json:"IsHoneypot"`
}

type topologyEdge struct {
	topology.Edge
	SensorID  string `json:"SensorID"`
	SrcNodeID string `json:"SrcNodeID"`
	DstNodeID string `json:"DstNodeID"`
}

// buildTopologyResponse fetches every sensor's stored topology JSONB and
// aggregates it into one graph. This is the expensive path (JSONB fetch +
// JSON decode for potentially large per-sensor graphs) — s.topology only
// calls this when the fingerprint shows something actually changed.
func (s *Server) buildTopologyResponse(c *gin.Context) ([]byte, error) {
	rows, err := s.Repo.TelemetryTopology(c)
	if err != nil {
		return nil, err
	}
	nodes := make([]topologyNode, 0)
	edges := make([]topologyEdge, 0)
	for _, row := range rows {
		var graph topology.Graph
		if json.Unmarshal(row.Topology, &graph) != nil {
			continue
		}
		sensorThreshold := graph.HoneypotThreshold
		if sensorThreshold <= 0 {
			sensorThreshold = 100
		}
		prefix := row.SensorID + "::"
		for _, n := range graph.Nodes {
			n.ID = prefix + n.ID
			nodes = append(nodes, topologyNode{
				Node:              n,
				SensorID:          row.SensorID,
				HoneypotThreshold: sensorThreshold,
				IsHoneypot:        n.Score >= sensorThreshold,
			})
		}
		for _, e := range graph.Edges {
			srcIP, dstIP := e.SrcIP, e.DstIP
			e.ID = prefix + e.ID
			edges = append(edges, topologyEdge{
				Edge:      e,
				SensorID:  row.SensorID,
				SrcNodeID: prefix + srcIP,
				DstNodeID: prefix + dstIP,
			})
		}
	}
	return json.Marshal(gin.H{"Nodes": nodes, "Edges": edges, "HoneypotThreshold": 100})
}

// topologyFingerprint hashes every sensor's telemetry sequence number into
// a single stable string. It changes if and only if at least one sensor
// has posted new telemetry since the last call — this is what lets
// s.topology skip the expensive rebuild (and lets the browser skip
// re-downloading/re-rendering) when nothing changed in the database.
func topologyFingerprint(seqBySensor map[string]int64) string {
	ids := make([]string, 0, len(seqBySensor))
	for id := range seqBySensor {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		fmt.Fprintf(h, "%s=%d;", id, seqBySensor[id])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) topology(c *gin.Context) {
	seq, err := s.Repo.TelemetryFingerprint(c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	fingerprint := topologyFingerprint(seq)

	s.topoCache.mu.Lock()
	cacheHit := s.topoCache.body != nil && s.topoCache.fingerprint == fingerprint
	etag := s.topoCache.etag
	body := s.topoCache.body
	s.topoCache.mu.Unlock()

	if !cacheHit {
		// Something changed on at least one sensor since the last poll —
		// this is the only path that actually fetches+decodes topology
		// JSONB, so an idle network with no new telemetry never pays it.
		newBody, err := s.buildTopologyResponse(c)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		etag = `"` + fingerprint + `"`
		body = newBody
		s.topoCache.mu.Lock()
		s.topoCache.fingerprint = fingerprint
		s.topoCache.etag = etag
		s.topoCache.body = body
		s.topoCache.mu.Unlock()
	}

	// Regardless of whether we just rebuilt or served the cache, honor
	// conditional GETs: if the browser already has this exact fingerprint
	// (it sends back the ETag we gave it last time), it doesn't need the
	// body at all — this is the "draw the graph once, don't touch it
	// again while it's unchanged in the database" behavior on the wire.
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-cache")
	if match := c.GetHeader("If-None-Match"); match != "" && match == etag {
		c.Status(http.StatusNotModified)
		return
	}
	c.Data(http.StatusOK, "application/json", body)
}

func aggregateRaw(c *gin.Context, snapshots []management.TelemetrySnapshot, pick func(management.TelemetrySnapshot) json.RawMessage) {
	out := make([]map[string]interface{}, 0)
	for _, snapshot := range snapshots {
		var rows []map[string]interface{}
		if json.Unmarshal(pick(snapshot), &rows) != nil {
			continue
		}
		for _, row := range rows {
			row["SensorID"] = snapshot.SensorID
			out = append(out, row)
		}
	}
	c.JSON(http.StatusOK, out)
}
func (s *Server) tagChanges(c *gin.Context) {
	v, e := s.Repo.Telemetry(c)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	aggregateRaw(c, v, func(x management.TelemetrySnapshot) json.RawMessage { return x.TagChanges })
}
func (s *Server) tagEvents(c *gin.Context) {
	v, e := s.Repo.Telemetry(c)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	aggregateRaw(c, v, func(x management.TelemetrySnapshot) json.RawMessage { return x.TagEvents })
}
func (s *Server) alerts(c *gin.Context) {
	v, e := s.Repo.Telemetry(c)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	aggregateRaw(c, v, func(x management.TelemetrySnapshot) json.RawMessage { return x.Alerts })
}
func (s *Server) rules(c *gin.Context) {
	v, e := s.Repo.Telemetry(c)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	aggregateRaw(c, v, func(x management.TelemetrySnapshot) json.RawMessage { return x.Rules })
}

func validateManagementRule(req *management.Rule) error {
	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if req.Kind == "" {
		req.Kind = "custom"
	}
	if req.Kind != "custom" {
		return fmt.Errorf("only custom rules can be created")
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}
	if req.Priority == 0 {
		req.Priority = 100
	}
	if req.Version == 0 {
		req.Version = 1
	}
	if req.GroupOperator == "" {
		req.GroupOperator = "AND"
	}
	if len(req.Groups) == 0 && strings.TrimSpace(req.Field) != "" {
		req.Groups = []management.RuleGroup{{Operator: "AND", Conditions: []management.RuleCondition{{Field: req.Field, Operator: "eq", Value: req.Value}}}}
	}
	if len(req.Groups) == 0 {
		return fmt.Errorf("at least one condition is required")
	}
	for _, group := range req.Groups {
		if len(group.Conditions) == 0 {
			return fmt.Errorf("condition group is empty")
		}
		for _, condition := range group.Conditions {
			if strings.TrimSpace(condition.Field) == "" || strings.TrimSpace(condition.Operator) == "" || strings.TrimSpace(condition.Value) == "" {
				return fmt.Errorf("each condition requires field, operator and value")
			}
		}
	}
	if len(req.Actions) == 0 {
		req.Actions = []management.RuleAction{{Type: "alert"}}
	}
	if req.Suppression.Mode == "" {
		req.Suppression.Mode = "aggregate"
	}
	return nil
}

func (s *Server) replaceRule(c *gin.Context) {
	var req management.Rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule"})
		return
	}
	req.ID = c.Param("rule")
	if err := validateManagementRule(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Version++
	payload, _ := json.Marshal(req)
	if err := s.Repo.QueueCommands(c, c.Param("id"), "rule.upsert", []string{string(payload)}); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, req)
}

func (s *Server) testRule(c *gin.Context) {
	var req management.Rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule"})
		return
	}
	if err := validateManagementRule(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"valid":      true,
		"simulation": true,
		"message":    "Rule is valid. Save it in simulation mode to measure live matches without generating alerts.",
		"conditions": func() int {
			n := 0
			for _, g := range req.Groups {
				n += len(g.Conditions)
			}
			return n
		}(),
	})
}

func (s *Server) importRules(c *gin.Context) {
	var req struct {
		SensorID string            `json:"sensor_id"`
		Rules    []management.Rule `json:"rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.SensorID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sensor_id and rules are required"})
		return
	}
	payloads := make([]string, 0, len(req.Rules))
	for i := range req.Rules {
		if err := validateManagementRule(&req.Rules[i]); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("rule %d: %v", i+1, err)})
			return
		}
		data, _ := json.Marshal(req.Rules[i])
		payloads = append(payloads, string(data))
	}
	if err := s.Repo.QueueCommands(c, req.SensorID, "rule.add", payloads); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"queued": len(payloads)})
}

func (s *Server) exportRules(c *gin.Context) {
	v, err := s.Repo.Telemetry(c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	result := make([]map[string]interface{}, 0)
	for _, snapshot := range v {
		var rows []map[string]interface{}
		if json.Unmarshal(snapshot.Rules, &rows) != nil {
			continue
		}
		for _, row := range rows {
			row["SensorID"] = snapshot.SensorID
			result = append(result, row)
		}
	}
	c.Header("Content-Disposition", "attachment; filename=otlens-rules.json")
	c.JSON(http.StatusOK, gin.H{"format": "otlens-policy-v1", "exported_at": time.Now().UTC(), "rules": result})
}

func (s *Server) createRule(c *gin.Context) {
	var req management.Rule
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule"})
		return
	}
	if err := validateManagementRule(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	payload, err := json.Marshal(req)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if err := s.Repo.QueueCommands(c, c.Param("id"), "rule.add", []string{string(payload)}); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusAccepted)
}

func (s *Server) updateRule(c *gin.Context) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if c.ShouldBindJSON(&req) != nil || req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled is required"})
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{"id": c.Param("rule"), "enabled": *req.Enabled})
	if err := s.Repo.QueueCommands(c, c.Param("id"), "rule.toggle", []string{string(payload)}); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusAccepted)
}

func (s *Server) deleteRule(c *gin.Context) {
	if err := s.Repo.QueueCommands(c, c.Param("id"), "rule.delete", []string{c.Param("rule")}); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusAccepted)
}

func (s *Server) baseline(c *gin.Context) {
	v, e := s.Repo.Telemetry(c)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	out := make([]map[string]interface{}, 0)
	for _, x := range v {
		var row map[string]interface{}
		if json.Unmarshal(x.Baseline, &row) == nil {
			row["SensorID"] = x.SensorID
			out = append(out, row)
		}
	}
	c.JSON(200, out)
}
func (s *Server) assetActions(c *gin.Context) {
	var req struct {
		Action  string   `json:"action"`
		Targets []string `json:"targets"`
	}
	if c.ShouldBindJSON(&req) != nil || (req.Action != "confirm" && req.Action != "delete") {
		c.JSON(400, gin.H{"error": "invalid action"})
		return
	}
	if err := s.Repo.QueueCommands(c, c.Param("id"), "asset."+req.Action, req.Targets); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Status(202)
}
func (s *Server) alertActions(c *gin.Context) {
	var req struct {
		Action  string   `json:"action"`
		Targets []string `json:"targets"`
	}
	if c.ShouldBindJSON(&req) != nil || (req.Action != "approve" && req.Action != "confirm") {
		c.JSON(400, gin.H{"error": "invalid action"})
		return
	}
	if err := s.Repo.QueueCommands(c, c.Param("id"), "alert."+req.Action, req.Targets); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Status(202)
}
func (s *Server) register(c *gin.Context) {
	var x management.SensorRegistration
	if c.ShouldBindJSON(&x) != nil || x.ID == "" {
		c.JSON(400, gin.H{"error": "invalid registration"})
		return
	}
	if err := s.Repo.RegisterSensor(c, x); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"sensor_id": x.ID, "status": "registered"})
}
func (s *Server) heartbeat(c *gin.Context) {
	var x management.Heartbeat
	if c.ShouldBindJSON(&x) != nil || x.SensorID == "" {
		c.JSON(400, gin.H{"error": "invalid heartbeat"})
		return
	}
	if err := s.Repo.Heartbeat(c, x); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Status(204)
}

func (s *Server) sensorActions(c *gin.Context) {
	var request struct {
		Action    string   `json:"action"`
		SensorIDs []string `json:"sensor_ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || len(request.SensorIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action and sensor_ids are required"})
		return
	}
	var commandType string
	switch strings.ToLower(strings.TrimSpace(request.Action)) {
	case "start":
		commandType = "sensor.capture.start"
	case "stop":
		commandType = "sensor.capture.stop"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be start or stop"})
		return
	}
	queued := 0
	seen := make(map[string]struct{}, len(request.SensorIDs))
	for _, sensorID := range request.SensorIDs {
		sensorID = strings.TrimSpace(sensorID)
		if sensorID == "" {
			continue
		}
		if _, exists := seen[sensorID]; exists {
			continue
		}
		seen[sensorID] = struct{}{}
		if err := s.Repo.QueueCommands(c, sensorID, commandType, []string{sensorID}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		queued++
	}
	if queued == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid sensor IDs"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"queued": queued, "action": request.Action})
}

func (s *Server) sensors(c *gin.Context) {
	v, e := s.Repo.ListSensors(c)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	c.JSON(200, v)
}
func (s *Server) sync(c *gin.Context) {
	commands, _ := s.Repo.PopCommands(c, c.Param("id"))
	rs, e := s.Repo.AssignedRuleSet(c, c.Param("id"))
	if e != nil {
		c.JSON(200, management.SyncResponse{RulesVersion: 0, Commands: commands})
		return
	}
	c.JSON(200, management.SyncResponse{RulesVersion: rs.Version, RuleSet: rs, Commands: commands})
}
func (s *Server) putRuleset(c *gin.Context) {
	var rs management.RuleSet
	if c.ShouldBindJSON(&rs) != nil || rs.ID == "" {
		c.JSON(400, gin.H{"error": "invalid ruleset"})
		return
	}
	if err := s.Repo.PutRuleSet(c, rs); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	out, e := s.Repo.GetRuleSet(c, rs.ID)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	c.JSON(200, out)
}
func (s *Server) assign(c *gin.Context) {
	if err := s.Repo.AssignRuleSet(c, c.Param("id"), c.Param("ruleset")); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Status(204)
}
func tlsConfig(minVersion uint16, cipherSuites []uint16) *tls.Config {
	cfg := &tls.Config{MinVersion: minVersion}
	if len(cipherSuites) > 0 {
		cfg.CipherSuites = cipherSuites
	}
	return cfg
}
func (s *Server) StartWeb(addr string, tlsEnabled bool, certFile, keyFile string, minVersion uint16, cipherSuites []uint16) error {
	s.web = &http.Server{Addr: addr, Handler: s.WebRouter(), ReadHeaderTimeout: 10 * time.Second}
	if tlsEnabled {
		s.web.TLSConfig = tlsConfig(minVersion, cipherSuites)
		return s.web.ListenAndServeTLS(certFile, keyFile)
	}
	return s.web.ListenAndServe()
}
func (s *Server) StartSensorAPI(addr string, tlsEnabled bool, certFile, keyFile string, minVersion uint16, cipherSuites []uint16) error {
	s.sensorAPI = &http.Server{Addr: addr, Handler: s.SensorRouter(), ReadHeaderTimeout: 10 * time.Second}
	if tlsEnabled {
		s.sensorAPI.TLSConfig = tlsConfig(minVersion, cipherSuites)
		return s.sensorAPI.ListenAndServeTLS(certFile, keyFile)
	}
	return s.sensorAPI.ListenAndServe()
}
func (s *Server) Shutdown(ctx context.Context) error {
	var first error
	if s.web != nil {
		if err := s.web.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			first = err
		}
	}
	if s.sensorAPI != nil {
		if err := s.sensorAPI.Shutdown(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func centralWebDir() string {
	if p := os.Getenv("OTLENS_CENTRAL_WEB_DIR"); p != "" {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "web", "central")
	}
	return filepath.Join("web", "central")
}

func randomAnalysisID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("analysis-%d", time.Now().UnixNano())
	}
	return "analysis-" + hex.EncodeToString(b)
}

func (s *Server) analysisJobs(c *gin.Context) {
	jobs, err := s.Repo.ListAnalysisJobs(c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, jobs)
}

func (s *Server) createAnalysisJob(c *gin.Context) {
	if !s.AnalysisEnabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "PCAP analysis is disabled"})
		return
	}
	if err := c.Request.ParseMultipartForm(s.AnalysisMaxBytes); err != nil {
		c.JSON(400, gin.H{"error": "invalid multipart upload: " + err.Error()})
		return
	}
	sensorID := strings.TrimSpace(c.PostForm("sensor_id"))
	if sensorID == "" {
		c.JSON(400, gin.H{"error": "sensor_id is required"})
		return
	}
	file, header, err := c.Request.FormFile("pcap")
	if err != nil {
		c.JSON(400, gin.H{"error": "pcap file is required"})
		return
	}
	defer file.Close()
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".pcap" && ext != ".pcapng" {
		c.JSON(400, gin.H{"error": "only .pcap and .pcapng files are allowed"})
		return
	}
	if s.AnalysisMaxBytes <= 0 {
		s.AnalysisMaxBytes = 2 << 30
	}
	lr := http.MaxBytesReader(c.Writer, file, s.AnalysisMaxBytes)
	if err := os.MkdirAll(s.AnalysisDir, 0700); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	id := randomAnalysisID()
	path := filepath.Join(s.AnalysisDir, id+ext)
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), lr)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(path)
		c.JSON(400, gin.H{"error": "upload failed or exceeds configured limit"})
		return
	}
	magic := make([]byte, 4)
	f, _ := os.Open(path)
	if f != nil {
		_, _ = io.ReadFull(f, magic)
		_ = f.Close()
	}
	valid := bytes.Equal(magic, []byte{0xd4, 0xc3, 0xb2, 0xa1}) || bytes.Equal(magic, []byte{0xa1, 0xb2, 0xc3, 0xd4}) || bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a})
	if !valid {
		_ = os.Remove(path)
		c.JSON(400, gin.H{"error": "file does not contain a valid PCAP/PCAPNG signature"})
		return
	}
	protocols := c.PostFormArray("protocols")
	if len(protocols) == 0 {
		protocols = []string{"auto", "modbus", "s7comm"}
	}
	job := management.AnalysisJob{ID: id, SensorID: sensorID, Filename: filepath.Base(header.Filename), SHA256: hex.EncodeToString(h.Sum(nil)), SizeBytes: n, Status: "queued", Protocols: protocols, CreatedAt: time.Now().UTC()}
	if err := s.Repo.CreateAnalysisJob(c, job, path); err != nil {
		_ = os.Remove(path)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, job)
}

func (s *Server) deleteAnalysisJob(c *gin.Context) {
	path, err := s.Repo.DeleteAnalysisJob(c, c.Param("job"))
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	_ = os.Remove(path)
	c.Status(204)
}

func (s *Server) nextAnalysisJob(c *gin.Context) {
	job, _, err := s.Repo.ClaimAnalysisJob(c, c.Param("id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.Status(204)
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, job)
}
func (s *Server) downloadAnalysisPCAP(c *gin.Context) {
	path, name, err := s.Repo.AnalysisJobPath(c, c.Param("job"), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "job not found"})
		return
	}
	c.FileAttachment(path, name)
}
func (s *Server) analysisResult(c *gin.Context) {
	var result management.AnalysisResult
	if c.ShouldBindJSON(&result) != nil {
		c.JSON(400, gin.H{"error": "invalid result"})
		return
	}
	if err := s.Repo.FinishAnalysisJob(c, c.Param("job"), c.Param("id"), result); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Status(204)
}

func (s *Server) resetData(c *gin.Context) {
	var req struct {
		Scope        string   `json:"scope"`
		Operation    string   `json:"operation"`
		SensorIDs    []string `json:"sensor_ids"`
		Confirmation string   `json:"confirmation"`
	}
	if c.ShouldBindJSON(&req) != nil || req.Confirmation != "RESET" {
		c.JSON(400, gin.H{"error": "confirmation RESET is required"})
		return
	}
	switch strings.ToLower(req.Scope) {
	case "central":
		op := strings.ToLower(strings.TrimSpace(req.Operation))

		// Central stores snapshots uploaded by sensors. Clearing PostgreSQL
		// alone is temporary: on the next sync every sensor uploads its still
		// populated SQLite snapshot and all data reappears. Queue the matching
		// sensor-side reset first, while preserving sensor_commands in the
		// repository reset, so the deletion is durable across the whole system.
		commandByOperation := map[string]string{
			"telemetry": "sensor.database.reset",
			"database":  "sensor.database.reset",
			"alerts":    "sensor.alerts.reset",
			"analysis":  "sensor.analysis.reset",
			"factory":   "sensor.factory.reset",
		}
		queued := 0
		if command, ok := commandByOperation[op]; ok {
			sensors, err := s.Repo.ListSensors(c)
			if err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			for _, sensor := range sensors {
				if err := s.Repo.QueueCommands(c, sensor.ID, command, []string{sensor.ID}); err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}
				queued++
			}
		}
		if err := s.Repo.ResetCentral(c, op); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(202, gin.H{"status": "reset_queued", "scope": "central", "operation": op, "sensors": queued})
	case "sensors":
		if len(req.SensorIDs) == 0 {
			c.JSON(400, gin.H{"error": "sensor_ids are required"})
			return
		}
		command := "sensor." + strings.ToLower(req.Operation) + ".reset"
		if req.Operation == "factory" {
			command = "sensor.factory.reset"
		}
		for _, id := range req.SensorIDs {
			if err := s.Repo.QueueCommands(c, strings.TrimSpace(id), command, []string{strings.TrimSpace(id)}); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
		}
		c.JSON(202, gin.H{"status": "queued", "sensors": len(req.SensorIDs), "command": command})
	default:
		c.JSON(400, gin.H{"error": "scope must be central or sensors"})
	}
}
func (s *Server) createBackup(c *gin.Context) {
	var req struct {
		Name      string   `json:"name"`
		Scope     string   `json:"scope"`
		SensorIDs []string `json:"sensor_ids"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	if req.Scope == "sensors" {
		for _, id := range req.SensorIDs {
			_ = s.Repo.QueueCommands(c, id, "sensor.backup.create", []string{func() string {
				if strings.TrimSpace(req.Name) == "" {
					return "auto"
				}
				return req.Name
			}()})
		}
		c.JSON(202, gin.H{"status": "queued", "sensors": len(req.SensorIDs)})
		return
	}
	id := fmt.Sprintf("bkp-%d", time.Now().UTC().UnixNano())
	b, err := s.Repo.CreateCentralBackup(c, id, req.Name)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, b)
}
func (s *Server) listBackups(c *gin.Context) {
	b, err := s.Repo.ListBackups(c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, b)
}
func (s *Server) deleteBackup(c *gin.Context) {
	if err := s.Repo.DeleteBackup(c, c.Param("backup")); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Status(204)
}
func (s *Server) downloadBackup(c *gin.Context) {
	b, name, err := s.Repo.BackupPayload(c, c.Param("backup"))
	if err != nil {
		c.JSON(404, gin.H{"error": "backup not found"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".json"))
	c.Data(200, "application/json", b)
}
