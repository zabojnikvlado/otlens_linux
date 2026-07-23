package central

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

type Server struct {
	Repo            *Repository
	ManagementToken string
	SensorToken     string
	SIEMSource      string
	AuditExport     bool
	web             *http.Server
	sensorAPI       *http.Server
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
	return r
}

func (s *Server) telemetry(c *gin.Context) {
	var x management.TelemetrySnapshot
	if c.ShouldBindJSON(&x) != nil || x.SensorID == "" || len(x.Topology) == 0 || len(x.Tags) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid telemetry snapshot"})
		return
	}
	if headerID := c.GetHeader("X-OTLens-Sensor-ID"); headerID != "" && headerID != x.SensorID {
		c.JSON(http.StatusForbidden, gin.H{"error": "sensor id mismatch"})
		return
	}
	if err := s.Repo.PutTelemetry(c, x); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
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
			Nodes []map[string]interface{} `json:"Nodes"`
		}
		if json.Unmarshal(snapshot.Topology, &graph) != nil {
			continue
		}
		for _, node := range graph.Nodes {
			node["SensorID"] = snapshot.SensorID
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
	out := make([]map[string]interface{}, 0)
	for _, snapshot := range snapshots {
		var tags []map[string]interface{}
		if json.Unmarshal(snapshot.Tags, &tags) != nil {
			continue
		}
		for _, tag := range tags {
			tag["SensorID"] = snapshot.SensorID
			out = append(out, tag)
		}
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) topology(c *gin.Context) {
	snapshots, err := s.Repo.Telemetry(c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	nodes := make([]map[string]interface{}, 0)
	edges := make([]map[string]interface{}, 0)
	threshold := 10
	for _, snapshot := range snapshots {
		var graph struct {
			Nodes             []map[string]interface{} `json:"Nodes"`
			Edges             []map[string]interface{} `json:"Edges"`
			HoneypotThreshold int                      `json:"HoneypotThreshold"`
		}
		if json.Unmarshal(snapshot.Topology, &graph) != nil {
			continue
		}
		if graph.HoneypotThreshold > threshold {
			threshold = graph.HoneypotThreshold
		}
		prefix := snapshot.SensorID + "::"
		for _, node := range graph.Nodes {
			node["ID"] = prefix + fmt.Sprint(node["ID"])
			node["SensorID"] = snapshot.SensorID
			nodes = append(nodes, node)
		}
		for _, edge := range graph.Edges {
			edge["ID"] = prefix + fmt.Sprint(edge["ID"])
			edge["SensorID"] = snapshot.SensorID
			edge["SrcNodeID"] = prefix + fmt.Sprint(edge["SrcIP"])
			edge["DstNodeID"] = prefix + fmt.Sprint(edge["DstIP"])
			edges = append(edges, edge)
		}
	}
	c.JSON(http.StatusOK, gin.H{"Nodes": nodes, "Edges": edges, "HoneypotThreshold": threshold})
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
