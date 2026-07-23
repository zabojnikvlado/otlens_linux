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
	api := r.Group("/v1", bearerAuth(s.ManagementToken))
	api.GET("/sensors", s.sensors)
	api.GET("/assets", s.assets)
	api.GET("/topology", s.topology)
	api.GET("/tags", s.tags)
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
	if err := s.Repo.PutTelemetry(c, x.SensorID, x.CapturedAt, x.Topology, x.Tags); err != nil {
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
	rs, e := s.Repo.AssignedRuleSet(c, c.Param("id"))
	if e != nil {
		c.JSON(200, management.SyncResponse{RulesVersion: 0})
		return
	}
	c.JSON(200, management.SyncResponse{RulesVersion: rs.Version, RuleSet: rs})
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
