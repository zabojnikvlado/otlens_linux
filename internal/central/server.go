package central

import (
	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	Repo  *Repository
	Token string
}

func (s *Server) auth(c *gin.Context) {
	if s.Token == "" {
		c.Next()
		return
	}
	got := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if got == "" || got != s.Token {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.Next()
}
func (s *Server) Router() *gin.Engine {
	r := gin.Default()
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	api := r.Group("/v1", s.auth)
	api.POST("/sensors/register", s.register)
	api.POST("/sensors/heartbeat", s.heartbeat)
	api.GET("/sensors", s.sensors)
	api.GET("/sensors/:id/sync", s.sync)
	api.POST("/rulesets", s.putRuleset)
	api.PUT("/sensors/:id/ruleset/:ruleset", s.assign)
	return r
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
	id := c.Param("id")
	rs, e := s.Repo.AssignedRuleSet(c, id)
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
func (s *Server) Start(addr string) error { return s.Router().Run(addr) }

var _ = time.Second
