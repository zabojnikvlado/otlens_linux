package api

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/zabojnikvlado/otlens/internal/core"
)

// publishAudit records one audit trail entry — see
// core.EventAuditAction's doc comment for what gets recorded and by
// whom, and internal/audit for where it ends up. No-op if eventBus
// is nil — shouldn't happen in practice (internal/app always wires
// one in), but defensive rather than panicking on a nil pointer if
// that ever changes.
//
// user is read from the gin context key gin.BasicAuth sets on
// success (see auth.go) — "" if Basic Auth isn't configured at all,
// since there's no authenticated identity to attach in that case.
func (s *Server) publishAudit(c *gin.Context, action string, success bool, details map[string]string) {

	if s.eventBus == nil {
		return
	}

	user, _ := c.Get(gin.AuthUserKey)
	userStr, _ := user.(string)

	s.eventBus.Publish(
		core.Event{
			Type: core.EventAuditAction,
			Data: core.AuditEntry{
				Timestamp: time.Now(),
				Action:    action,
				SourceIP:  c.ClientIP(),
				User:      userStr,
				Success:   success,
				Details:   details,
			},
		},
	)
}
