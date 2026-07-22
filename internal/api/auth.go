package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// basicAuthMiddleware requires HTTP Basic Auth credentials matching
// username/password on every request except /health — health checks
// are typically made by monitoring/orchestration tooling that has no
// way to supply credentials, and a liveness probe leaks nothing
// sensitive on its own.
//
// Only registered at all when both username and password are
// non-empty — see server.go's Start(). gin.BasicAuth does a
// constant-time comparison internally (via subtle.ConstantTimeCompare
// through its own accounts map lookup), so this doesn't need its own
// timing-safe comparison on top.
//
// A method on *Server (rather than a free function, like it used to
// be) so it can publish an "auth.failed" audit entry — see audit.go
// — on a rejected attempt, without needing its own separate way to
// reach the event bus.
func (s *Server) basicAuthMiddleware(username, password string) gin.HandlerFunc {

	auth := gin.BasicAuth(gin.Accounts{username: password})

	return func(c *gin.Context) {

		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		auth(c)

		// gin.BasicAuth calls c.AbortWithStatus(401) itself on a
		// mismatch (and never reaches c.Next()) — checking the
		// response status after calling it is how to tell a failure
		// happened from out here, since it doesn't return anything
		// itself to check directly.
		if c.IsAborted() && c.Writer.Status() == http.StatusUnauthorized {

			s.publishAudit(
				c,
				"auth.failed",
				false,
				map[string]string{"path": c.Request.URL.Path},
			)
		}
	}
}
