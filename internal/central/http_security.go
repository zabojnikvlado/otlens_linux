package central

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const genericInternalError = "internal server error"

// securityHeaders applies a conservative browser security policy to every
// management response. The external vis-network dependency remains explicitly
// allow-listed until it can be vendored into the release artifact.
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", strings.Join([]string{
			"default-src 'self'",
			"base-uri 'self'",
			"frame-ancestors 'none'",
			"form-action 'self'",
			"object-src 'none'",
			"script-src 'self' https://unpkg.com",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data: blob:",
			"font-src 'self' data:",
			"connect-src 'self'",
			"worker-src 'self' blob:",
		}, "; "))
		c.Next()
	}
}

// respondInternalError prevents database, filesystem and configuration details
// from crossing the HTTP trust boundary. The full cause and a correlation ID
// remain in Central's server log for diagnosis.
// respondUpstreamError hides transport and parser details from remote feed
// integrations while preserving the distinction from an internal failure.
func respondUpstreamError(c *gin.Context, err error) {
	requestID := newRequestID(c)
	log.Printf("request_id=%s method=%s path=%s upstream_error=%v", requestID, c.Request.Method, c.Request.URL.Path, err)
	c.Header("X-Request-ID", requestID)
	c.JSON(http.StatusBadGateway, gin.H{"error": "upstream service error", "request_id": requestID})
}

func newRequestID(c *gin.Context) string {
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		return requestID
	}
	var b [12]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return "unavailable"
}

func respondInternalError(c *gin.Context, err error) {
	requestID := newRequestID(c)
	log.Printf("request_id=%s method=%s path=%s internal_error=%v", requestID, c.Request.Method, c.Request.URL.Path, err)
	c.Header("X-Request-ID", requestID)
	c.JSON(http.StatusInternalServerError, gin.H{"error": genericInternalError, "request_id": requestID})
}
