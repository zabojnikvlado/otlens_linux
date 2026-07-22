package api

import "github.com/gin-gonic/gin"

// corsMiddleware allows the configured origin to call this API.
// OTLens's API is read-mostly (one write action: acknowledging an
// alert) and is meant to be consumed by a browser-based dashboard
// that may well be served from a different origin/port during
// development — without this, the browser blocks every request
// before it even reaches gin's handlers.
//
// origin empty (the default) skips setting the header entirely —
// only same-origin requests work, which is what the bundled
// dashboard needs. Set api.corsorigin in config.yaml to a specific
// origin only if something else genuinely needs cross-origin access;
// avoid "*" (any origin) outside local/development use, especially
// if api.username/password aren't set — an unauthenticated API with
// wildcard CORS lets any website a visitor's browser loads read this
// API's responses.
func corsMiddleware(origin string) gin.HandlerFunc {

	return func(c *gin.Context) {

		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
