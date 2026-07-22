package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/zabojnikvlado/otlens/internal/logger"
	"go.uber.org/zap"
)

// registerAdminRoutes wires up capture start/stop control and manual
// pcap upload/analysis. Start/stop/status work in both npcap and
// ipfix mode (via the shared dataSource interface — see server.go);
// AnalyzeFile (uploading a saved pcap) is capture.Engine-specific and
// stays npcap-only, since analyzing a packet capture file doesn't
// have an ipfix equivalent.
func (s *Server) registerAdminRoutes(r *gin.Engine) {

	r.GET(
		"/admin/capture/status",
		func(c *gin.Context) {

			running := s.dataSource != nil && s.dataSource.IsRunning()

			c.JSON(
				http.StatusOK,
				gin.H{
					"mode":    s.cfg.CaptureMode,
					"running": running,
				},
			)

		},
	)

	r.POST(
		"/admin/capture/stop",
		func(c *gin.Context) {

			if s.dataSource == nil {

				c.JSON(
					http.StatusConflict,
					gin.H{"error": "no active data source to stop"},
				)

				return
			}

			s.dataSource.Stop()

			s.publishAudit(c, "admin.capture.stop", true, nil)

			c.JSON(http.StatusOK, gin.H{"running": false})

		},
	)

	r.POST(
		"/admin/capture/start",
		func(c *gin.Context) {

			if s.dataSource == nil {

				c.JSON(
					http.StatusConflict,
					gin.H{"error": "no active data source to start"},
				)

				return
			}

			if s.dataSource.IsRunning() {

				c.JSON(
					http.StatusConflict,
					gin.H{"error": "already running"},
				)

				return
			}

			go func() {

				if err := s.dataSource.Start(); err != nil {

					logger.Log.Warn(
						"Restarting data source failed",
						zap.Error(err),
					)
				}

			}()

			s.publishAudit(c, "admin.capture.start", true, nil)

			c.JSON(http.StatusOK, gin.H{"running": true})

		},
	)

	r.POST(
		"/admin/capture/analyze",
		func(c *gin.Context) {

			if s.captureEngine == nil {

				c.JSON(
					http.StatusConflict,
					gin.H{"error": "manual pcap analysis is only available in npcap mode"},
				)

				return
			}

			if s.captureEngine.IsRunning() {

				c.JSON(
					http.StatusConflict,
					gin.H{"error": "stop live capture before analyzing an uploaded file"},
				)

				return
			}

			fileHeader, err := c.FormFile("file")

			if err != nil {

				c.JSON(
					http.StatusBadRequest,
					gin.H{"error": "no file uploaded (expected multipart field \"file\")"},
				)

				return
			}

			// A project-relative directory (same convention as
			// persist.path/configs/config.yaml) rather than
			// os.TempDir() — more predictable permissions across
			// different Windows setups (some restrict the system
			// temp directory in ways that silently break
			// os.TempDir()-based writes) and easy to find/clean up.
			uploadDir := "tmp-uploads"

			if err := os.MkdirAll(uploadDir, 0o755); err != nil {

				c.JSON(
					http.StatusInternalServerError,
					gin.H{"error": fmt.Sprintf("creating upload directory %q failed: %v", uploadDir, err)},
				)

				return
			}

			tmpPath := filepath.Join(
				uploadDir,
				fmt.Sprintf("otlens-upload-%d-%s", time.Now().UnixNano(), filepath.Base(fileHeader.Filename)),
			)

			if err := c.SaveUploadedFile(fileHeader, tmpPath); err != nil {

				// The real OS error (permission denied, disk full,
				// invalid filename, ...) — a generic "saving failed"
				// message here gives no way to diagnose what
				// actually went wrong.
				c.JSON(
					http.StatusInternalServerError,
					gin.H{"error": fmt.Sprintf("saving uploaded file to %q failed: %v", tmpPath, err)},
				)

				return
			}

			defer os.Remove(tmpPath)

			count, err := s.captureEngine.AnalyzeFile(tmpPath)

			if err != nil {

				c.JSON(
					http.StatusInternalServerError,
					gin.H{"error": err.Error()},
				)

				return
			}

			s.publishAudit(
				c,
				"admin.capture.analyze",
				true,
				map[string]string{
					"filename":          filepath.Base(fileHeader.Filename),
					"packets_processed": fmt.Sprintf("%d", count),
				},
			)

			c.JSON(
				http.StatusOK,
				gin.H{"packets_processed": count},
			)

		},
	)

	r.POST(
		"/admin/wipe",
		func(c *gin.Context) {

			// Scoped to assets/flows/tags/alerts — everything the admin
			// UI's Assets/Flows/OT Tags/Alerts tabs show. Deliberately
			// NOT baseline learning state or the ARP knownMAC map (see
			// detect.Engine.Clear's doc comment) — those represent
			// "what's normal," not accumulated findings, and wiping
			// them would force learning to restart and could
			// spuriously re-flag already-known ARP mappings.
			if s.dataSource != nil && s.dataSource.IsRunning() {

				c.JSON(
					http.StatusConflict,
					gin.H{"error": "stop capture before wiping the database"},
				)

				return
			}

			s.assetEngine.Clear()
			s.flowEngine.Clear()
			s.storeEngine.Clear()
			s.detectEngine.Clear()

			// Flush immediately rather than waiting for the next
			// periodic tick, so the on-disk bbolt file reflects the
			// wipe right away instead of a stale pre-wipe snapshot
			// surviving there until the next flush interval (or,
			// worse, being what gets restored if the process
			// restarts before that tick happens).
			if err := s.snapshotter.Flush(); err != nil {

				logger.Log.Warn(
					"Flushing after database wipe failed",
					zap.Error(err),
				)
			}

			logger.Log.Warn(
				"Database wiped via admin UI (assets, flows, OT tags, alerts)",
			)

			s.publishAudit(c, "admin.wipe", true, nil)

			c.Status(http.StatusNoContent)

		},
	)

}
