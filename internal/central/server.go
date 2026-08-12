package central

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"github.com/zabojnikvlado/otlens_linux/internal/topology"
	"github.com/zabojnikvlado/otlens_linux/internal/vuln"
)

type Server struct {
	StartedAt             time.Time
	Repo                  *Repository
	ManagementToken       string
	SensorToken           string
	BootstrapUsername     string
	BootstrapPasswordHash string
	SIEMEnabled           bool
	SIEMMaxAttempts       int
	AnalysisEnabled       bool
	AnalysisDir           string
	AnalysisMaxBytes      int64
	// SensorOfflineAfter/SensorCheckInterval and the TLS flags below are
	// purely for the read-only Settings tab (s.settings) — the actual
	// offline-sweep ticker and TLS listeners in main.go read the same
	// config.CentralConfig values directly, this is just so the UI can
	// show what's actually running without a second config parse.
	SensorOfflineAfter  time.Duration
	SensorCheckInterval time.Duration
	WebTLSEnabled       bool
	SensorAPITLSEnabled bool
	// SessionDuration is the sliding-expiry window for logged-in Central
	// UI sessions — see authMiddleware. Defaults to 6h (auth.session_duration).
	SessionDuration time.Duration
	// Retention is shown read-only on the Settings tab — see
	// retention.go for what it actually does.
	Retention RetentionConfig
	// Notifications drives dispatchNotifications — see notify.go.
	Notifications NotificationConfig
	// Reports drives the scheduled report pipeline — see reports.go.
	Reports ReportsConfig
	// RuntimeConfig contains only non-secret effective configuration values for the Settings UI.
	RuntimeConfig map[string]map[string]interface{}
	// Vuln is looked up by asset vendor only (see package vuln's doc
	// comment for why that's a real precision limit, not an oversight) —
	// never nil; main.go always sets it to at least an empty *vuln.Database
	// so this handler never needs its own "feature disabled" branch.
	Vuln *vuln.Database
	web  *http.Server
	// loginFailures tracks consecutive failed login attempts per
	// username, purely in-memory (reset on Central restart — that's
	// fine, this is a detection signal, not an account lockout
	// mechanism; it never blocks a login attempt). See recordLoginFailure.
	loginFailures struct {
		mu     sync.Mutex
		counts map[string]int
	}
	sensorAPI *http.Server

	liveOnce     sync.Once
	live         *LiveHub
	livePresence struct {
		mu    sync.Mutex
		items map[string]LivePresence
	}

	// incidentRefresh serializes/debounces expensive correlation+risk refreshes.
	// Telemetry can arrive every few seconds from multiple sensors; without this
	// guard each upload could start another full correlation scan concurrently.
	incidentRefresh struct {
		mu      sync.Mutex
		running bool
		last    time.Time
	}

	// dataResetMu prevents telemetry/correlation writes from racing an
	// administrator Data Management reset.
	dataResetMu sync.RWMutex

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

// serverErrorLogger logs the response body whenever a handler answers with
// a 5xx status. Central's handlers already return the real failure reason
// in the response body (respondInternalError(c, err)), but
// that only helps whoever's inspecting that specific response — a sensor
// that only logs resp.Status, or an operator who wasn't watching at the
// exact moment, never sees it. This puts it in Central's own log
// unconditionally, independent of what any particular caller does with it.
func serverErrorLogger(source string) gin.HandlerFunc {
	return func(c *gin.Context) {
		capture := &bodyCaptureWriter{ResponseWriter: c.Writer, body: &bytes.Buffer{}}
		c.Writer = capture
		c.Next()
		if status := c.Writer.Status(); status >= 500 {
			log.Printf("[%s] %s %s -> %d: %s", source, c.Request.Method, c.Request.URL.Path, status, strings.TrimSpace(capture.body.String()))
		}
	}
}

type bodyCaptureWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *bodyCaptureWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
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

// sensorAuth binds every non-enrollment Sensor API request to the sensor ID
// carried by the per-sensor token. A token issued to sensor A can therefore
// never be used against sensor B's URL or payload, even if A is compromised.
func (s *Server) sensorAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		sensorID := strings.TrimSpace(c.GetHeader("X-OTLens-Sensor-ID"))
		if paramID := strings.TrimSpace(c.Param("id")); paramID != "" {
			if sensorID != "" && sensorID != paramID {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "sensor identity mismatch"})
				return
			}
			sensorID = paramID
		}
		if sensorID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "sensor identity required"})
			return
		}
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		expected, err := s.Repo.SensorAuthTokenHash(c, sensorID)
		if err != nil || expected == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "sensor is not enrolled"})
			return
		}
		digest := sha256.Sum256([]byte(token))
		got := hex.EncodeToString(digest[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("sensor_id", sensorID)
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
		c.Next()
		if s.Repo == nil {
			return
		}
		status := c.Writer.Status()
		actor := identityFromContext(c).Username
		// Written unconditionally — this is the durable audit trail
		// (audit_log), independent of whether SIEM export happens to be
		// configured. A failure here is logged, not fatal to the
		// request: the action the person took already happened either
		// way, and audit logging shouldn't be able to break the app.
		if err := s.Repo.InsertAuditLog(c, AuditEntry{
			Actor: actor, Action: method + " " + c.FullPath(), Method: method, Path: c.Request.URL.Path,
			Status: status, Success: status < 400, SourceIP: c.ClientIP(), SensorID: c.Param("id"),
		}); err != nil {
			log.Printf("audit_log insert failed: %v", err)
		}

	}
}

func (s *Server) WebRouter() *gin.Engine {
	r := gin.Default()
	r.Use(securityHeaders())
	webDir := centralWebDir()
	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/ui/") })
	r.GET("/ui", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/ui/") })
	if info, err := os.Stat(webDir); err == nil && info.IsDir() {
		// Go's default static file server sets Last-Modified/ETag but no
		// Cache-Control, which leaves it up to each browser's own
		// heuristics whether to even ask before reusing a cached copy —
		// in practice that can mean a redeployed style.css/app.js sits
		// stale in someone's browser indefinitely. no-cache forces a
		// revalidation request on every load; the server still answers
		// with a fast 304 when the file genuinely hasn't changed, so this
		// costs a round trip, not a re-download, for the common case.
		r.Use(func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, "/ui/") {
				c.Header("Cache-Control", "no-cache")
			}
			c.Next()
		})
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

	// Login/logout are unauthenticated by definition — everything else in
	// /v1 goes through authMiddleware (session cookie, falling back to
	// the legacy management_token bearer as an emergency path).
	public := r.Group("/v1")
	public.POST("/login", s.login)
	public.POST("/logout", s.logout)

	api := r.Group("/v1", serverErrorLogger("web-api"), s.authMiddleware(), s.auditMiddleware())
	api.GET("/me", s.me)
	api.POST("/change-password", s.changePassword)

	api.GET("/sensors", requireView(ViewSensors), s.sensors)
	api.GET("/sensors/metrics", requireView(ViewSensors), s.sensorMetricsOverview)
	api.GET("/sensors/:id/metrics", requireView(ViewSensors), s.sensorMetricsHistory)
	api.GET("/healthcheck", requireView(ViewSensors), s.healthcheck)
	api.GET("/reconnaissance/credentials", requireView(ViewAssets), s.listReconCredentials)
	api.POST("/reconnaissance/credentials", requireAction(ActionDataManagement), s.createReconCredential)
	api.DELETE("/reconnaissance/credentials/:id", requireAction(ActionDataManagement), s.deleteReconCredential)
	api.GET("/reconnaissance/jobs", requireView(ViewAssets), s.listReconJobs)
	api.POST("/reconnaissance/jobs", requireAction(ActionAssetConfirmDelete), s.createReconJob)
	api.GET("/reconnaissance/campaigns", requireView(ViewAssets), s.listReconCampaigns)
	api.POST("/reconnaissance/campaigns", requireAction(ActionAssetConfirmDelete), s.createReconCampaign)
	api.POST("/reconnaissance/campaigns/:id/run", requireAction(ActionAssetConfirmDelete), s.runReconCampaign)
	api.DELETE("/reconnaissance/campaigns/:id", requireAction(ActionAssetConfirmDelete), s.deleteReconCampaign)
	api.GET("/sensors/:id/assets/:ip/recon-history", requireView(ViewAssets), s.assetReconHistory)
	api.GET("/sensors/:id/assets/:ip/alerts", requireView(ViewAssets), s.assetAlertHistory)
	api.POST("/sensors/actions", requireAction(ActionSensorStartStop), s.sensorActions)
	api.DELETE("/sensors/:id", requireAction(ActionSensorStartStop), s.deleteSensor)
	api.GET("/assets", requireView(ViewAssets), s.assets)
	api.GET("/devices", requireView(ViewAssets), s.devices)
	api.POST("/sensors/:id/assets/:mac/category", requireAction(ActionAssetConfirmDelete), s.setDeviceCategory)
	api.POST("/sensors/:id/devices/import", requireAction(ActionAssetConfirmDelete), s.importDeviceList)
	api.POST("/sensors/:id/tags/import", requireAction(ActionDataManagement), s.importTagList)
	api.GET("/assets/vulnerabilities", requireView(ViewAssets), s.assetVulnerabilities)
	api.GET("/vulnerabilities", requireView(ViewAssets), s.vulnerabilities)
	api.POST("/vulnerabilities/import", requireAction(ActionDataManagement), s.importVulnerabilities)
	api.POST("/vulnerabilities/feed", requireAction(ActionDataManagement), s.importVulnerabilityFeed)
	api.PUT("/vulnerabilities/findings", requireAction(ActionDataManagement), s.updateVulnerabilityFinding)
	api.GET("/sensors/:id/vlans", requireView(ViewTopology), s.listVLANConfig)
	api.GET("/sensors/:id/segmentation-settings", requireView(ViewTopology), s.getMaxLevelJump)
	api.PUT("/sensors/:id/vlans/:vlanid", requireAction(ActionDataManagement), s.setVLANConfig)
	api.PUT("/sensors/:id/segmentation-settings", requireAction(ActionDataManagement), s.setMaxLevelJump)
	api.GET("/sensors/:id/vlans/:vlanid/assets", requireView(ViewTopology), s.listVLANAssets)
	api.GET("/sensors/:id/assets/by-mac/:mac/ip-history", requireView(ViewAssets), s.assetIPHistory)
	api.GET("/settings", requireView(ViewSettings), s.settings)
	api.GET("/audit", requireView(ViewAudit), s.auditLog)
	api.GET("/security/permission-audit", requireAction(ActionUsersRolesManage), s.permissionAudit)
	api.GET("/data/diagnostics", requireAction(ActionDataManagement), s.diagnosticsBundle)
	api.GET("/topology", requireView(ViewTopology), s.topology)
	api.GET("/sensors/:id/purdue-topology", requireView(ViewTopology), s.purdueTopology)
	api.GET("/sensors/:id/itot-paths", requireView(ViewTopology), s.observedITOTPaths)
	api.GET("/asset-context", requireView(ViewAssets), s.assetContexts)
	api.PUT("/sensors/:id/assets/:ip/context", requireAction(ActionDataManagement), s.setAssetContext)
	api.GET("/tags", requireView(ViewTags), s.tags)
	api.GET("/dns-observations", requireView(ViewAlerts), s.dnsObservations)
	api.GET("/smb-observations", requireView(ViewAlerts), s.smbObservations)
	api.GET("/protocol-observations", requireView(ViewAlerts), s.protocolObservations)
	api.GET("/udp-conversations", requireView(ViewAlerts), s.udpConversations)
	api.GET("/udp-conversations/:id", requireView(ViewAlerts), s.udpConversation)
	api.GET("/udp-telemetry", requireView(ViewDashboard), s.udpTelemetry)
	api.GET("/behavior-findings", requireView(ViewAlerts), s.behaviorFindings)
	api.GET("/behavior-findings/:id", requireView(ViewAlerts), s.behaviorFinding)
	api.GET("/behavior-overview", behaviorReadAccess(), s.behaviorOverview)
	api.GET("/threat-intel/sources", requireView(ViewAlerts), s.listThreatIntelSources)
	api.POST("/threat-intel/sources", requireAction(ActionDataManagement), s.createThreatIntelSource)
	api.POST("/threat-intel/sources/:id/refresh", requireAction(ActionDataManagement), s.refreshThreatIntelSourceHTTP)
	api.DELETE("/threat-intel/sources/:id", requireAction(ActionDataManagement), s.deleteThreatIntelSource)
	api.GET("/threat-intel/indicators", requireView(ViewAlerts), s.listThreatIntelIndicators)
	api.POST("/threat-intel/indicators", requireAction(ActionDataManagement), s.addThreatIntelIndicator)
	api.DELETE("/threat-intel/indicators/:id", requireAction(ActionDataManagement), s.deleteThreatIntelIndicator)
	api.POST("/threat-intel/import", requireAction(ActionDataManagement), s.importThreatIntel)
	api.GET("/tags/changes", requireView(ViewTags), s.tagChanges)
	api.GET("/tags/events", requireView(ViewTags), s.tagEvents)
	api.GET("/alerts", requireView(ViewAlerts), s.alerts)
	api.GET("/alerts/search", requireView(ViewAlerts), s.alertSearch)
	api.GET("/alerts/stats", requireView(ViewAlerts), s.alertStats)
	api.GET("/live/events", s.liveEvents)
	api.GET("/live/history", s.liveHistory)
	api.GET("/live/presence", s.livePresenceList)
	api.POST("/live/presence", s.livePresenceUpdate)
	api.GET("/incidents", requireView(ViewAlerts), s.incidents)
	api.GET("/incidents/search", requireView(ViewAlerts), s.incidentsSearch)
	api.GET("/incidents/dashboard", requireView(ViewAlerts), s.incidentsDashboard)
	api.GET("/incidents/:id", requireView(ViewAlerts), s.incidentDetail)
	api.PATCH("/incidents/:id", requireAction(ActionAlertConfirmApprove), s.updateIncident)
	api.POST("/incidents/:id/comments", requireAction(ActionAlertConfirmApprove), s.addIncidentComment)
	api.GET("/correlation-rules", requireView(ViewAlerts), s.listCorrelationRules)
	api.POST("/correlation-rules", requireAction(ActionDataManagement), s.saveCorrelationRule)
	api.DELETE("/correlation-rules/:id", requireAction(ActionDataManagement), s.deleteCorrelationRule)
	api.GET("/asset-risk", requireView(ViewAssets), s.assetRisk)
	api.GET("/asset-risk/:sensor/:ip/history", requireView(ViewAssets), s.assetRiskHistory)
	api.GET("/asset-risk/:sensor/:ip/exception", requireView(ViewAssets), s.assetRiskException)
	api.PUT("/asset-risk/:sensor/:ip/exception", requireAction(ActionAssetConfirmDelete), s.setAssetRiskException)
	api.GET("/asset-security-status", requireView(ViewAssets), s.assetSecurityStatuses)
	api.PUT("/sensors/:id/assets/:ip/security-status", requireAction(ActionAssetConfirmDelete), s.setAssetSecurityStatus)
	api.POST("/malware-incidents/contact-trace", requireAction(ActionAlertConfirmApprove), s.createMalwareContactTrace)
	api.GET("/malware-incidents/:id", requireView(ViewAlerts), s.getMalwareIncident)
	api.GET("/malware-incidents/:id/contact-graph", requireView(ViewTopology), s.getMalwareContactGraph)
	api.GET("/baseline", behaviorReadAccess(), s.baseline)
	api.POST("/sensors/:id/baseline/candidates/promote", requireAction(ActionAlertConfirmApprove), s.promoteBaselineCandidate)
	api.POST("/sensors/:id/learning/complete", requireAction(ActionDataManagement), s.completeSensorLearning)
	api.GET("/dashboard/trends", requireView(ViewDashboard), s.dashboardTrends)
	api.GET("/reports", requireView(ViewDashboard), s.listReports)
	api.GET("/reports/:id", requireView(ViewDashboard), s.getReport)
	api.GET("/reports/:id/pdf", requireView(ViewDashboard), s.downloadReportPDF)
	api.DELETE("/reports/:id", requireAction(ActionDataManagement), s.deleteReport)
	api.POST("/reports/generate", requireAction(ActionDataManagement), s.generateReportNow)
	api.GET("/rules", requireView(ViewRules), s.rules)
	api.GET("/rules/export", requireView(ViewRules), s.exportRules)
	api.POST("/sensors/:id/rules", requireAction(ActionRuleManage), s.createRule)
	api.PUT("/sensors/:id/rules/:rule", requireAction(ActionRuleManage), s.replaceRule)
	api.PATCH("/sensors/:id/rules/:rule", requireAction(ActionRuleManage), s.updateRule)
	api.DELETE("/sensors/:id/rules/:rule", requireAction(ActionRuleManage), s.deleteRule)
	api.POST("/sensors/:id/rules/test", requireAction(ActionRuleManage), s.testRule)
	api.POST("/rules/import", requireAction(ActionRuleManage), s.importRules)
	api.POST("/sensors/:id/assets/actions", requireAction(ActionAssetConfirmDelete), s.assetActions)
	api.POST("/sensors/:id/alerts/actions", requireAction(ActionAlertConfirmApprove), s.alertActions)
	api.POST("/rulesets", requireAction(ActionRuleManage), s.putRuleset)
	api.PUT("/sensors/:id/ruleset/:ruleset", requireAction(ActionRuleManage), s.assign)
	api.GET("/analysis/jobs", requireView(ViewAnalysis), s.analysisJobs)
	api.POST("/analysis/jobs", requireAction(ActionAnalysisManage), s.createAnalysisJob)
	api.DELETE("/analysis/jobs/:job", requireAction(ActionAnalysisManage), s.deleteAnalysisJob)
	api.GET("/data/backups", requireView(ViewDashboard), s.listBackups)
	api.POST("/data/backups", requireAction(ActionDataManagement), s.createBackup)
	api.GET("/data/backups/:backup/download", requireAction(ActionDataManagement), s.downloadBackup)
	api.DELETE("/data/backups/:backup", requireAction(ActionDataManagement), s.deleteBackup)
	api.POST("/data/reset", requireAction(ActionDataManagement), s.resetData)

	// Users & roles management — admin only (requireView(ViewSettings)
	// gates the whole Settings tab these live on; requireAction gates the
	// mutations specifically).
	api.GET("/users", requireAction(ActionUsersRolesManage), s.listUsers)
	api.POST("/users", requireAction(ActionUsersRolesManage), s.createUser)
	api.PATCH("/users/:id", requireAction(ActionUsersRolesManage), s.updateUser)
	api.DELETE("/users/:id", requireAction(ActionUsersRolesManage), s.deleteUser)
	api.POST("/users/:id/reset-password", requireAction(ActionUsersRolesManage), s.resetUserPassword)
	api.GET("/roles", requireAction(ActionUsersRolesManage), s.listRoles)
	api.PUT("/roles", requireAction(ActionUsersRolesManage), s.upsertRole)
	api.DELETE("/roles/:id", requireAction(ActionUsersRolesManage), s.deleteRole)
	return r
}

func (s *Server) SensorRouter() *gin.Engine {
	r := gin.Default()
	r.Use(securityHeaders())
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	enrollment := r.Group("/v1", serverErrorLogger("sensor-api"))
	enrollment.POST("/sensors/register", s.register)
	api := r.Group("/v1", serverErrorLogger("sensor-api"), s.sensorAuth())
	api.POST("/sensors/heartbeat", s.heartbeat)
	api.POST("/sensors/telemetry", s.telemetry)
	api.GET("/sensors/:id/sync", s.sync)
	api.GET("/sensors/:id/analysis/jobs/next", s.nextAnalysisJob)
	api.GET("/sensors/:id/analysis/jobs/:job/pcap", s.downloadAnalysisPCAP)
	api.POST("/sensors/:id/analysis/jobs/:job/result", s.analysisResult)
	api.POST("/sensors/:id/reconnaissance/jobs/:job/result", s.reconResult)
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
	s.dataResetMu.RLock()
	defer s.dataResetMu.RUnlock()
	pendingReset, err := s.Repo.HasPendingDataReset(c, x.SensorID)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	if pendingReset {
		c.JSON(http.StatusConflict, gin.H{"error": "sensor reset pending", "code": "sensor_reset_pending"})
		return
	}
	newAlerts, err := s.Repo.PutTelemetry(c, x)
	if err != nil {
		var sequenceConflict *TelemetrySequenceConflictError
		if errors.As(err, &sequenceConflict) {
			c.JSON(http.StatusConflict, gin.H{
				"error":            "telemetry sequence is older than Central state",
				"code":             "telemetry_sequence_conflict",
				"current_sequence": sequenceConflict.CurrentSequence,
			})
			return
		}
		respondInternalError(c, err)
		return
	}
	// Fire-and-forget: notification delivery (SMTP/webhook, both
	// involving network I/O to a third party) must never make the
	// sensor's telemetry upload wait on it or fail because of it. Runs
	// after the response is written, on a background context, not
	// gin's per-request one (which is canceled the moment this handler
	// returns).
	if len(newAlerts) > 0 {
		go s.dispatchNotifications(context.Background(), newAlerts)
		for _, alert := range newAlerts {
			s.publishLive(LiveEvent{Type: "alert.created", SensorID: alert.SensorID, EntityID: alert.AlertKey, Severity: alert.Severity, Message: alert.Message, Data: gin.H{"ip": alert.IP, "alert_type": alert.Type}})
		}
	}
	s.publishLive(LiveEvent{Type: "telemetry.updated", SensorID: x.SensorID, EntityID: x.BatchID, Message: "sensor telemetry updated", Data: gin.H{"sequence": x.Sequence, "new_alerts": len(newAlerts)}})
	s.scheduleIncidentRefresh(x.SensorID)
	c.JSON(http.StatusOK, management.TelemetryAck{Accepted: true, BatchID: x.BatchID, AcceptedSequence: x.Sequence, StoredAt: time.Now().UTC()})
}

func (s *Server) scheduleIncidentRefresh(sensorID string) {
	now := time.Now()
	s.incidentRefresh.mu.Lock()
	if s.incidentRefresh.running || (!s.incidentRefresh.last.IsZero() && now.Sub(s.incidentRefresh.last) < 15*time.Second) {
		s.incidentRefresh.mu.Unlock()
		return
	}
	s.incidentRefresh.running = true
	s.incidentRefresh.mu.Unlock()

	go func() {
		// Keep correlation/risk writes out of Data Management reset
		// transactions. A reset takes the write lock, waits for any in-flight
		// refresh to finish, and prevents an old pre-reset scan from recreating
		// incidents or risk rows after the destructive transaction commits.
		s.dataResetMu.RLock()
		defer s.dataResetMu.RUnlock()

		defer func() {
			s.incidentRefresh.mu.Lock()
			s.incidentRefresh.running = false
			s.incidentRefresh.last = time.Now()
			s.incidentRefresh.mu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := s.Repo.SyncCorrelatedIncidents(ctx); err != nil {
			log.Printf("incident correlation refresh failed: %v", err)
		} else {
			s.publishLive(LiveEvent{Type: "incidents.changed", SensorID: sensorID, Message: "incident correlation refreshed"})
		}
		cancel()

		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		if err := s.Repo.RecalculateAssetRisk(ctx); err != nil {
			log.Printf("asset risk refresh failed: %v", err)
		} else {
			s.publishLive(LiveEvent{Type: "asset-risk.changed", SensorID: sensorID, Message: "asset risk recalculated"})
		}
		cancel()
	}()
}

func (s *Server) assets(c *gin.Context) {
	snapshots, err := s.Repo.Telemetry(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	profiles, _ := s.Repo.AssetReconProfiles(c)
	identityMeta, _ := s.Repo.AssetIdentityMetadata(c)
	out := make([]map[string]interface{}, 0)
	for _, snapshot := range snapshots {
		var graph struct {
			Nodes             []map[string]interface{} `json:"Nodes"`
			HoneypotThreshold int                      `json:"HoneypotThreshold"`
		}
		if json.Unmarshal(snapshot.Topology, &graph) != nil {
			continue
		}
		contexts, _ := s.Repo.ListAssetContexts(c, snapshot.SensorID)
		vlanRows, _ := s.Repo.ListVLANConfig(c, snapshot.SensorID)
		vlanLevels := map[int]*float64{}
		vlanNames := map[int]string{}
		for _, v := range vlanRows {
			vlanLevels[v.VLANID] = v.PurdueLevel
			vlanNames[v.VLANID] = v.Name
		}
		threshold := graph.HoneypotThreshold
		if threshold <= 0 {
			threshold = 100
		}
		for _, node := range graph.Nodes {
			node["SensorID"] = snapshot.SensorID
			ip := fmt.Sprint(node["IP"])
			identity := canonicalAssetIdentity(fmt.Sprint(node["MAC"]), ip)
			if im, ok := identityMeta[snapshot.SensorID+"\x00"+ip]; ok {
				identity = im.CanonicalID
				node["CanonicalIdentity"] = im.CanonicalID
				node["IdentityFirstSeen"] = im.FirstSeen
				node["IdentityLastSeen"] = im.LastSeen
				node["IdentityIPCount"] = im.IPCount
				node["IdentitySourceCount"] = im.SourceCount
				node["IdentityConfidence"] = im.IdentityConfidence
				node["IdentityAliases"] = im.Aliases
				node["IdentityActive"] = true
				node["IdentityFresh"] = time.Since(im.LastSeen) <= 10*time.Minute
			}
			discoveredOT, _ := node["IsOT"].(bool)
			node["DiscoveredIsOT"] = discoveredOT
			if ac, ok := contexts[identity]; ok {
				node["AssetRole"] = ac.AssetRole
				node["Criticality"] = ac.Criticality
				node["Zone"] = ac.Zone
				node["PurdueOverride"] = ac.PurdueOverride
				node["IsAttackPathEntry"] = ac.IsEntryPoint
				node["IsAttackPathTarget"] = ac.IsTarget
				if ac.AssetRole != "" || ac.PurdueOverride != nil {
					node["IsOT"] = roleIsOT(ac.AssetRole) || (ac.PurdueOverride != nil && *ac.PurdueOverride <= 3)
				}
			}
			vlanID, _ := strconv.Atoi(fmt.Sprint(node["VLANID"]))
			if name := vlanNames[vlanID]; name != "" {
				node["VLANName"] = name
			}
			if ac, ok := contexts[identity]; ok && ac.PurdueOverride != nil {
				node["PurdueLevel"] = *ac.PurdueOverride
				node["PurdueSource"] = "asset_override"
			} else if level := vlanLevels[vlanID]; level != nil {
				node["PurdueLevel"] = *level
				node["PurdueSource"] = "vlan_config"
			} else {
				node["PurdueSource"] = "unclassified"
			}
			// Reconnaissance identity is owned by the stable asset identity, not
			// by its current/previous IP. Otherwise a DHCP address reused by a
			// different MAC can inherit the previous device's OS/firmware/serial.
			profile, profileOK := profiles[snapshot.SensorID+"\x00"+identity]
			if rp, ok := profile, profileOK; ok {
				if rp.Hostname != "" {
					node["ReconHostname"] = rp.Hostname
					if fmt.Sprint(node["Hostname"]) == "" {
						node["Hostname"] = rp.Hostname
					}
				}
				if rp.Vendor != "" {
					node["ReconVendor"] = rp.Vendor
				}
				node["ReconOS"] = rp.OS
				node["ReconModel"] = rp.Model
				node["ReconFirmware"] = rp.Firmware
				node["ReconSerial"] = rp.Serial
				node["ReconOTIdentity"] = rp.OTIdentity
				node["ReconServices"] = rp.Services
				node["ReconEvidence"] = rp.Evidence
				node["LastProfiledAt"] = rp.LastProfiledAt
			}
			score, _ := strconv.Atoi(fmt.Sprint(node["Score"]))
			node["HoneypotThreshold"] = threshold
			node["IsHoneypot"] = score >= threshold
			out = append(out, node)
		}
	}
	c.JSON(http.StatusOK, out)
}

// devices backs the Devices tab: the same live asset data as
// /assets, plus a Category (Rogue/Unknown, IT, OT, Mobile, Network) —
// classifyDeviceCategory's automatic guess, or an asset_overrides row
// if one exists for that device (always wins over the guess). See
// devices.go's doc comments for exactly how the guess is made and why
// it's only best-effort.
func (s *Server) devices(c *gin.Context) {
	snapshots, err := s.Repo.Telemetry(c)
	if err != nil {
		respondInternalError(c, err)
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
		overrides, err := s.Repo.ListAssetOverrides(c, snapshot.SensorID)
		if err != nil {
			respondInternalError(c, err)
			return
		}
		contexts, err := s.Repo.ListAssetContexts(c, snapshot.SensorID)
		if err != nil {
			respondInternalError(c, err)
			return
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
			mac := fmt.Sprint(node["MAC"])
			if normalized, err := normalizeAssetMAC(mac); err == nil {
				mac = normalized
			}
			isOT, _ := node["IsOT"].(bool)
			node["DiscoveredIsOT"] = isOT
			identity := canonicalAssetIdentity(mac, fmt.Sprint(node["IP"]))
			if ac, ok := contexts[identity]; ok && (ac.AssetRole != "" || ac.PurdueOverride != nil) {
				isOT = roleIsOT(ac.AssetRole) || (ac.PurdueOverride != nil && *ac.PurdueOverride <= 3)
				node["IsOT"] = isOT
			}
			confirmed := true
			if v, ok := node["Confirmed"].(bool); ok {
				confirmed = v
			}
			category := classifyDeviceCategory(fmt.Sprint(node["Vendor"]), isOT, confirmed)
			if o, ok := overrides[mac]; ok && o.Category != "" {
				category = o.Category
			}
			node["Category"] = category
			if o, ok := overrides[mac]; ok && o.Name != "" {
				node["OverrideName"] = o.Name
			}
			out = append(out, node)
		}
	}
	c.JSON(http.StatusOK, out)
}

// setDeviceCategory is the Devices tab's single-device "set category"
// action.
func (s *Server) setDeviceCategory(c *gin.Context) {
	var req struct {
		Category string `json:"category"`
		Name     string `json:"name"`
	}
	if c.ShouldBindJSON(&req) != nil || req.Category == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category is required"})
		return
	}
	sensorID, mac := c.Param("id"), c.Param("mac")
	if _, err := normalizeAssetMAC(mac); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validAssetCategory(strings.TrimSpace(req.Category)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid category"})
		return
	}
	if err := s.Repo.SetAssetCategory(c, sensorID, mac, req.Category, req.Name, identityFromContext(c).Username); err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("device category set: %s (%s) -> %s", mac, sensorID, req.Category), sensorID)
	c.Status(http.StatusOK)
}

// importDeviceList is the Devices tab's "Import asset list" CSV upload
// — mac,category,name per row, no header. Malformed rows are skipped,
// not fatal to the rest of the import — see ImportAssetOverrides.
func (s *Server) importDeviceList(c *gin.Context) {
	sensorID := c.Param("id")
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required (multipart form field 'file')"})
		return
	}
	defer file.Close()
	rows := make([]AssetOverride, 0)
	isJSON := strings.EqualFold(filepath.Ext(header.Filename), ".json") || strings.Contains(strings.ToLower(header.Header.Get("Content-Type")), "json")
	if isJSON {
		var raw []map[string]interface{}
		if err := json.NewDecoder(io.LimitReader(file, 10<<20)).Decode(&raw); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
			return
		}
		for _, item := range raw {
			mac := strings.TrimSpace(fmt.Sprint(firstValue(item, "mac", "MAC", "mac_address")))
			if mac == "" {
				continue
			}
			rows = append(rows, AssetOverride{MAC: mac, Category: strings.TrimSpace(fmt.Sprint(firstValue(item, "category", "Category", "class"))), Name: strings.TrimSpace(fmt.Sprint(firstValue(item, "name", "Name", "hostname")))})
		}
	} else {
		reader := csv.NewReader(io.LimitReader(file, 10<<20))
		reader.FieldsPerRecord = -1
		first := true
		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid CSV: " + err.Error()})
				return
			}
			if len(record) < 1 {
				continue
			}
			if first && strings.EqualFold(strings.TrimSpace(record[0]), "mac") {
				first = false
				continue
			}
			first = false
			o := AssetOverride{MAC: strings.TrimSpace(record[0])}
			if len(record) > 1 {
				o.Category = strings.TrimSpace(record[1])
			}
			if len(record) > 2 {
				o.Name = strings.TrimSpace(record[2])
			}
			if o.MAC != "" {
				rows = append(rows, o)
			}
		}
	}
	applied, err := s.Repo.ImportAssetOverrides(c, sensorID, rows, identityFromContext(c).Username)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("device list imported: %d row(s) for %s", applied, sensorID), sensorID)
	c.JSON(http.StatusOK, gin.H{"received": len(rows), "applied": applied, "skipped": len(rows) - applied})
}

func importedTagKey(tag map[string]interface{}) string {
	if key := strings.TrimSpace(fmt.Sprint(firstValue(tag, "Key", "key"))); key != "" {
		return key
	}
	return fmt.Sprintf("%v|%v|%v|%v|%v", firstValue(tag, "DeviceIP", "device_ip", "ip"), firstValue(tag, "DevicePort", "device_port", "port"), firstValue(tag, "Protocol", "protocol"), firstValue(tag, "AddressSpace", "address_space"), firstValue(tag, "Address", "address"))
}

func normalizeImportedTag(in map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	fields := map[string][]string{"DeviceIP": {"DeviceIP", "device_ip", "ip"}, "DevicePort": {"DevicePort", "device_port", "port"}, "Protocol": {"Protocol", "protocol"}, "AddressSpace": {"AddressSpace", "address_space"}, "Address": {"Address", "address"}, "Name": {"Name", "name"}, "Operation": {"Operation", "operation", "op"}, "LastValue": {"LastValue", "last_value", "value"}, "MinValue": {"MinValue", "min_value"}, "MaxValue": {"MaxValue", "max_value"}}
	for dst, keys := range fields {
		if v := firstValue(in, keys...); fmt.Sprint(v) != "" {
			out[dst] = v
		}
	}
	out["Key"] = importedTagKey(out)
	out["Imported"] = true
	out["LastChangeAt"] = time.Now().UTC()
	return out
}

func (s *Server) importTagList(c *gin.Context) {
	sensorID := c.Param("id")
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}
	defer file.Close()
	items := make([]map[string]interface{}, 0)
	isJSON := strings.EqualFold(filepath.Ext(header.Filename), ".json") || strings.Contains(strings.ToLower(header.Header.Get("Content-Type")), "json")
	if isJSON {
		if err := json.NewDecoder(io.LimitReader(file, 10<<20)).Decode(&items); err != nil {
			c.JSON(400, gin.H{"error": "invalid JSON: " + err.Error()})
			return
		}
	} else {
		r := csv.NewReader(io.LimitReader(file, 10<<20))
		r.FieldsPerRecord = -1
		var headerRow []string
		for {
			row, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				c.JSON(400, gin.H{"error": "invalid CSV: " + err.Error()})
				return
			}
			if len(row) == 0 {
				continue
			}
			if headerRow == nil && strings.Contains(strings.ToLower(strings.Join(row, ",")), "device_ip") {
				headerRow = row
				continue
			}
			m := map[string]interface{}{}
			names := headerRow
			if names == nil {
				names = []string{"device_ip", "device_port", "protocol", "address_space", "address", "name", "operation"}
			}
			for i, v := range row {
				if i < len(names) {
					m[strings.TrimSpace(names[i])] = strings.TrimSpace(v)
				}
			}
			items = append(items, m)
		}
	}
	tx, err := s.Repo.db.BeginTx(c, nil)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	defer tx.Rollback()
	applied := 0
	for _, raw := range items {
		tag := normalizeImportedTag(raw)
		key := importedTagKey(tag)
		if strings.Trim(key, "|") == "" {
			continue
		}
		blob, _ := json.Marshal(tag)
		if _, err = tx.ExecContext(c, `INSERT INTO imported_tags(sensor_id,tag_key,tag,imported_at,imported_by) VALUES($1,$2,$3,NOW(),$4) ON CONFLICT(sensor_id,tag_key) DO UPDATE SET tag=EXCLUDED.tag,imported_at=NOW(),imported_by=EXCLUDED.imported_by`, sensorID, key, blob, identityFromContext(c).Username); err != nil {
			respondInternalError(c, err)
			return
		}
		applied++
	}
	if err = tx.Commit(); err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("tag list imported: %d row(s) for %s", applied, sensorID), sensorID)
	c.JSON(200, gin.H{"applied": applied})
}

// Matching is vendor-only — see package vuln's doc comment for why OTLens
// has no passive way to fingerprint a device's exact product/firmware, so
// this narrows to "known issues affecting this vendor," not "known issues
// confirmed on this specific device." The Assets tab calls this on row
// click with whatever vendor string it already has for that asset.
func (s *Server) assetVulnerabilities(c *gin.Context) {
	vendor := strings.TrimSpace(c.Query("vendor"))
	if vendor == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vendor query parameter is required"})
		return
	}
	advisories := []vuln.Advisory{}
	if s.Vuln != nil {
		advisories = s.Vuln.Lookup(vendor)
	}
	c.JSON(http.StatusOK, gin.H{"Vendor": vendor, "Advisories": advisories, "Loaded": s.Vuln != nil && s.Vuln.Count() > 0})
}

// vulnerabilities backs the Vulnerability Management tab: every loaded
// advisory, each with the list of currently-known assets whose vendor
// matches — the reverse direction of assetVulnerabilities (which goes
// asset -> advisories for one device at a time). Same vendor-only
// matching limitation applies here, at larger scale: a widely-used
// vendor (Siemens, Rockwell) will show *every* asset from that vendor
// against *every* advisory for it, which is expected given how
// approximate this matching is, not a bug — the frontend says so
// explicitly rather than letting the list read as confirmed findings.
func (s *Server) vulnerabilities(c *gin.Context) {
	if s.Vuln == nil || s.Vuln.Count() == 0 {
		c.JSON(http.StatusOK, gin.H{"Loaded": false, "Advisories": []gin.H{}})
		return
	}
	snapshots, err := s.Repo.Telemetry(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	findings, err := s.Repo.ListVulnerabilityFindings(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	assetsByVendor := make(map[string][]gin.H)
	for _, snapshot := range snapshots {
		var graph struct {
			Nodes []map[string]interface{} `json:"Nodes"`
		}
		if json.Unmarshal(snapshot.Topology, &graph) != nil {
			continue
		}
		for _, node := range graph.Nodes {
			vendor := strings.ToLower(strings.TrimSpace(fmt.Sprint(node["Vendor"])))
			if vendor == "" || vendor == "<nil>" {
				continue
			}
			mac := strings.TrimSpace(fmt.Sprint(node["MAC"]))
			ip := strings.TrimSpace(fmt.Sprint(node["IP"]))
			identity := canonicalAssetIdentity("", ip)
			if normalized, err := normalizeAssetMAC(mac); err == nil {
				mac = normalized
				identity = canonicalAssetIdentity(normalized, ip)
			}
			assetsByVendor[vendor] = append(assetsByVendor[vendor], gin.H{
				"SensorID": snapshot.SensorID, "IP": node["IP"], "MAC": node["MAC"], "Hostname": node["Hostname"], "AssetIdentity": identity,
			})
		}
	}
	advisories := s.Vuln.All()
	out := make([]gin.H, 0, len(advisories))
	for _, adv := range advisories {
		matched := assetsByVendor[strings.ToLower(strings.TrimSpace(adv.Vendor))]
		statusCounts := map[string]int{"potential": 0, "confirmed": 0, "accepted_risk": 0, "false_positive": 0, "remediated": 0}
		for _, asset := range matched {
			key := adv.CVEID + "|" + fmt.Sprint(asset["SensorID"]) + "|" + fmt.Sprint(asset["AssetIdentity"])
			status := "potential"
			notes, updatedBy, updatedAt := "", "", ""
			if f, ok := findings[key]; ok {
				status, notes, updatedBy, updatedAt = f.Status, f.Notes, f.UpdatedBy, f.UpdatedAt.Format(time.RFC3339)
			}
			asset["FindingStatus"] = status
			asset["FindingNotes"] = notes
			asset["FindingUpdatedBy"] = updatedBy
			asset["FindingUpdatedAt"] = updatedAt
			statusCounts[status]++
		}
		out = append(out, gin.H{
			"CVEID": adv.CVEID, "Vendor": adv.Vendor, "Product": adv.Product, "Severity": adv.Severity,
			"Title": adv.Title, "PublishedDate": adv.PublishedDate, "URL": adv.URL,
			"AffectedAssets": matched, "AffectedCount": len(matched), "StatusCounts": statusCounts,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := severityRank[strings.ToLower(fmt.Sprint(out[i]["Severity"]))], severityRank[strings.ToLower(fmt.Sprint(out[j]["Severity"]))]
		if si != sj {
			return si > sj
		}
		return out[i]["AffectedCount"].(int) > out[j]["AffectedCount"].(int)
	})
	c.JSON(http.StatusOK, gin.H{"Loaded": true, "Advisories": out})
}

// listVLANConfig backs the Network Segmentation tab: every VLAN
// currently observed for a sensor, with whatever name/Purdue level has
// been assigned to it (see Repository.ListVLANConfig).
func (s *Server) listVLANConfig(c *gin.Context) {
	vlans, err := s.Repo.ListVLANConfig(c, c.Param("id"))
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, vlans)
}

func (s *Server) getMaxLevelJump(c *gin.Context) {
	jump, err := s.Repo.GetMaxLevelJump(c, c.Param("id"))
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"max_level_jump": jump})
}

// setVLANConfig names a VLAN and/or assigns it a Purdue Model level.
// Level: null clears it (unclassified again), a number sets it.
//
// Central persists this configuration and sends the complete authoritative
// snapshot to the sensor on every sync. No parallel one-shot command is queued:
// two delivery channels can otherwise replay stale policy in the wrong order.
func (s *Server) setVLANConfig(c *gin.Context) {
	vlanID, err := strconv.Atoi(c.Param("vlanid"))
	if err != nil || !validVLANID(vlanID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vlanid must be an integer between 0 and 4094"})
		return
	}
	var req struct {
		Name        string   `json:"name"`
		PurdueLevel *float64 `json:"purdue_level"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := validatePurdueLevel(req.PurdueLevel); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	sensorID := c.Param("id")
	if err := s.Repo.SetVLANConfig(c, sensorID, vlanID, req.Name, req.PurdueLevel, identityFromContext(c).Username); err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("VLAN %d configured: %s (level %v)", vlanID, req.Name, req.PurdueLevel), sensorID)
	c.Status(http.StatusOK)
}

// setMaxLevelJump sets a sensor's segmentation max-level-jump and
// exposes it through the next authoritative sensor sync — the Network
// Segmentation tab's per-sensor "how many levels apart is too many" setting.
func (s *Server) setMaxLevelJump(c *gin.Context) {
	var req struct {
		MaxLevelJump float64 `json:"max_level_jump"`
	}
	if c.ShouldBindJSON(&req) != nil || req.MaxLevelJump <= 0 || req.MaxLevelJump > 5 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "max_level_jump must be > 0 and <= 5"})
		return
	}
	sensorID := c.Param("id")
	if err := s.Repo.SetMaxLevelJump(c, sensorID, req.MaxLevelJump, identityFromContext(c).Username); err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("segmentation max_level_jump set: %s -> %v", sensorID, req.MaxLevelJump), sensorID)
	c.Status(http.StatusOK)
}

// Segmentation is distributed as authoritative state in every sensor sync.
// Historical one-shot segmentation.config commands are deliberately discarded
// by sync(): replaying an old queued snapshot after the current snapshot would
// temporarily roll a restarted/offline sensor back to stale VLAN/Purdue policy.

func (s *Server) listVLANAssets(c *gin.Context) {
	vlanID, err := strconv.Atoi(c.Param("vlanid"))
	if err != nil || !validVLANID(vlanID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vlanid must be an integer between 0 and 4094"})
		return
	}
	assets, err := s.Repo.ListVLANAssets(c, c.Param("id"), vlanID)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, assets)
}

// assetIPHistory returns every IP a given asset has ever been recorded
// with — see Repository.ListIPHistory.
func (s *Server) assetIPHistory(c *gin.Context) {
	entries, err := s.Repo.ListIPHistory(c, c.Param("id"), c.Param("mac"))
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, entries)
}

// settings exposes the operational (non-secret) config values the
// Settings tab shows — never tokens, passwords, or TLS key material. It's
// read-only: there is no corresponding PUT/PATCH, since these all come
// from central.config.yaml and take a restart to change; this just lets
// an operator confirm what's actually running without SSHing in to read
// the file.
func (s *Server) settings(c *gin.Context) {
	vulnCount := 0
	if s.Vuln != nil {
		vulnCount = s.Vuln.Count()
	}
	runtimeConfig := make(map[string]map[string]interface{}, len(s.RuntimeConfig)+1)
	for group, values := range s.RuntimeConfig {
		copyValues := make(map[string]interface{}, len(values))
		for key, value := range values {
			copyValues[key] = value
		}
		runtimeConfig[group] = copyValues
	}
	if stats, err := s.Repo.GetSIEMQueueStats(c, s.SIEMMaxAttempts); err == nil {
		runtimeConfig["SIEM delivery queue"] = map[string]interface{}{
			"queued": stats.Queued, "ready": stats.Ready, "failed": stats.Failed,
			"exhausted": stats.Exhausted, "oldest_created_at": stats.OldestCreatedAt,
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"SensorOfflineAfterSeconds":   int64(s.SensorOfflineAfter / time.Second),
		"SensorCheckIntervalSeconds":  int64(s.SensorCheckInterval / time.Second),
		"SessionDurationSeconds":      int64(s.SessionDuration / time.Second),
		"SIEMEnabled":                 s.SIEMEnabled,
		"AnalysisEnabled":             s.AnalysisEnabled,
		"VulnerabilityLoaded":         vulnCount > 0,
		"VulnerabilityCount":          vulnCount,
		"WebTLSEnabled":               s.WebTLSEnabled,
		"SensorAPITLSEnabled":         s.SensorAPITLSEnabled,
		"RetentionEnabled":            s.Retention.Enabled,
		"RetentionIntervalHours":      s.Retention.Interval.Hours(),
		"TelemetryRetentionDays":      s.Retention.TelemetryDays,
		"AlertsRetentionDays":         s.Retention.AlertsDays,
		"AuditRetentionDays":          s.Retention.AuditDays,
		"MaxDatabaseSizeGB":           s.Retention.MaxDatabaseSizeGB,
		"TargetDatabaseSizeGB":        s.Retention.TargetDatabaseSizeGB,
		"NotificationsEnabled":        s.Notifications.Enabled,
		"NotificationsMinSeverity":    s.Notifications.MinSeverity,
		"NotificationsEmailEnabled":   s.Notifications.Email.Enabled,
		"NotificationsWebhookEnabled": s.Notifications.Webhook.Enabled,
		"RuntimeConfig":               runtimeConfig,
		"SchemaVersion":               s.Repo.SchemaVersion(c),
	})
}

// logAudit is for explicit, richer audit entries beyond what
// auditMiddleware captures generically (method+path only) — e.g. which
// specific asset/rule/sensor was affected. Best-effort: a logging
// failure is written to the server log, never fails the request it's
// attached to, since the actual action already happened either way.
func (s *Server) logAudit(c *gin.Context, actor, action, sensorID string) {
	if s.Repo == nil {
		return
	}
	if err := s.Repo.InsertAuditLog(c, AuditEntry{
		Actor: actor, Action: action, Method: c.Request.Method, Path: c.Request.URL.Path,
		Status: http.StatusOK, Success: true, SourceIP: c.ClientIP(), SensorID: sensorID,
	}); err != nil {
		log.Printf("audit_log insert failed: %v", err)
	}
}

// summarizeTargets renders a short, human-readable summary of a bulk
// action's targets for the audit log — the full list for a handful, just
// a count for a large bulk action (someone approving thousands of alerts
// at once shouldn't turn one audit row into a multi-KB string).
func summarizeTargets(targets []string) string {
	const max = 5
	if len(targets) <= max {
		return strings.Join(targets, ", ")
	}
	return fmt.Sprintf("%s, and %d more (%d total)", strings.Join(targets[:max], ", "), len(targets)-max, len(targets))
}

func (s *Server) auditLog(c *gin.Context) {
	entries, err := s.Repo.ListAuditLogFiltered(c, auditFilterFromRequest(c))
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, entries)
}

func (s *Server) tags(c *gin.Context) {
	snapshots, err := s.Repo.Telemetry(c)
	if err != nil {
		respondInternalError(c, err)
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
	rows, queryErr := s.Repo.db.QueryContext(c, `SELECT sensor_id, tag FROM imported_tags ORDER BY imported_at`)
	if queryErr == nil {
		defer rows.Close()
		for rows.Next() {
			var sensorID string
			var raw []byte
			if rows.Scan(&sensorID, &raw) != nil {
				continue
			}
			var tag map[string]interface{}
			if json.Unmarshal(raw, &tag) != nil {
				continue
			}
			tag["SensorID"] = sensorID
			stableKey := importedTagKey(tag)
			key := sensorID + "::" + stableKey
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
	// FlowCount is how many distinct flows (protocol/port combinations)
	// were aggregated into this single visual edge. See aggregateEdges.
	FlowCount int `json:"FlowCount"`
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
		liveIPs := make(map[string]bool, len(graph.Nodes))
		seenIDs := make(map[string]bool, len(graph.Nodes))
		for _, n := range graph.Nodes {
			liveIPs[n.IP] = true
			n.ID = prefix + n.ID
			seenIDs[n.ID] = true
			nodes = append(nodes, topologyNode{
				Node:              n,
				SensorID:          row.SensorID,
				HoneypotThreshold: sensorThreshold,
				IsHoneypot:        n.Score >= sensorThreshold,
			})
		}
		// Nodes, same durability problem edges had: the live snapshot only
		// ever has this sensor's *current* assets (persist.retention prunes
		// the rest), so an edge safely recorded in topology_edges would
		// otherwise become undrawable — no node to attach it to — the
		// moment either endpoint asset ages out of the live list. Anything
		// in the node ledger that the live snapshot doesn't currently have
		// fills that gap; live data always wins when both exist.
		persistedNodes, err := s.Repo.ListTopologyNodes(c, row.SensorID)
		if err != nil {
			return nil, err
		}
		for _, rec := range persistedNodes {
			if liveIPs[rec.IP] {
				continue
			}
			id := rec.MAC
			if id == "" {
				id = "ip:" + rec.IP
			}
			fullID := prefix + id
			// A device that changed IP over time (DHCP renewal etc.) has one
			// topology_nodes row per IP it's ever had, all sharing the same
			// MAC — without this check, every one of those old-IP rows would
			// produce the *same* node id (MAC-derived), and vis.DataSet
			// throws on the frontend the moment a second item with an
			// already-used id is added. Only the first (most recently
			// upserted, since ListTopologyNodes has no defined order beyond
			// that) stale IP per MAC gets a node; edges tied to any other
			// now-superseded IP for that same device won't resolve to a
			// node until that IP is seen live again.
			if seenIDs[fullID] {
				continue
			}
			seenIDs[fullID] = true
			ledgerNode := topology.Node{
				ID: fullID, IP: rec.IP, MAC: rec.MAC, Hostname: rec.Hostname, Vendor: rec.Vendor,
				IsOT: rec.IsOT, Protocols: splitProtocols(rec.Protocols), Confirmed: rec.Confirmed,
				Score: rec.Score, VLANID: rec.VLANID, FirstSeen: rec.FirstSeen, LastSeen: rec.LastSeen,
				PacketCount: rec.PacketCount,
			}
			nodes = append(nodes, topologyNode{
				Node:              ledgerNode,
				SensorID:          row.SensorID,
				HoneypotThreshold: sensorThreshold,
				IsHoneypot:        ledgerNode.Score >= sensorThreshold,
			})
		}
		// Edges are drawn from the durable per-sensor ledger (topology_edges),
		// not graph.Edges directly — the sensor prunes flows that have gone
		// quiet (internal/flow/engine.go's Prune) to bound its own SQLite
		// growth, which is correct there but would otherwise make a
		// connection that only happened once disappear from the map the
		// next time it drops out of the live snapshot. PutTelemetry upserts
		// into this ledger on every sync; once a pair is recorded here it
		// stays on the map regardless of what the sensor currently still has.
		persisted, err := s.Repo.ListTopologyEdges(c, row.SensorID)
		if err != nil {
			return nil, err
		}
		for _, rec := range persisted {
			pairKey := rec.PairKey()
			edges = append(edges, topologyEdge{
				Edge: topology.Edge{
					SrcIP:        rec.SrcIP,
					DstIP:        rec.DstIP,
					Protocol:     rec.Protocol,
					IsOT:         rec.IsOT,
					FromHoneypot: rec.FromHoneypot,
					VLANID:       rec.VLANID,
					Packets:      rec.Packets,
					Bytes:        rec.Bytes,
					FirstSeen:    rec.FirstSeen,
					LastSeen:     rec.LastSeen,
					ID:           prefix + "agg:" + pairKey,
				},
				SensorID:  row.SensorID,
				SrcNodeID: prefix + rec.SrcIP,
				DstNodeID: prefix + rec.DstIP,
				FlowCount: rec.FlowCount,
			})
		}
	}
	return json.Marshal(gin.H{"Nodes": nodes, "Edges": edges, "HoneypotThreshold": 100})
}

// aggregatedEdge pairs a topology.Edge with how many raw flows were folded
// into it, for display ("N flows" in the tooltip) without needing to keep
// every individual flow around.
type aggregatedEdge struct {
	topology.Edge
	FlowCount int
}

// aggregateEdges folds every flow between the same two assets into one
// visual edge. A sensor's raw graph has one Edge per underlying flow.Flow,
// and flow.Flow is keyed on protocol+both ports — so a single chatty asset
// pair (an HMI polling a PLC over several sessions, a workstation with many
// ephemeral client ports to a server, etc.) can otherwise produce dozens of
// parallel edges between the exact same two nodes. On a busy network this
// inflates edge count far more than the actual number of devices does, and
// is what actually makes a "large network" graph feel slow — so the
// Topology tab draws one edge per asset pair, with the underlying flow
// count/aggregated traffic available in the edge's tooltip.
//
// Direction (SrcIP/DstIP) is arbitrary per individual flow — flowKey folds
// both directions of a conversation into one record, so which side ended
// up as SrcIP just reflects whichever packet happened to create it first.
// That's harmless for most fields (VLAN mismatch, OT classification, byte
// counts don't care which side is "src"), but it does matter for
// FromHoneypot: that flag specifically means "the honeypot initiated this",
// so once we've seen a flow where it's true, its Src/DstIP (the honeypot as
// SrcIP) is kept as the aggregated edge's direction rather than being
// overwritten by some later, direction-arbitrary non-honeypot flow.
// canonicalPair returns (lo, hi) — the two IPs of a conversation ordered
// consistently regardless of which one happened to be recorded as
// "source" for a given flow (flowKey on the sensor folds both directions
// into one record already, but which side ends up as SrcIP is otherwise
// arbitrary). Used to key both in-memory edge aggregation here and the
// durable topology_edges table the same way.
func canonicalPair(a, b string) (string, string) {
	if b < a {
		return b, a
	}
	return a, b
}

func aggregateEdges(flows []topology.Edge) []aggregatedEdge {
	type bucket struct {
		edge      topology.Edge
		protocols map[string]bool
		count     int
	}
	order := make([]string, 0, len(flows))
	buckets := make(map[string]*bucket, len(flows))
	for _, f := range flows {
		lo, hi := canonicalPair(f.SrcIP, f.DstIP)
		key := lo + "|" + hi

		b, ok := buckets[key]
		if !ok {
			b = &bucket{edge: f, protocols: map[string]bool{}}
			buckets[key] = b
			order = append(order, key)
		}
		b.protocols[f.Protocol] = true
		b.count++

		if f.IsOT {
			b.edge.IsOT = true
		}
		if f.FromHoneypot && !b.edge.FromHoneypot {
			// First honeypot-initiated flow seen for this pair — lock in
			// its direction so later flows can't overwrite it.
			b.edge.SrcIP, b.edge.DstIP = f.SrcIP, f.DstIP
		}
		if f.FromHoneypot {
			b.edge.FromHoneypot = true
		}
		b.edge.Packets += f.Packets
		b.edge.Bytes += f.Bytes
		if b.edge.FirstSeen.IsZero() || (!f.FirstSeen.IsZero() && f.FirstSeen.Before(b.edge.FirstSeen)) {
			b.edge.FirstSeen = f.FirstSeen
		}
		if f.LastSeen.After(b.edge.LastSeen) {
			b.edge.LastSeen = f.LastSeen
		}
	}

	out := make([]aggregatedEdge, 0, len(order))
	for _, key := range order {
		b := buckets[key]
		protocols := make([]string, 0, len(b.protocols))
		for p := range b.protocols {
			protocols = append(protocols, p)
		}
		sort.Strings(protocols)
		b.edge.ID = "agg:" + key
		b.edge.Protocol = strings.Join(protocols, ", ")
		out = append(out, aggregatedEdge{Edge: b.edge, FlowCount: b.count})
	}
	return out
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
		respondInternalError(c, err)
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
			respondInternalError(c, err)
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
		respondInternalError(c, e)
		return
	}
	aggregateRaw(c, v, func(x management.TelemetrySnapshot) json.RawMessage { return x.TagChanges })
}
func (s *Server) tagEvents(c *gin.Context) {
	v, e := s.Repo.Telemetry(c)
	if e != nil {
		respondInternalError(c, e)
		return
	}
	aggregateRaw(c, v, func(x management.TelemetrySnapshot) json.RawMessage { return x.TagEvents })
}
func (s *Server) alertStats(c *gin.Context) {
	stats, err := s.Repo.GetAlertHistoryStats(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, stats)
}

func parseAlertQueryTime(value string, endOfDay bool) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return &parsed, nil
	}
	parsed, err := time.ParseInLocation("2006-01-02", value, time.Local)
	if err != nil {
		return nil, err
	}
	if endOfDay {
		parsed = parsed.Add(24 * time.Hour)
	}
	return &parsed, nil
}

func (s *Server) alertSearch(c *gin.Context) {
	limit := 100
	if value := strings.TrimSpace(c.Query("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 || parsed > 500 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be between 1 and 500"})
			return
		}
		limit = parsed
	}
	offset := 0
	if value := strings.TrimSpace(c.Query("offset")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "offset must be zero or greater"})
			return
		}
		offset = parsed
	}

	status := strings.ToLower(strings.TrimSpace(c.Query("status")))
	if status == "all" {
		status = ""
	}
	if status != "" && status != "new" && status != "confirmed" && status != "approved" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert status"})
		return
	}

	severity := strings.ToLower(strings.TrimSpace(c.Query("severity")))
	if severity == "all" {
		severity = ""
	}
	switch severity {
	case "", "critical", "high", "medium", "low", "info":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert severity"})
		return
	}

	activity := strings.ToLower(strings.TrimSpace(c.Query("activity")))
	if activity == "all" {
		activity = ""
	}
	switch activity {
	case "", "active", "resolved":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert activity"})
		return
	}

	from, err := parseAlertQueryTime(c.Query("from"), false)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from date; use YYYY-MM-DD or RFC3339"})
		return
	}
	to, err := parseAlertQueryTime(c.Query("to"), true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to date; use YYYY-MM-DD or RFC3339"})
		return
	}
	if from != nil && to != nil && !from.Before(*to) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "from must be before to"})
		return
	}

	page, err := s.Repo.SearchAlertHistory(c, AlertHistoryQuery{
		Search:   c.Query("q"),
		SensorID: c.Query("sensor_id"),
		Status:   status,
		Severity: severity,
		Activity: activity,
		From:     from,
		To:       to,
		Limit:    limit,
		Offset:   offset,
		Oldest:   strings.EqualFold(c.Query("sort"), "oldest"),
	})
	if err != nil {
		respondInternalError(c, err)
		return
	}

	items := make([]gin.H, 0, len(page.Items))
	for _, e := range page.Items {
		items = append(items, gin.H{
			"SensorID": e.SensorID, "ID": e.AlertKey, "AlertKey": e.AlertKey, "Type": e.Type, "Severity": e.Severity,
			"Message": e.Message, "IP": e.IP, "Status": e.Status, "Count": e.Count, "Active": e.Active,
			"ApprovedBy": e.ApprovedBy, "ApprovedAt": e.ApprovedAt, "FirstSeen": e.FirstSeen, "LastSeen": e.LastSeen,
			"Evidence": e.Evidence,
		})
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": page.Total, "limit": page.Limit, "offset": page.Offset})
}

func (s *Server) assetAlertHistory(c *gin.Context) {
	limit := 500
	if value := strings.TrimSpace(c.Query("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 || parsed > 5000 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be between 1 and 5000"})
			return
		}
		limit = parsed
	}
	entries, err := s.Repo.ListAssetAlertHistory(c, c.Param("id"), c.Param("ip"), limit)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	out := make([]gin.H, 0, len(entries))
	for _, e := range entries {
		out = append(out, gin.H{
			"SensorID": e.SensorID, "ID": e.AlertKey, "AlertKey": e.AlertKey, "Type": e.Type, "Severity": e.Severity,
			"Message": e.Message, "IP": e.IP, "Status": e.Status, "Count": e.Count, "Active": e.Active,
			"ApprovedBy": e.ApprovedBy, "ApprovedAt": e.ApprovedAt, "FirstSeen": e.FirstSeen, "LastSeen": e.LastSeen,
			"Evidence": e.Evidence,
		})
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) alerts(c *gin.Context) {
	entries, err := s.Repo.ListAlertHistory(c, 2000)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	out := make([]gin.H, 0, len(entries))
	for _, e := range entries {
		out = append(out, gin.H{
			"SensorID": e.SensorID, "ID": e.AlertKey, "Type": e.Type, "Severity": e.Severity,
			"Message": e.Message, "IP": e.IP, "Status": e.Status, "Count": e.Count, "Active": e.Active,
			"ApprovedBy": e.ApprovedBy, "ApprovedAt": e.ApprovedAt, "FirstSeen": e.FirstSeen, "LastSeen": e.LastSeen,
		})
	}
	c.JSON(http.StatusOK, out)
}

func (s *Server) incidents(c *gin.Context) {
	// Read-only by design. Correlation is refreshed asynchronously from telemetry
	// ingestion; a UI GET must never trigger a full alert-history correlation scan.
	incidents, err := s.Repo.ListManagedIncidents(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, incidents)
}

func (s *Server) incidentsDashboard(c *gin.Context) {
	stats, items, err := s.Repo.IncidentDashboard(c, 5)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"stats": stats, "items": items})
}

func (s *Server) incidentsSearch(c *gin.Context) {
	status := strings.TrimSpace(strings.ToLower(c.Query("status")))
	if status == "all" {
		status = ""
	}
	if status != "" && status != "new" && status != "investigating" && status != "contained" && status != "resolved" && status != "closed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid incident status"})
		return
	}
	minScore, _ := strconv.Atoi(c.DefaultQuery("min_score", "0"))
	if minScore < 0 {
		minScore = 0
	}
	if minScore > 100 {
		minScore = 100
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if offset < 0 {
		offset = 0
	}
	items, total, err := s.Repo.ListManagedIncidentsPage(c, status, strings.TrimSpace(c.Query("q")), minScore, limit, offset)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) incidentDetail(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}
	events, err := s.Repo.IncidentEvents(c, id)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	comments, err := s.Repo.IncidentComments(c, id)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, gin.H{"Events": events, "Comments": comments})
}

func (s *Server) updateIncident(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}
	var req struct {
		Status  string `json:"status"`
		Owner   string `json:"owner"`
		Summary string `json:"summary"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(400, gin.H{"error": "invalid JSON"})
		return
	}
	valid := map[string]bool{"new": true, "investigating": true, "contained": true, "resolved": true, "closed": true}
	if !valid[req.Status] {
		c.JSON(400, gin.H{"error": "invalid incident status"})
		return
	}
	if err := s.Repo.UpdateIncident(c, id, req.Status, strings.TrimSpace(req.Owner), strings.TrimSpace(req.Summary)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "incident not found"})
			return
		}
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("incident %d moved to %s", id, req.Status), "")
	s.publishLive(LiveEvent{Type: "incident.updated", EntityID: strconv.FormatInt(id, 10), Message: "incident moved to " + req.Status, Data: gin.H{"status": req.Status, "owner": strings.TrimSpace(req.Owner)}})
	c.JSON(200, gin.H{"updated": true})
}

func (s *Server) addIncidentComment(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if c.ShouldBindJSON(&req) != nil || strings.TrimSpace(req.Body) == "" {
		c.JSON(400, gin.H{"error": "comment body is required"})
		return
	}
	actor := identityFromContext(c).Username
	if err := s.Repo.AddIncidentComment(c, id, actor, strings.TrimSpace(req.Body)); err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, actor, fmt.Sprintf("comment added to incident %d", id), "")
	s.publishLive(LiveEvent{Type: "incident.comment", EntityID: strconv.FormatInt(id, 10), Message: "new incident comment", Data: gin.H{"actor": actor}})
	c.JSON(201, gin.H{"created": true})
}

func (s *Server) assetRisk(c *gin.Context) {
	if err := s.Repo.RecalculateAssetRisk(c); err != nil {
		respondInternalError(c, err)
		return
	}
	risks, err := s.Repo.ListAssetRisk(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, risks)
}

func (s *Server) assetRiskHistory(c *gin.Context) {
	v, err := s.Repo.AssetRiskHistory(c, c.Param("sensor"), c.Param("ip"))
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, v)
}
func (s *Server) assetRiskException(c *gin.Context) {
	v, err := s.Repo.GetAssetRiskException(c, c.Param("sensor"), c.Param("ip"))
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(200, gin.H{"sensor_id": c.Param("sensor"), "asset_ip": c.Param("ip"), "disposition": "none"})
		return
	}
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, v)
}
func (s *Server) setAssetRiskException(c *gin.Context) {
	var req AssetRiskException
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(400, gin.H{"error": "invalid JSON"})
		return
	}
	valid := map[string]bool{"none": true, "accepted_risk": true, "false_positive": true, "compensating_control": true}
	if !valid[req.Disposition] {
		c.JSON(400, gin.H{"error": "invalid disposition"})
		return
	}
	req.SensorID = c.Param("sensor")
	req.AssetIP = c.Param("ip")
	req.UpdatedBy = identityFromContext(c).Username
	if req.ScoreOverride != nil && (*req.ScoreOverride < 0 || *req.ScoreOverride > 100) {
		c.JSON(400, gin.H{"error": "score override must be 0-100"})
		return
	}
	if err := s.Repo.SetAssetRiskException(c, req); err != nil {
		respondInternalError(c, err)
		return
	}
	_ = s.Repo.RecalculateAssetRisk(c)
	s.logAudit(c, req.UpdatedBy, "asset risk exception updated", req.SensorID+"/"+req.AssetIP)
	s.publishLive(LiveEvent{Type: "asset-risk.changed", SensorID: req.SensorID, EntityID: req.AssetIP, Message: "asset risk exception updated"})
	c.JSON(200, gin.H{"updated": true})
}

func (s *Server) rules(c *gin.Context) {
	v, e := s.Repo.Telemetry(c)
	if e != nil {
		respondInternalError(c, e)
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
		respondInternalError(c, err)
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
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"queued": len(payloads)})
}

func (s *Server) exportRules(c *gin.Context) {
	v, err := s.Repo.Telemetry(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	result := make([]map[string]interface{}, 0)
	// custom_rules remains as a compatibility convenience for old importers,
	// but is de-duplicated across sensors. custom_rules_by_sensor is the
	// authoritative v3 representation so a multi-sensor export never merges
	// divergent copies of the same rule into one ambiguous import set.
	custom := make([]map[string]interface{}, 0)
	customSeen := make(map[string]bool)
	customBySensor := make(map[string][]map[string]interface{})
	warnings := make([]string, 0)
	runtimeSnapshots := make([]map[string]interface{}, 0, len(v))
	for _, snapshot := range v {
		runtimeSnapshots = append(runtimeSnapshots, map[string]interface{}{
			"sensor_id": snapshot.SensorID, "captured_at": snapshot.CapturedAt, "sequence": snapshot.Sequence,
		})
		var rows []map[string]interface{}
		if err := json.Unmarshal(snapshot.Rules, &rows); err != nil {
			warnings = append(warnings, fmt.Sprintf("sensor %s rules could not be decoded: %v", snapshot.SensorID, err))
			continue
		}
		for _, row := range rows {
			runtimeRow := make(map[string]interface{}, len(row)+1)
			for key, value := range row {
				runtimeRow[key] = value
			}
			runtimeRow["SensorID"] = snapshot.SensorID
			result = append(result, runtimeRow)

			kind := strings.ToLower(strings.TrimSpace(fmt.Sprint(row["Kind"])))
			if kind == "" {
				kind = strings.ToLower(strings.TrimSpace(fmt.Sprint(row["kind"])))
			}
			if kind != "custom" {
				continue
			}
			importRow := make(map[string]interface{}, len(row))
			for key, value := range row {
				if strings.EqualFold(key, "SensorID") {
					continue
				}
				importRow[key] = value
			}
			customBySensor[snapshot.SensorID] = append(customBySensor[snapshot.SensorID], importRow)
			canonical, marshalErr := json.Marshal(importRow)
			if marshalErr != nil {
				warnings = append(warnings, fmt.Sprintf("sensor %s custom rule could not be canonicalized: %v", snapshot.SensorID, marshalErr))
				continue
			}
			key := string(canonical)
			if !customSeen[key] {
				customSeen[key] = true
				custom = append(custom, importRow)
			}
		}
	}
	c.Header("Content-Disposition", "attachment; filename=otlens-rules.json")
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"format":                 "otlens-policy-v3",
		"exported_at":            time.Now().UTC(),
		"runtime_sensor_count":   len(v),
		"runtime_snapshots":      runtimeSnapshots,
		"rules":                  result,         // complete runtime rule snapshots, tagged by sensor
		"custom_rules":           custom,         // compatibility: exact duplicates de-duplicated
		"custom_rules_by_sensor": customBySensor, // authoritative import source for multi-sensor exports
		"warnings":               warnings,
	})
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("rules exported: sensors=%d custom=%d warnings=%d", len(v), len(custom), len(warnings)), "")
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
		respondInternalError(c, err)
		return
	}
	if err := s.Repo.QueueCommands(c, c.Param("id"), "rule.add", []string{string(payload)}); err != nil {
		respondInternalError(c, err)
		return
	}
	c.Status(http.StatusAccepted)
}

func (s *Server) updateRule(c *gin.Context) {
	var req struct {
		Enabled          *bool                       `json:"enabled,omitempty"`
		Severity         *string                     `json:"severity,omitempty"`
		SeverityOverride *bool                       `json:"severity_override,omitempty"`
		Priority         *int                        `json:"priority,omitempty"`
		Simulation       *bool                       `json:"simulation,omitempty"`
		Suppression      *management.RuleSuppression `json:"suppression,omitempty"`
		Schedule         *string                     `json:"schedule,omitempty"`
		Parameters       *map[string]float64         `json:"parameters,omitempty"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule policy"})
		return
	}
	if req.Enabled == nil && req.Severity == nil && req.SeverityOverride == nil && req.Priority == nil && req.Simulation == nil && req.Suppression == nil && req.Schedule == nil && req.Parameters == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one policy field is required"})
		return
	}
	if req.Severity != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Severity))
		switch v {
		case "info", "low", "medium", "high", "critical":
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid severity"})
			return
		}
		*req.Severity = v
	}
	if req.Priority != nil && *req.Priority <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "priority must be positive"})
		return
	}
	if req.Suppression != nil {
		v := strings.ToLower(strings.TrimSpace(req.Suppression.Mode))
		switch v {
		case "every", "once", "interval", "aggregate":
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid suppression mode"})
			return
		}
		if v == "interval" && req.Suppression.IntervalSeconds <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "interval_seconds must be positive"})
			return
		}
		req.Suppression.Mode = v
	}
	if req.Parameters != nil {
		for key, value := range *req.Parameters {
			if strings.TrimSpace(key) == "" || value < 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "rule parameters must use non-empty names and non-negative numeric values"})
				return
			}
		}
	}
	sensorID, ruleID := c.Param("id"), c.Param("rule")
	payload := map[string]interface{}{"id": ruleID}
	if req.Enabled != nil {
		payload["enabled"] = *req.Enabled
	}
	if req.Severity != nil {
		payload["severity"] = *req.Severity
		// A severity submitted by an operator is an explicit policy override.
		// Dynamic detectors otherwise keep their computed severity.
		payload["severity_override"] = true
	}
	if req.SeverityOverride != nil {
		payload["severity_override"] = *req.SeverityOverride
	}
	if req.Priority != nil {
		payload["priority"] = *req.Priority
	}
	if req.Simulation != nil {
		payload["simulation"] = *req.Simulation
	}
	if req.Suppression != nil {
		payload["suppression"] = *req.Suppression
	}
	if req.Schedule != nil {
		payload["schedule"] = *req.Schedule
	}
	if req.Parameters != nil {
		payload["parameters"] = *req.Parameters
	}
	data, _ := json.Marshal(payload)
	if err := s.Repo.QueueCommands(c, sensorID, "rule.policy", []string{string(data)}); err != nil {
		respondInternalError(c, err)
		return
	}
	label := ruleID
	if name, ok := s.Repo.RuleName(c, sensorID, ruleID); ok {
		label = fmt.Sprintf("%s (%s)", name, ruleID)
	}
	s.logAudit(c, identityFromContext(c).Username, "rule policy updated: "+label, sensorID)
	c.Status(http.StatusAccepted)
}

func (s *Server) deleteRule(c *gin.Context) {
	if err := s.Repo.QueueCommands(c, c.Param("id"), "rule.delete", []string{c.Param("rule")}); err != nil {
		respondInternalError(c, err)
		return
	}
	c.Status(http.StatusAccepted)
}

func (s *Server) baseline(c *gin.Context) {
	v, e := s.Repo.Telemetry(c)
	if e != nil {
		respondInternalError(c, e)
		return
	}
	registered, e := s.Repo.ListSensors(c.Request.Context())
	if e != nil {
		respondInternalError(c, e)
		return
	}
	pendingLearning, e := s.Repo.PendingCommandSensors(c.Request.Context(), "sensor.learning.complete")
	if e != nil {
		respondInternalError(c, e)
		return
	}
	out := make([]map[string]interface{}, 0, len(registered))
	seen := make(map[string]struct{}, len(registered))
	for _, x := range v {
		var row map[string]interface{}
		if json.Unmarshal(x.Baseline, &row) == nil {
			row["SensorID"] = x.SensorID
			row["telemetry_available"] = true
			row["learning_completion_pending"] = pendingLearning[x.SensorID]
			out = append(out, row)
			seen[x.SensorID] = struct{}{}
		}
	}
	// Keep the learning-control selector useful even before a sensor has sent
	// its first baseline telemetry. The UI can show the registered sensor as
	// unavailable instead of rendering an empty select control.
	for _, sensor := range registered {
		if _, ok := seen[sensor.ID]; ok {
			continue
		}
		out = append(out, map[string]interface{}{
			"SensorID":                    sensor.ID,
			"sensor_name":                 sensor.Name,
			"telemetry_available":         false,
			"learning_completion_pending": pendingLearning[sensor.ID],
		})
	}
	c.JSON(200, out)
}

func (s *Server) promoteBaselineCandidate(c *gin.Context) {
	var req struct {
		CandidateID string `json:"candidate_id"`
	}
	if c.ShouldBindJSON(&req) != nil || strings.TrimSpace(req.CandidateID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "candidate_id is required"})
		return
	}
	candidateID := strings.TrimSpace(req.CandidateID)
	if err := s.Repo.QueueCommands(c.Request.Context(), c.Param("id"), "baseline.candidate.promote", []string{candidateID}); err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, "behavior baseline candidate promotion queued", c.Param("id")+":"+candidateID)
	c.Status(http.StatusAccepted)
}

func (s *Server) completeSensorLearning(c *gin.Context) {
	var req struct {
		Force bool `json:"force"`
	}
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if req.Force && !identityFromContext(c).Permissions.HasAction(ActionUsersRolesManage) {
		c.JSON(http.StatusForbidden, gin.H{"error": "force finish requires administrator permission"})
		return
	}

	sensorID := strings.TrimSpace(c.Param("id"))
	telemetry, err := s.Repo.Telemetry(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	type learningStatus struct {
		Enabled                   bool      `json:"enabled"`
		ManualCompletionSupported bool      `json:"manual_completion_supported"`
		Mode                      string    `json:"mode"`
		LearningStarted           time.Time `json:"learning_started"`
		LearningEndsAt            time.Time `json:"learning_ends_at"`
		Behavior                  struct {
			Enabled                   bool      `json:"enabled"`
			ManualCompletionSupported bool      `json:"manual_completion_supported"`
			Mode                      string    `json:"mode"`
			LearningStarted           time.Time `json:"learning_started"`
			LearningEndsAt            time.Time `json:"learning_ends_at"`
		} `json:"behavior"`
	}

	found := false
	var status learningStatus
	for _, snapshot := range telemetry {
		if snapshot.SensorID != sensorID {
			continue
		}
		found = true
		if err := json.Unmarshal(snapshot.Baseline, &status); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "sensor baseline telemetry is unavailable"})
			return
		}
		break
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "sensor telemetry not found"})
		return
	}
	if pending, err := s.Repo.HasPendingCommand(c.Request.Context(), sensorID, "sensor.learning.complete"); err != nil {
		respondInternalError(c, err)
		return
	} else if pending {
		c.JSON(http.StatusAccepted, gin.H{"status": "pending", "sensor_id": sensorID, "force": req.Force, "command": "sensor.learning.complete", "capability_verified": status.ManualCompletionSupported || status.Behavior.ManualCompletionSupported})
		return
	}

	now := time.Now().UTC()
	active := false
	started := true
	deadline := time.Time{}
	check := func(enabled bool, mode string, learningStarted, learningEndsAt time.Time) {
		if !enabled || strings.EqualFold(mode, "monitoring") {
			return
		}
		active = true
		if learningStarted.IsZero() {
			started = false
		}
		if learningEndsAt.After(deadline) {
			deadline = learningEndsAt
		}
	}
	check(status.Enabled, status.Mode, status.LearningStarted, status.LearningEndsAt)
	check(status.Behavior.Enabled, status.Behavior.Mode, status.Behavior.LearningStarted, status.Behavior.LearningEndsAt)
	if !active {
		c.JSON(http.StatusConflict, gin.H{"error": "sensor is not in learning mode"})
		return
	}
	if !started {
		c.JSON(http.StatusConflict, gin.H{"error": "learning has not started yet"})
		return
	}
	if !req.Force && !deadline.IsZero() && now.Before(deadline) {
		c.JSON(http.StatusConflict, gin.H{"error": "minimum learning duration has not elapsed", "learning_ends_at": deadline})
		return
	}

	target := "normal"
	if req.Force {
		target = "force"
	}
	if err := s.Repo.QueueCommands(c.Request.Context(), sensorID, "sensor.learning.complete", []string{target}); err != nil {
		respondInternalError(c, err)
		return
	}
	action := "sensor learning completion queued"
	if req.Force {
		action = "sensor learning force-completion queued"
	}
	s.logAudit(c, identityFromContext(c).Username, action, sensorID)
	c.JSON(http.StatusAccepted, gin.H{"status": "queued", "sensor_id": sensorID, "force": req.Force, "command": "sensor.learning.complete", "capability_verified": status.ManualCompletionSupported || status.Behavior.ManualCompletionSupported})
}

// dashboardTrends backs the Dashboard tab's trend charts — 30 days of
// daily new-alert and new-asset counts, see AlertsByDay/NewAssetsByDay.
func (s *Server) dashboardTrends(c *gin.Context) {
	alertsByDay, err := s.Repo.AlertsByDay(c, 30)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	assetsByDay, err := s.Repo.NewAssetsByDay(c, 30)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, gin.H{"AlertsByDay": alertsByDay, "NewAssetsByDay": assetsByDay})
}

func (s *Server) listReports(c *gin.Context) {
	reports, err := s.Repo.ListReports(c, 50)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, reports)
}

func (s *Server) getReport(c *gin.Context) {
	rep, err := s.Repo.GetReport(c, c.Param("id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "report not found"})
		} else {
			respondInternalError(c, err)
		}
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, rep)
}

// generateReportNow is the manual "Generate now" trigger on the Reports
// tab — covers the 7 days immediately before this call, same window a
// scheduled run would use, rather than needing to wait for the next
// scheduled time just to see what a report looks like.

func (s *Server) deleteReport(c *gin.Context) {
	id := c.Param("id")
	if err := s.Repo.DeleteReport(c, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "report not found"})
			return
		}
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, "report deleted: "+id, "")
	c.Status(http.StatusNoContent)
}

var reportTagRE = regexp.MustCompile(`<[^>]+>`)
var reportStyleRE = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
var reportScriptRE = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)

func reportPlainText(htmlBody string) string {
	// Remove CSS and JavaScript together with their contents before stripping tags.
	// Removing only the tags leaves raw stylesheet text in the generated PDF.
	x := reportStyleRE.ReplaceAllString(htmlBody, "")
	x = reportScriptRE.ReplaceAllString(x, "")
	x = strings.ReplaceAll(x, "&ndash;", "-")
	x = strings.ReplaceAll(x, "&mdash;", "-")
	x = strings.ReplaceAll(x, "&nbsp;", " ")
	x = strings.ReplaceAll(x, "&amp;", "&")
	x = strings.ReplaceAll(x, "&lt;", "<")
	x = strings.ReplaceAll(x, "&gt;", ">")
	x = regexp.MustCompile(`(?i)</(h1|h2|h3|p|div|tr|li)>`).ReplaceAllString(x, "\n")
	x = reportTagRE.ReplaceAllString(x, "")
	lines := strings.Split(x, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if v := strings.TrimSpace(strings.Join(strings.Fields(line), " ")); v != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, "\n")
}

func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 || r > 126 {
			if r == '\n' {
				b.WriteByte('\n')
			} else {
				b.WriteByte('?')
			}
			continue
		}
		if r == '(' || r == ')' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func wrapPDFText(text string, width int) []string {
	var out []string
	words := strings.Fields(text)
	line := ""
	for _, w := range words {
		if line != "" && len(line)+1+len(w) > width {
			out = append(out, line)
			line = w
		} else if line == "" {
			line = w
		} else {
			line += " " + w
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

type reportPDFLine struct {
	text string
	kind string
}

func reportPDFLines(htmlBody string) []reportPDFLine {
	plain := reportPlainText(htmlBody)
	var out []reportPDFLine
	for _, raw := range strings.Split(plain, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		kind := "body"
		switch {
		case strings.EqualFold(line, "Weekly security summary") || strings.EqualFold(line, "OTLens weekly summary"):
			kind = "title"
		case line == "Alert posture" || line == "Open alerts by severity" || line == "Correlated incidents" || strings.HasPrefix(line, "Incidents (") || line == "Sensor health" || line == "Sensors":
			kind = "section"
		case strings.HasPrefix(line, "Generated by OTLens"):
			kind = "note"
		}
		width := 92
		if kind == "title" {
			width = 52
		} else if kind == "section" {
			width = 70
		}
		for _, wrapped := range wrapPDFText(line, width) {
			out = append(out, reportPDFLine{wrapped, kind})
		}
	}
	return out
}

func reportPDF(htmlBody string, reportID string) []byte {
	lines := reportPDFLines(htmlBody)
	const pageW = 595.0
	const left, right = 48.0, 48.0
	const topStart, bottom = 742.0, 58.0

	var pages [][]reportPDFLine
	var current []reportPDFLine
	y := topStart
	for _, ln := range lines {
		h := 15.0
		if ln.kind == "title" {
			h = 31
		} else if ln.kind == "section" {
			h = 27
		} else if ln.kind == "note" {
			h = 13
		}
		if y-h < bottom && len(current) > 0 {
			pages = append(pages, current)
			current = nil
			y = topStart
		}
		current = append(current, ln)
		y -= h
	}
	if len(current) > 0 || len(pages) == 0 {
		pages = append(pages, current)
	}

	objects := []string{"", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"}
	pageIDs := make([]int, len(pages))
	contentIDs := make([]int, len(pages))
	for i, pageLines := range pages {
		pageIDs[i] = len(objects) + 1
		objects = append(objects, "")
		contentIDs[i] = len(objects) + 1
		var c strings.Builder
		// Header band and accent.
		c.WriteString("0.058 0.161 0.259 rg 0 782 595 60 re f\n")
		c.WriteString("0.090 0.310 0.451 rg 0 778 595 4 re f\n")
		c.WriteString("BT /F2 16 Tf 1 1 1 rg 48 810 Td (OTLens Security Operations) Tj ET\n")
		c.WriteString("BT /F1 8 Tf 0.80 0.87 0.92 rg 48 794 Td (Operational security report) Tj ET\n")
		y := topStart
		for _, ln := range pageLines {
			font, size, r, g, b, spacing := "F1", 10.0, 0.12, 0.16, 0.22, 15.0
			switch ln.kind {
			case "title":
				font, size, r, g, b, spacing = "F2", 20, 0.058, 0.161, 0.259, 31
			case "section":
				// light section rule
				fmt.Fprintf(&c, "0.86 0.90 0.93 RG %.1f %.1f m %.1f %.1f l S\n", left, y-7, pageW-right, y-7)
				font, size, r, g, b, spacing = "F2", 13, 0.058, 0.161, 0.259, 27
			case "note":
				font, size, r, g, b, spacing = "F1", 8, 0.40, 0.46, 0.54, 13
			}
			fmt.Fprintf(&c, "BT /%s %.1f Tf %.3f %.3f %.3f rg %.1f %.1f Td (%s) Tj ET\n", font, size, r, g, b, left, y, pdfEscape(ln.text))
			y -= spacing
		}
		// Footer.
		c.WriteString("0.86 0.90 0.93 RG 48 40 m 547 40 l S\n")
		fmt.Fprintf(&c, "BT /F1 8 Tf 0.40 0.46 0.54 rg 48 25 Td (%s) Tj ET\n", pdfEscape(reportID))
		fmt.Fprintf(&c, "BT /F1 8 Tf 0.40 0.46 0.54 rg 486 25 Td (Page %d of %d) Tj ET\n", i+1, len(pages))
		stream := c.String()
		objects = append(objects, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len([]byte(stream)), stream))
	}
	kids := make([]string, len(pages))
	for i, id := range pageIDs {
		kids[i] = fmt.Sprintf("%d 0 R", id)
	}
	objects[0] = "<< /Type /Catalog /Pages 2 0 R >>"
	objects[1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages))
	for i := range pages {
		objects[pageIDs[i]-1] = fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>", contentIDs[i])
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
	offsets := make([]int, len(objects)+1)
	for i, obj := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}

func (s *Server) downloadReportPDF(c *gin.Context) {
	rep, err := s.Repo.GetReport(c, c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "report not found"})
		return
	}
	pdf, err := renderStyledReportPDF(c, rep.HTML, rep.ID)
	if err != nil {
		log.Printf("report PDF browser rendering failed for %s: %v", rep.ID, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "styled PDF renderer unavailable",
			"detail": err.Error(),
		})
		return
	}
	filename := strings.ReplaceAll(rep.ID, "\"", "") + ".pdf"
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/pdf", pdf)
	s.logAudit(c, identityFromContext(c).Username, "report PDF downloaded: "+rep.ID, "")
}

func (s *Server) generateReportNow(c *gin.Context) {
	now := time.Now().UTC()
	if err := s.GenerateAndDispatchReport(c, now.AddDate(0, 0, -7), now); err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, "report generated manually", "")
	c.Status(202)
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
	sensorID := c.Param("id")
	if len(req.Targets) == 0 {
		c.JSON(400, gin.H{"error": "at least one asset target is required"})
		return
	}
	clean := make([]string, 0, len(req.Targets))
	seen := map[string]bool{}
	for _, target := range req.Targets {
		normalized, err := normalizeAssetMAC(target)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		if !seen[normalized] {
			seen[normalized] = true
			clean = append(clean, normalized)
		}
	}
	req.Targets = clean
	if err := s.Repo.QueueCommands(c, sensorID, "asset."+req.Action, req.Targets); err != nil {
		respondInternalError(c, err)
		return
	}
	verb := "asset confirmed"
	if req.Action == "delete" {
		verb = "asset deleted"
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("%s: %s", verb, summarizeTargets(req.Targets)), sensorID)
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
	sensorID := c.Param("id")
	if err := s.Repo.QueueCommands(c, sensorID, "alert."+req.Action, req.Targets); err != nil {
		respondInternalError(c, err)
		return
	}
	// Best-effort: Central already knows who did this and when, right
	// now — no need to wait for the sensor to eventually process the
	// queued command and report the status change back on its next
	// sync. upsertAlertHistory's status-downgrade guard means that
	// later report is a safe no-op against what's set here.
	actor := identityFromContext(c).Username
	status := "confirmed"
	if req.Action == "approve" {
		status = "approved"
	}
	if err := s.Repo.MarkAlertsReviewed(c, sensorID, req.Targets, status, actor); err != nil {
		log.Printf("mark alert_history reviewed: %v", err)
	}
	verb := "alert confirmed"
	if req.Action == "approve" {
		verb = "alert approved (pattern remembered as known)"
	}
	s.logAudit(c, actor, fmt.Sprintf("%s: %s", verb, summarizeTargets(req.Targets)), sensorID)
	c.Status(202)
}
func (s *Server) register(c *gin.Context) {
	var x management.SensorRegistration
	if c.ShouldBindJSON(&x) != nil || strings.TrimSpace(x.ID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registration", "code": "invalid_registration"})
		return
	}
	auth := c.GetHeader("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "code": "sensor_credential_missing"})
		return
	}
	presented := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if presented == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "code": "sensor_credential_missing"})
		return
	}

	existingHash, lookupErr := s.Repo.SensorAuthTokenHash(c, x.ID)
	needsEnrollment := false
	switch {
	case lookupErr == nil && existingHash != "":
		digest := sha256.Sum256([]byte(presented))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(digest[:])), []byte(existingHash)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "existing sensor credential required", "code": "sensor_credential_invalid"})
			return
		}
	case errors.Is(lookupErr, ErrNotFound) || (lookupErr == nil && existingHash == ""):
		needsEnrollment = true
		enrollmentToken := strings.TrimSpace(s.SensorToken)
		if enrollmentToken == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(enrollmentToken)) != 1 {
			log.Printf("sensor enrollment rejected: sensor_id=%s source_ip=%s reason=enrollment credential mismatch", x.ID, c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "valid enrollment credential required", "code": "sensor_enrollment_required"})
			return
		}
	case lookupErr != nil:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sensor enrollment lookup failed", "code": "sensor_enrollment_lookup_failed"})
		return
	}

	if err := s.Repo.RegisterSensor(c, x); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sensor registration failed", "code": "sensor_registration_failed"})
		return
	}

	// A valid existing per-sensor credential is already sufficient proof of
	// identity. Do not rotate it on every synchronization cycle: doing so made
	// registration stateful, wrote the credential file every few seconds and
	// widened the failure window around Central/database resets.
	if !needsEnrollment {
		// A valid per-sensor token merely refreshed registration metadata. Do
		// not emit a "connected" style live event: connectivity is established
		// by authenticated heartbeats, not by POST /register.
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"sensor_id": x.ID, "status": "registered"})
		return
	}

	token, err := newRandomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sensor credential generation failed", "code": "sensor_credential_generation_failed"})
		return
	}
	digest := sha256.Sum256([]byte(token))
	if err := s.Repo.SetSensorAuthToken(c, x.ID, hex.EncodeToString(digest[:])); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sensor credential enrollment failed", "code": "sensor_credential_enrollment_failed"})
		return
	}
	s.publishLive(LiveEvent{Type: "sensor.registered", SensorID: x.ID, EntityID: x.ID, Message: "sensor enrolled"})
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"sensor_id": x.ID, "status": "registered", "sensor_token": token})
}
func (s *Server) heartbeat(c *gin.Context) {
	var x management.Heartbeat
	if c.ShouldBindJSON(&x) != nil || x.SensorID == "" {
		c.JSON(400, gin.H{"error": "invalid heartbeat"})
		return
	}
	if authenticatedID, _ := c.Get("sensor_id"); authenticatedID != x.SensorID {
		c.JSON(http.StatusForbidden, gin.H{"error": "sensor id mismatch"})
		return
	}
	if err := s.Repo.Heartbeat(c, x); err != nil {
		respondInternalError(c, err)
		return
	}
	s.publishLive(LiveEvent{Type: "sensor.health", SensorID: x.SensorID, EntityID: x.SensorID, Message: "sensor heartbeat received"})
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
	actor := identityFromContext(c).Username
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
			respondInternalError(c, err)
			return
		}
		s.logAudit(c, actor, fmt.Sprintf("sensor capture %s: %s", strings.ToLower(strings.TrimSpace(request.Action)), sensorID), sensorID)
		queued++
	}
	if queued == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid sensor IDs"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"queued": queued, "action": request.Action})
}

// deleteSensor removes a sensor's row and everything derived from it —
// see Repository.DeleteSensor's comment. This is not a permanent ban: a
// running sensor detects that its per-sensor credential is no longer known,
// re-enrolls with central.token, and recreates the row with a fresh credential.
func (s *Server) deleteSensor(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sensor id is required"})
		return
	}
	if err := s.Repo.DeleteSensor(c, id); err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("sensor deleted: %s", id), id)
	c.Status(http.StatusNoContent)
}

func metricRange(value string) time.Duration {
	switch value {
	case "15m":
		return 15 * time.Minute
	case "6h":
		return 6 * time.Hour
	case "24h":
		return 24 * time.Hour
	default:
		return time.Hour
	}
}

func nestedMetric(root map[string]interface{}, path ...string) float64 {
	var current interface{} = root
	for _, key := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return 0
		}
		current = m[key]
	}
	switch v := current.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		n, _ := v.Float64()
		return n
	default:
		return 0
	}
}

func nestedBool(root map[string]interface{}, path ...string) bool {
	var current interface{} = root
	for _, key := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return false
		}
		current = m[key]
	}
	switch v := current.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return strings.EqualFold(v, "true") || strings.EqualFold(v, "running") || v == "1"
	default:
		return false
	}
}

func sensorPipelineDiagnostics(sample management.SensorMetricSample) []gin.H {
	pps := nestedMetric(sample.Metrics, "capture", "packets_per_second")
	tcp := nestedMetric(sample.Metrics, "tcp_reassembly", "tcp_packets_per_second")
	segments := nestedMetric(sample.Metrics, "tcp_reassembly", "segments_seen")
	queue := nestedMetric(sample.Metrics, "pipeline", "event_queue_depth")
	assertFailures := nestedMetric(sample.Metrics, "tcp_reassembly", "type_assertion_failures")
	reassemblyEnabled := nestedBool(sample.Metrics, "tcp_reassembly", "enabled")
	status := func(ok, warning bool) string {
		if !ok {
			return "failed"
		}
		if warning {
			return "degraded"
		}
		return "healthy"
	}
	authRecent := !sample.RecordedAt.IsZero() && time.Since(sample.RecordedAt) <= 90*time.Second
	authDetail := "Latest heartbeat was accepted with the sensor-specific Central credential"
	if !authRecent {
		authDetail = "No recent authenticated heartbeat"
	}
	syncDetail := "Telemetry/rule synchronization is healthy"
	if sample.Sync.LastError != "" {
		syncDetail = sample.Sync.LastError
	} else if sample.Sync.ConsecutiveFailures > 0 {
		syncDetail = "Sensor-to-Central synchronization is failing"
	}
	return []gin.H{
		{"stage": "Capture", "status": status(pps > 0, false), "value": pps, "unit": "packets/s", "detail": "Packets received from the capture backend"},
		{"stage": "Event bus", "status": status(pps == 0 || queue < 100000, queue > 50000), "value": queue, "unit": "queued", "detail": "Packet delivery queue between capture and consumers"},
		{"stage": "TCP classification", "status": status(pps == 0 || tcp > 0 || segments > 0, pps > 0 && tcp == 0), "value": tcp, "unit": "packets/s", "detail": "TCP packets accepted by the stream pipeline"},
		{"stage": "TCP reassembly", "status": status(reassemblyEnabled, reassemblyEnabled && segments == 0 && pps > 0), "value": segments, "unit": "segments", "detail": "Reassembly engine state and accepted segments"},
		{"stage": "Packet type contract", "status": status(assertFailures == 0, assertFailures > 0), "value": assertFailures, "unit": "failures", "detail": "Publisher/subscriber packet type compatibility"},
		{"stage": "Central authentication", "status": status(authRecent, false), "value": 0, "unit": "", "detail": authDetail},
		{"stage": "Central sync", "status": status(sample.Sync.ConsecutiveFailures == 0, sample.Sync.ConsecutiveFailures > 0), "value": sample.Sync.ConsecutiveFailures, "unit": "failed cycles", "detail": syncDetail},
	}
}
func (s *Server) sensorMetricsHistory(c *gin.Context) {
	samples, err := s.Repo.SensorMetricHistory(c, c.Param("id"), time.Now().UTC().Add(-metricRange(c.Query("range"))), 10000)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, samples)
}
func (s *Server) sensorMetricsOverview(c *gin.Context) {
	samples, err := s.Repo.LatestSensorMetrics(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, samples)
}
func (s *Server) healthcheck(c *gin.Context) {
	start := time.Now()
	dbOK := s.Repo.db.PingContext(c) == nil
	latency := float64(time.Since(start).Microseconds()) / 1000
	samples, err := s.Repo.LatestSensorMetrics(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	started := s.StartedAt
	if started.IsZero() {
		started = time.Now()
	}
	h := management.CentralHealth{RecordedAt: time.Now().UTC(), UptimeSeconds: int64(time.Since(started).Seconds()), GoRoutines: runtime.NumGoroutine(), MemoryAllocBytes: ms.Alloc, MemorySysBytes: ms.Sys, HeapObjects: ms.HeapObjects, DatabaseOK: dbOK, DatabaseLatencyMS: latency, SensorsTotal: len(samples)}
	for _, x := range samples {
		switch x.HealthState {
		case "healthy":
			h.SensorsHealthy++
		case "warning":
			h.SensorsWarning++
		case "critical":
			h.SensorsCritical++
		case "offline":
			h.SensorsOffline++
		}
	}
	diagnostics := make(map[string][]gin.H, len(samples))
	for _, sample := range samples {
		diagnostics[sample.SensorID] = sensorPipelineDiagnostics(sample)
	}
	c.JSON(200, gin.H{"central": h, "sensors": samples, "diagnostics": diagnostics, "schema_version": s.Repo.SchemaVersion(c)})
}

func (s *Server) sensors(c *gin.Context) {
	v, e := s.Repo.ListSensors(c)
	if e != nil {
		respondInternalError(c, e)
		return
	}
	c.JSON(200, v)
}
func (s *Server) sync(c *gin.Context) {
	sensorID := c.Param("id")
	response := management.SyncResponse{}

	contexts, err := s.Repo.ResolvedAssetContexts(c, sensorID)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	response.AssetContexts = make([]management.AssetPolicyContext, 0, len(contexts))
	for _, x := range contexts {
		response.AssetContexts = append(response.AssetContexts, management.AssetPolicyContext{AssetIP: x.AssetIP, AssetRole: x.AssetRole, Criticality: x.Criticality, Zone: x.Zone, PurdueOverride: x.PurdueOverride})
	}

	configured, err := s.Repo.HasSegmentationConfig(c, sensorID)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	if configured {
		segmentation, err := s.Repo.SegmentationConfig(c, sensorID)
		if err != nil {
			respondInternalError(c, err)
			return
		}
		response.Segmentation = &segmentation
	} else {
		// Always send an explicit unmanaged state. A sensor may have persisted a
		// Central-managed policy from a previous Central; omitting this field would
		// leave that stale policy active forever instead of returning to local YAML.
		response.Segmentation = &management.SegmentationConfig{Managed: false}
	}

	if snapshot, err := s.Repo.ThreatIntelSnapshot(c); err == nil {
		response.ThreatIntelVersion = snapshot.Version
		sensorVersion, _ := strconv.ParseInt(c.Query("threat_intel_version"), 10, 64)
		if sensorVersion != snapshot.Version {
			response.ThreatIntel = &snapshot
		}
	}
	if rs, err := s.Repo.AssignedRuleSet(c, sensorID); err == nil {
		response.RulesVersion = rs.Version
		response.RuleSet = rs
	}

	// Pull one-shot commands only after authoritative state above has been read
	// successfully. Asset confirm/delete remain pending until telemetry proves
	// execution (Repository.PopCommands); this ordering also avoids consuming
	// unrelated commands merely because an asset-context/segmentation query
	// failed before a response could be built.
	commands, err := s.Repo.PopCommands(c, sensorID)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	filteredCommands := make([]management.Command, 0, len(commands))
	for _, command := range commands {
		// Segmentation is authoritative state in SyncResponse.Segmentation. Older
		// builds queued complete segmentation.config snapshots as commands; if
		// several accumulated while a sensor was offline, replaying them after the
		// current snapshot could temporarily roll policy backwards. PopCommands
		// retires those legacy rows but they are never executed by current sensors.
		if command.Type == "segmentation.config" {
			continue
		}
		filteredCommands = append(filteredCommands, command)
	}
	response.Commands = filteredCommands
	c.JSON(http.StatusOK, response)
}

func (s *Server) putRuleset(c *gin.Context) {
	var rs management.RuleSet
	if c.ShouldBindJSON(&rs) != nil || rs.ID == "" {
		c.JSON(400, gin.H{"error": "invalid ruleset"})
		return
	}
	if err := s.Repo.PutRuleSet(c, rs); err != nil {
		respondInternalError(c, err)
		return
	}
	out, e := s.Repo.GetRuleSet(c, rs.ID)
	if e != nil {
		respondInternalError(c, e)
		return
	}
	c.JSON(200, out)
}
func (s *Server) assign(c *gin.Context) {
	if err := s.Repo.AssignRuleSet(c, c.Param("id"), c.Param("ruleset")); err != nil {
		respondInternalError(c, err)
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
		respondInternalError(c, err)
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
		respondInternalError(c, err)
		return
	}
	id := randomAnalysisID()
	path := filepath.Join(s.AnalysisDir, id+ext)
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		respondInternalError(c, err)
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
		respondInternalError(c, err)
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
		respondInternalError(c, err)
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
		respondInternalError(c, err)
		return
	}
	c.Status(204)
}

func (s *Server) clearAnalysisStorage() error {
	if strings.TrimSpace(s.AnalysisDir) == "" {
		return nil
	}
	if err := os.RemoveAll(s.AnalysisDir); err != nil {
		return err
	}
	return os.MkdirAll(s.AnalysisDir, 0700)
}

func clearAnalysisPaths(paths []string) {
	for _, path := range paths {
		if strings.TrimSpace(path) != "" {
			_ = os.Remove(path)
		}
	}
}

func (s *Server) clearResetCaches() {
	// Let the first clean post-reset telemetry immediately rebuild incidents/risk
	// rather than inheriting the pre-reset debounce timestamp.
	s.incidentRefresh.mu.Lock()
	s.incidentRefresh.last = time.Time{}
	s.incidentRefresh.mu.Unlock()

	s.topoCache.mu.Lock()
	s.topoCache.fingerprint = ""
	s.topoCache.etag = ""
	s.topoCache.body = nil
	s.topoCache.mu.Unlock()
	if s.live != nil {
		s.live.ClearReplay()
	}
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

	s.dataResetMu.Lock()
	defer s.dataResetMu.Unlock()

	switch strings.ToLower(req.Scope) {
	case "central":
		op := strings.ToLower(strings.TrimSpace(req.Operation))
		commandByOperation := map[string]string{
			"telemetry": "sensor.telemetry.reset",
			"database":  "sensor.telemetry.reset",
			"alerts":    "sensor.alerts.reset",
			"analysis":  "sensor.analysis.reset",
			"rules":     "sensor.rules.reset",
			"factory":   "sensor.factory.reset",
		}
		queued := 0
		if command, ok := commandByOperation[op]; ok {
			sensors, err := s.Repo.ListSensors(c)
			if err != nil {
				respondInternalError(c, err)
				return
			}
			for _, sensor := range sensors {
				if err := s.Repo.QueueCommands(c, sensor.ID, command, []string{sensor.ID}); err != nil {
					respondInternalError(c, err)
					return
				}
				queued++
			}
		}

		if err := s.Repo.ResetCentral(c, op, s.BootstrapUsername, s.BootstrapPasswordHash); err != nil {
			respondInternalError(c, err)
			return
		}
		if op == "analysis" || op == "factory" {
			if err := s.clearAnalysisStorage(); err != nil {
				respondInternalError(c, fmt.Errorf("clear analysis files: %w", err))
				return
			}
		}
		s.clearResetCaches()
		s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("data reset: central/%s", op), "")
		c.JSON(202, gin.H{
			"status":                  "reset_queued",
			"scope":                   "central",
			"operation":               op,
			"sensors":                 queued,
			"auth_defaults_preserved": true,
			"verified":                true,
		})

	case "sensors":
		if len(req.SensorIDs) == 0 {
			c.JSON(400, gin.H{"error": "sensor_ids are required"})
			return
		}
		op := strings.ToLower(strings.TrimSpace(req.Operation))
		clean := make([]string, 0, len(req.SensorIDs))
		for _, id := range req.SensorIDs {
			if id = strings.TrimSpace(id); id != "" {
				clean = append(clean, id)
			}
		}
		if len(clean) == 0 {
			c.JSON(400, gin.H{"error": "sensor_ids are required"})
			return
		}
		var analysisPaths []string
		if op == "analysis" || op == "factory" {
			analysisPaths, _ = s.Repo.AnalysisPathsForSensors(c, clean)
		}

		command := "sensor." + op + ".reset"
		for _, id := range clean {
			if err := s.Repo.QueueCommands(c, id, command, []string{id}); err != nil {
				respondInternalError(c, err)
				return
			}
		}
		if err := s.Repo.ResetSensors(c, op, clean); err != nil {
			respondInternalError(c, err)
			return
		}
		clearAnalysisPaths(analysisPaths)
		s.clearResetCaches()
		s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("data reset: sensors/%s (%s)", op, strings.Join(clean, ",")), "")
		c.JSON(202, gin.H{"status": "queued", "sensors": len(clean), "command": command, "central_mirror_cleared": true, "verified": true})

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
		if len(req.SensorIDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "at least one sensor_id is required"})
			return
		}
		target := strings.TrimSpace(req.Name)
		if target == "" {
			target = "auto"
		}
		queued := make([]string, 0, len(req.SensorIDs))
		failed := make(map[string]string)
		for _, id := range req.SensorIDs {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if err := s.Repo.QueueCommands(c, id, "sensor.backup.create", []string{target}); err != nil {
				failed[id] = err.Error()
				continue
			}
			queued = append(queued, id)
		}
		status := http.StatusAccepted
		label := "queued"
		if len(failed) > 0 {
			status = http.StatusMultiStatus
			label = "partial"
		}
		s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("sensor backup commands %s: queued=%d failed=%d", label, len(queued), len(failed)), "")
		c.JSON(status, gin.H{"status": label, "queued": queued, "failed": failed})
		return
	}
	id := fmt.Sprintf("bkp-%d", time.Now().UTC().UnixNano())
	b, err := s.Repo.CreateCentralBackup(c, id, req.Name)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("backup created: central (%s)", id), "")
	c.JSON(201, b)
}
func (s *Server) listBackups(c *gin.Context) {
	b, err := s.Repo.ListBackups(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, b)
}
func (s *Server) deleteBackup(c *gin.Context) {
	backupID := c.Param("backup")
	if err := s.Repo.DeleteBackup(c, backupID); err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("backup deleted: %s", backupID), "")
	c.Status(204)
}
func safeExportFilename(name, fallback, extension string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = fallback
	}
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 96 {
			break
		}
	}
	base := strings.Trim(b.String(), ".")
	if base == "" {
		base = fallback
	}
	return base + extension
}

func (s *Server) downloadBackup(c *gin.Context) {
	b, name, err := s.Repo.BackupPayload(c, c.Param("backup"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "backup not found"})
		} else {
			respondInternalError(c, err)
		}
		return
	}
	filename := safeExportFilename(name, "otlens-central-core", ".json")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("Cache-Control", "no-store")
	c.Data(200, "application/json", b)
	s.logAudit(c, identityFromContext(c).Username, "central core snapshot downloaded: "+c.Param("backup"), "")
}

func (s *Server) assetSecurityStatuses(c *gin.Context) {
	rows, err := s.Repo.ListAssetSecurityStatuses(c, strings.TrimSpace(c.Query("sensor_id")))
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, rows)
}

func (s *Server) setAssetSecurityStatus(c *gin.Context) {
	var in struct {
		Status        string     `json:"status"`
		Reason        string     `json:"reason"`
		Source        string     `json:"source"`
		DetectedAt    *time.Time `json:"detected_at"`
		UpdatedBy     string     `json:"updated_by"`
		AutoTrace     bool       `json:"auto_trace"`
		LookbackHours int        `json:"lookback_hours"`
		MaxHops       int        `json:"max_hops"`
	}
	if c.ShouldBindJSON(&in) != nil || validateSecurityStatus(strings.ToLower(in.Status)) != nil {
		c.JSON(400, gin.H{"error": "invalid security status"})
		return
	}
	if in.Source == "" {
		in.Source = "manual"
	}
	v := AssetSecurityStatus{SensorID: c.Param("id"), AssetIP: c.Param("ip"), Status: strings.ToLower(in.Status), Reason: in.Reason, Source: in.Source, DetectedAt: in.DetectedAt, UpdatedBy: in.UpdatedBy}
	if err := s.Repo.SetAssetSecurityStatus(c, v); err != nil {
		respondInternalError(c, err)
		return
	}
	out := gin.H{"status": v}
	if in.AutoTrace && (v.Status == "infected" || v.Status == "suspected") {
		incident, err := s.Repo.CreateContactTrace(c, v.SensorID, v.AssetIP, in.LookbackHours, in.MaxHops)
		if err != nil {
			respondInternalError(c, err)
			return
		}
		out["incident"] = incident
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("asset security status set: %s %s", v.AssetIP, v.Status), v.SensorID)
	c.JSON(200, out)
}

func (s *Server) createMalwareContactTrace(c *gin.Context) {
	var in struct {
		SensorID      string `json:"sensor_id"`
		AssetIP       string `json:"asset_ip"`
		LookbackHours int    `json:"lookback_hours"`
		MaxHops       int    `json:"max_hops"`
	}
	if c.ShouldBindJSON(&in) != nil || strings.TrimSpace(in.SensorID) == "" || strings.TrimSpace(in.AssetIP) == "" {
		c.JSON(400, gin.H{"error": "sensor_id and asset_ip are required"})
		return
	}
	v, err := s.Repo.CreateContactTrace(c, in.SensorID, in.AssetIP, in.LookbackHours, in.MaxHops)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("malware contact trace created: incident %d for %s", v.ID, v.InitialAssetIP), v.SensorID)
	c.JSON(201, v)
}
func (s *Server) getMalwareIncident(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}
	v, err := s.Repo.GetMalwareIncident(c, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "incident not found"})
		} else {
			respondInternalError(c, err)
		}
		return
	}
	c.JSON(200, v)
}
func (s *Server) getMalwareContactGraph(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}
	v, err := s.Repo.GetMalwareIncident(c, id)
	if err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}
	c.JSON(200, v.Graph())
}

func (s *Server) dnsObservations(c *gin.Context) {
	limit := 500
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	rows, err := s.Repo.ListDNSObservations(c, strings.TrimSpace(c.Query("sensor_id")), strings.TrimSpace(c.Query("query")), strings.TrimSpace(c.Query("client_ip")), strings.TrimSpace(c.Query("search")), limit)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, rows)
}

func (s *Server) smbObservations(c *gin.Context) {
	limit := 500
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	rows, err := s.Repo.ListSMBObservations(c, strings.TrimSpace(c.Query("sensor_id")), strings.TrimSpace(c.Query("client_ip")), strings.TrimSpace(c.Query("server_ip")), strings.TrimSpace(c.Query("artifact")), strings.TrimSpace(c.Query("search")), limit)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, rows)
}

func (s *Server) listCorrelationRules(c *gin.Context) {
	rules, err := s.Repo.ListCorrelationRules(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, rules)
}
func (s *Server) saveCorrelationRule(c *gin.Context) {
	var req CorrelationRule
	if c.ShouldBindJSON(&req) != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Severity == "" {
		req.Severity = "high"
	}
	valid := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !valid[req.Severity] {
		c.JSON(400, gin.H{"error": "invalid severity"})
		return
	}
	id, err := s.Repo.SaveCorrelationRule(c, req)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, "correlation rule saved: "+req.Name, "")
	s.publishLive(LiveEvent{Type: "correlation.rules.changed", EntityID: strconv.FormatInt(id, 10), Message: "correlation rule updated"})
	c.JSON(200, gin.H{"ID": id})
}
func (s *Server) deleteCorrelationRule(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "invalid rule id"})
		return
	}
	if err = s.Repo.DeleteCorrelationRule(c, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "custom rule not found"})
			return
		}
		respondInternalError(c, err)
		return
	}
	s.logAudit(c, identityFromContext(c).Username, fmt.Sprintf("correlation rule %d deleted", id), "")
	c.JSON(200, gin.H{"deleted": true})
}

func (s *Server) protocolObservations(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "500"))
	rows, err := s.Repo.ListProtocolObservations(c.Request.Context(), c.Query("sensor_id"), c.Query("protocol"), c.Query("ip"), limit)
	if err != nil {
		respondInternalError(c, fmt.Errorf("listing protocol observations: %w", err))
		return
	}
	c.JSON(http.StatusOK, rows)
}
