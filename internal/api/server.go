// Package api exposes every engine's current state over a read-mostly
// HTTP/JSON REST API (gin), for a dashboard/visualization to consume,
// and serves that dashboard itself (see web/) under /ui:
//
//	GET  /ui                the dashboard (static files, see web/)
//	GET  /assets            discovered devices, enriched with OT/IT classification
//	DELETE /assets/:mac      manually remove one asset (admin/cleanup)
//	POST /assets/:mac/confirm  confirm a device flagged unconfirmed (new after baseline learning)
//	GET  /flows              tracked network conversations
//	GET  /topology           combined node+edge graph for visualization
//	GET  /tags               OT process variables (registers) and their current values
//	GET  /tags/changes       historical value-change log (optional ?key=... to filter to one tag)
//	GET  /tags/events        historical write/control-operation log (optional ?key=... to filter to one tag)
//	GET  /alerts             detected anomalies (ARP spoofing, baseline deviations, ICS critical ops)
//	POST /alerts/:id/approve  mark an alert reviewed and accepted as expected/benign
//	POST /alerts/:id/confirm  mark an alert reviewed and confirmed as a genuine issue
//	GET  /baseline           baseline learning mode/progress
//	GET  /health             liveness check
//	GET  /admin/capture/status   current capture mode + running state
//	POST /admin/capture/stop     stop live capture (npcap mode only)
//	POST /admin/capture/start    resume live capture (npcap mode only)
//	POST /admin/capture/analyze  analyze an uploaded .pcap/.pcapng file (npcap mode only, capture must be stopped)
//	POST /admin/wipe             erase all assets/flows/OT tags/alerts from memory and disk (capture must be stopped)
package api

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/zabojnikvlado/otlens_linux/internal/asset"
	"github.com/zabojnikvlado/otlens_linux/internal/capture"
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/flow"
	"github.com/zabojnikvlado/otlens_linux/internal/ipfix"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"github.com/zabojnikvlado/otlens_linux/internal/oui"
	"github.com/zabojnikvlado/otlens_linux/internal/persist"
	"github.com/zabojnikvlado/otlens_linux/internal/store"
	"github.com/zabojnikvlado/otlens_linux/internal/topology"
	"github.com/zabojnikvlado/otlens_linux/internal/vuln"
	"go.uber.org/zap"
)

// Config bundles every setting api.New needs, so the constructor
// doesn't keep growing a list of same-typed positional parameters
// (host/port/mode/corsOrigin/... are all strings/ints — easy to
// silently swap two by accident at a 13-argument call site).
type Config struct {
	Host string
	Port int

	// Mode is gin's run mode ("debug"/"release"/"test" — gin.SetMode
	// validates against exactly these strings). Empty leaves gin's
	// own default (debug).
	Mode string

	// CORSOrigin is the Access-Control-Allow-Origin value sent on
	// every response — see cors.go.
	CORSOrigin string

	// Username/Password, if both non-empty, require HTTP Basic Auth
	// on every request except /health — see registerAuthMiddleware.
	Username string
	Password string

	// ModbusPort/S7Port must match whatever the ics.Engine was
	// actually configured with, so /topology's OT classification
	// stays consistent with what the ics decoder is really matching
	// on — see topology.Build.
	ModbusPort uint16
	S7Port     uint16

	// HoneypotThreshold — see config.Deception.HoneypotThreshold and
	// topology.Build's honeypotThreshold parameter.
	HoneypotThreshold int

	// VulnerabilityEnabled mirrors config.Vulnerability.Enabled — lets
	// /assets/:mac/vulnerabilities tell the frontend "this feature
	// isn't turned on" apart from "turned on, nothing found for this
	// vendor" (vulnDB.Lookup returns an empty slice in both cases, so
	// the handler needs this to distinguish them in its response).
	VulnerabilityEnabled bool

	// CaptureMode is "npcap" or "ipfix" — see config.Capture.Mode.
	// The admin capture start/stop/analyze-pcap controls only make
	// sense in npcap mode (there's no equivalent "pause" concept for
	// an IPFIX collector in this first pass) — see the /admin/capture
	// handlers.
	CaptureMode string

	// TLS — see tls.go. If Enabled and the cert/key files don't
	// already exist, a self-signed pair is generated automatically.
	// MinVersion is "1.0"/"1.1"/"1.2"/"1.3" (default "1.2").
	// CipherSuites is a list of Go/IANA cipher suite names; only
	// meaningful when the negotiated connection is TLS 1.2 or below
	// (TLS 1.3's suites are fixed by the protocol) — see
	// resolveCipherSuites's doc comment.
	TLSEnabled      bool
	TLSCertFile     string
	TLSKeyFile      string
	TLSMinVersion   string
	TLSCipherSuites []string
}

// dataSource is satisfied by both *capture.Engine and *ipfix.Engine —
// the common "start/stop/query" surface the admin capture controls
// need, regardless of which data source (config.Capture.Mode) is
// active. AnalyzeFile (uploading a saved pcap) stays capture.Engine-
// specific — see the /admin/capture/analyze handler in admin.go —
// since analyzing a packet capture file doesn't have an ipfix
// equivalent.
type dataSource interface {
	IsRunning() bool
	Stop()
	Start() error
}

type Server struct {
	assetEngine   *asset.Engine
	flowEngine    *flow.Engine
	storeEngine   *store.Engine
	detectEngine  *detect.Engine
	captureEngine *capture.Engine // nil when CaptureMode is "ipfix" — only used for AnalyzeFile
	dataSource    dataSource      // whichever of captureEngine/ipfixEngine is actually active
	snapshotter   *persist.Snapshotter

	// eventBus lets handlers publish core.EventAuditAction — see
	// publishAudit.
	eventBus *core.EventBus

	// vulnDB is always non-nil (a working no-op when
	// vulnerability.enabled is false) — see vuln.New's doc comment.
	vulnDB *vuln.Database

	cfg Config
}

func New(
	assetEngine *asset.Engine,
	flowEngine *flow.Engine,
	storeEngine *store.Engine,
	detectEngine *detect.Engine,
	captureEngine *capture.Engine,
	ipfixEngine *ipfix.Engine,
	snapshotter *persist.Snapshotter,
	eventBus *core.EventBus,
	vulnDB *vuln.Database,
	cfg Config,
) *Server {

	// Deliberately not a plain "dataSource = captureEngine" — a nil
	// *capture.Engine assigned into an interface variable produces a
	// NON-nil interface (it carries the concrete type alongside the
	// nil pointer), so a later "dataSource != nil" check would
	// wrongly succeed. Only assign when the concrete pointer is
	// actually non-nil.
	var ds dataSource

	if captureEngine != nil {
		ds = captureEngine
	} else if ipfixEngine != nil {
		ds = ipfixEngine
	}

	return &Server{
		assetEngine:   assetEngine,
		flowEngine:    flowEngine,
		storeEngine:   storeEngine,
		detectEngine:  detectEngine,
		captureEngine: captureEngine,
		dataSource:    ds,
		snapshotter:   snapshotter,
		eventBus:      eventBus,
		vulnDB:        vulnDB,

		cfg: cfg,
	}

}

func (s *Server) Start() {

	switch s.cfg.Mode {

	case gin.ReleaseMode, gin.TestMode:
		gin.SetMode(s.cfg.Mode)

	case gin.DebugMode, "":
		// Leave gin's own default (debug).

	default:

		logger.Log.Warn(
			"Unknown api.mode, falling back to debug",
			zap.String("mode", s.cfg.Mode),
		)
	}

	r := gin.Default()

	r.Use(corsMiddleware(s.cfg.CORSOrigin))

	if s.cfg.Username != "" && s.cfg.Password != "" {
		r.Use(s.basicAuthMiddleware(s.cfg.Username, s.cfg.Password))
	}

	// Prevent the browser from caching stale dashboard JS/CSS/HTML
	// after a rebuild — without this, an updated web/app.js can sit
	// invisibly cached in the browser and old behavior (or a fixed
	// bug) appears to "still not work" purely because the browser
	// never re-fetched it. A hard refresh (Ctrl+Shift+R) works around
	// it, but this makes that unnecessary going forward.
	r.Use(func(c *gin.Context) {

		if strings.HasPrefix(c.Request.URL.Path, "/ui") {
			c.Header("Cache-Control", "no-cache, must-revalidate")
		}

		c.Next()
	})

	// Dashboard static files (web/) — mounted under /ui rather than
	// "/" so it can't collide with the JSON API routes below (e.g.
	// GET /assets already means "asset list JSON", not a static
	// file). Visit http://<host>:<port>/ui/ for the dashboard.
	// Relative to the process's working directory, same convention
	// as configs/config.yaml and persist.path.
	r.Static("/ui", "./web")

	s.registerAdminRoutes(r)

	r.GET(
		"/assets",
		func(c *gin.Context) {

			assets := s.assetEngine.GetAll()

			isOT, protocols := topology.Classify(s.storeEngine.GetTags())

			views := make([]AssetView, 0, len(assets))

			for _, a := range assets {

				views = append(
					views,
					AssetView{
						Asset: a,

						IsOT:      isOT[a.IP],
						Protocols: protocols[a.IP],
						Vendor:    oui.Lookup(a.MAC),
					},
				)

			}

			c.JSON(http.StatusOK, views)

		},
	)

	r.DELETE(
		"/assets/:mac",
		func(c *gin.Context) {

			mac := c.Param("mac")

			if !s.assetEngine.Delete(mac) {

				c.JSON(
					http.StatusNotFound,
					gin.H{"error": "asset not found"},
				)

				return
			}

			s.publishAudit(c, "asset.delete", true, map[string]string{"mac": mac})

			c.Status(http.StatusNoContent)

		},
	)

	r.POST(
		"/assets/:mac/confirm",
		func(c *gin.Context) {

			mac := c.Param("mac")

			if !s.assetEngine.Confirm(mac) {

				c.JSON(
					http.StatusNotFound,
					gin.H{"error": "asset not found"},
				)

				return
			}

			s.publishAudit(c, "asset.confirm", true, map[string]string{"mac": mac})

			c.Status(http.StatusNoContent)

		},
	)

	r.GET(
		"/assets/:mac/vulnerabilities",
		func(c *gin.Context) {

			mac := c.Param("mac")

			a := s.assetEngine.Get(mac)

			if a == nil {

				c.JSON(
					http.StatusNotFound,
					gin.H{"error": "asset not found"},
				)

				return
			}

			vendor := oui.Lookup(mac)

			c.JSON(
				http.StatusOK,
				gin.H{
					"vendor":     vendor,
					"advisories": s.vulnDB.Lookup(vendor),
					"enabled":    s.cfg.VulnerabilityEnabled,
				},
			)

		},
	)

	r.GET(
		"/flows",
		func(c *gin.Context) {

			c.JSON(
				http.StatusOK,
				s.flowEngine.GetAll(),
			)

		},
	)

	r.GET(
		"/topology",
		func(c *gin.Context) {

			graph := topology.Build(
				s.assetEngine.GetAll(),
				s.flowEngine.GetAll(),
				s.storeEngine.GetTags(),
				s.cfg.ModbusPort,
				s.cfg.S7Port,
				s.cfg.HoneypotThreshold,
			)

			c.JSON(http.StatusOK, graph)

		},
	)

	r.GET(
		"/tags",
		func(c *gin.Context) {

			c.JSON(
				http.StatusOK,
				s.storeEngine.GetTags(),
			)

		},
	)

	r.GET(
		"/tags/changes",
		func(c *gin.Context) {

			changes := s.storeEngine.GetValueChanges()

			// Optional ?key=... filters to one tag's history — used by
			// the Tag History popup (OT Tags tab). Without it, returns
			// everything, same as before.
			if key := c.Query("key"); key != "" {

				filtered := make([]store.ValueChange, 0, len(changes))

				for _, vc := range changes {
					if vc.TagKey == key {
						filtered = append(filtered, vc)
					}
				}

				changes = filtered
			}

			c.JSON(
				http.StatusOK,
				changes,
			)

		},
	)

	r.GET(
		"/tags/events",
		func(c *gin.Context) {

			events := s.storeEngine.GetControlEvents()

			if key := c.Query("key"); key != "" {

				filtered := make([]store.ControlEvent, 0, len(events))

				for _, ce := range events {
					if ce.TagKey == key {
						filtered = append(filtered, ce)
					}
				}

				events = filtered
			}

			c.JSON(
				http.StatusOK,
				events,
			)

		},
	)

	r.GET(
		"/alerts",
		func(c *gin.Context) {

			c.JSON(
				http.StatusOK,
				s.detectEngine.GetAlerts(),
			)

		},
	)

	r.POST(
		"/alerts/:id/approve",
		func(c *gin.Context) {

			id := c.Param("id")

			if !s.detectEngine.ApproveAlert(id) {

				c.JSON(
					http.StatusNotFound,
					gin.H{"error": "alert not found"},
				)

				return
			}

			s.publishAudit(c, "alert.approve", true, map[string]string{"id": id})

			c.Status(http.StatusNoContent)

		},
	)

	r.POST(
		"/alerts/:id/confirm",
		func(c *gin.Context) {

			id := c.Param("id")

			if !s.detectEngine.ConfirmAlert(id) {

				c.JSON(
					http.StatusNotFound,
					gin.H{"error": "alert not found"},
				)

				return
			}

			s.publishAudit(c, "alert.confirm", true, map[string]string{"id": id})

			c.Status(http.StatusNoContent)

		},
	)

	r.GET(
		"/rules",
		func(c *gin.Context) {
			c.JSON(http.StatusOK, s.detectEngine.GetRules())
		},
	)

	r.POST(
		"/rules",
		func(c *gin.Context) {

			var req struct {
				Name     string `json:"name"`
				Field    string `json:"field"`
				Value    string `json:"value"`
				Severity string `json:"severity"`
			}

			if err := c.ShouldBindJSON(&req); err != nil {

				c.JSON(
					http.StatusBadRequest,
					gin.H{"error": "invalid request body"},
				)

				return
			}

			rule, err := s.detectEngine.AddCustomRule(
				req.Name,
				detect.RuleField(req.Field),
				req.Value,
				req.Severity,
			)

			if err != nil {

				c.JSON(
					http.StatusBadRequest,
					gin.H{"error": err.Error()},
				)

				return
			}

			s.publishAudit(
				c,
				"rule.create",
				true,
				map[string]string{"id": rule.ID, "name": rule.Name},
			)

			c.JSON(http.StatusCreated, rule)

		},
	)

	r.POST(
		"/rules/:id/toggle",
		func(c *gin.Context) {

			id := c.Param("id")

			var req struct {
				Enabled bool `json:"enabled"`
			}

			if err := c.ShouldBindJSON(&req); err != nil {

				c.JSON(
					http.StatusBadRequest,
					gin.H{"error": "invalid request body"},
				)

				return
			}

			if !s.detectEngine.ToggleRule(id, req.Enabled) {

				c.JSON(
					http.StatusNotFound,
					gin.H{"error": "rule not found"},
				)

				return
			}

			s.publishAudit(
				c,
				"rule.toggle",
				true,
				map[string]string{"id": id, "enabled": fmt.Sprintf("%v", req.Enabled)},
			)

			c.Status(http.StatusNoContent)

		},
	)

	r.DELETE(
		"/rules/:id",
		func(c *gin.Context) {

			id := c.Param("id")

			if !s.detectEngine.DeleteRule(id) {

				c.JSON(
					http.StatusNotFound,
					gin.H{"error": "rule not found, or is a built-in rule (toggle it off instead)"},
				)

				return
			}

			s.publishAudit(c, "rule.delete", true, map[string]string{"id": id})

			c.Status(http.StatusNoContent)

		},
	)

	r.GET(
		"/baseline",
		func(c *gin.Context) {

			c.JSON(
				http.StatusOK,
				s.detectEngine.BaselineStatus(),
			)

		},
	)

	r.GET(
		"/health",
		func(c *gin.Context) {

			c.JSON(http.StatusOK, gin.H{"status": "ok"})

		},
	)

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	if !s.cfg.TLSEnabled {

		logger.Log.Info(
			"API listening",
			zap.String("addr", addr),
			zap.Bool("tls", false),
		)

		r.Run(addr)

		return
	}

	if err := ensureSelfSignedCert(s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil {

		logger.Log.Fatal(
			"TLS certificate setup failed",
			zap.Error(err),
		)
	}

	tlsConfig := &tls.Config{
		MinVersion: resolveTLSMinVersion(s.cfg.TLSMinVersion),
	}

	if len(s.cfg.TLSCipherSuites) > 0 {
		tlsConfig.CipherSuites = resolveCipherSuites(s.cfg.TLSCipherSuites)
	}

	// A plain gin.Default().RunTLS(...) can't have its cipher suites
	// or minimum version configured — it just calls
	// http.ListenAndServeTLS with gin's own default http.Server.
	// Building the http.Server ourselves, with gin's router as its
	// Handler, is what lets api.tls.minversion/ciphersuites actually
	// take effect.
	httpServer := &http.Server{
		Addr:      addr,
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	logger.Log.Info(
		"API listening",
		zap.String("addr", addr),
		zap.Bool("tls", true),
		zap.String("tls_min_version", s.cfg.TLSMinVersion),
	)

	if err := httpServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil {

		logger.Log.Fatal(
			"API TLS server failed",
			zap.Error(err),
		)
	}

}
