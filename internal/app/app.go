// Package app wires every engine together into a running
// application: it owns the shared core.EventBus, constructs each
// engine (capture, parser, flow, asset, ics, store, detect, debug,
// api, persist) with its config-driven settings, and controls their
// startup/shutdown order. This is the one place in the codebase that
// knows about every other internal package — every other package
// only knows about core and whatever specific engines it directly
// depends on.
package app

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/api"
	"github.com/zabojnikvlado/otlens_linux/internal/asset"
	"github.com/zabojnikvlado/otlens_linux/internal/audit"
	"github.com/zabojnikvlado/otlens_linux/internal/capture"
	"github.com/zabojnikvlado/otlens_linux/internal/config"
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/debug"
	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/export"
	"github.com/zabojnikvlado/otlens_linux/internal/flow"
	"github.com/zabojnikvlado/otlens_linux/internal/hostname"
	"github.com/zabojnikvlado/otlens_linux/internal/ics"
	"github.com/zabojnikvlado/otlens_linux/internal/ipfix"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"github.com/zabojnikvlado/otlens_linux/internal/parser"
	"github.com/zabojnikvlado/otlens_linux/internal/persist"
	"github.com/zabojnikvlado/otlens_linux/internal/store"
	"github.com/zabojnikvlado/otlens_linux/internal/vuln"
	"go.uber.org/zap"
)

type Application struct {
	EventBus *core.EventBus

	AssetEngine *asset.Engine

	API *api.Server

	// CaptureMode is "pcap" or "ipfix" — see config.Capture.Mode.
	// Exactly one of CaptureEngine/IPFIXEngine is non-nil, matching
	// this mode.
	CaptureMode string

	// DebugEnabled gates whether DebugEngine.Start() runs — see
	// config.Debug.Enabled's doc comment for why this defaults off.
	DebugEnabled bool

	CaptureEngine *capture.Engine

	IPFIXEngine *ipfix.Engine

	ParserEngine *parser.Engine

	FlowEngine *flow.Engine

	ICSEngine *ics.Engine

	HostnameEngine *hostname.Engine

	StoreEngine *store.Engine

	DetectEngine *detect.Engine

	DebugEngine *debug.Engine

	// ExportEngine is nil when export.enabled is false — entirely
	// optional, see internal/export.
	ExportEngine *export.Engine

	// AuditEngine is always non-nil (New always constructs one), but
	// is a working no-op when audit.enabled is false — see
	// audit.New's doc comment.
	AuditEngine *audit.Engine

	Snapshotter *persist.Snapshotter
}

// New wires up the application. It can now fail — opening the bbolt
// persistence file may error (e.g. the file is locked by another
// running OTLens instance) — so unlike before, the caller must check
// the returned error.
func New(cfg *config.Config) (*Application, error) {

	// Shared by asset.Engine (assigns Asset.Score) and detect.Engine
	// (honeypot.go's lateral-movement detection) — both need the same
	// IP -> Score mapping, built once here rather than each engine
	// parsing config.Deception.Stations independently.
	deceptionScores := make(map[string]int, len(cfg.Deception.Stations))

	for _, station := range cfg.Deception.Stations {
		deceptionScores[station.IP] = station.Score
	}

	assetEngine := asset.NewEngine(deceptionScores)

	eventBus := core.NewEventBus()

	flowEngine := flow.New(eventBus, deceptionScores, cfg.Deception.HoneypotThreshold)

	icsEngine := ics.New(eventBus, cfg.ICS.ModbusPort, cfg.ICS.S7Port)

	hostnameEngine := hostname.New(eventBus)

	storeEngine := store.NewEngine(cfg.Store.MaxValueChanges, cfg.Store.MaxControlEvents)

	detectEngine := detect.NewEngine(
		cfg.Baseline.LearningDuration,
		cfg.Detect.ARPConfirmThreshold,
		cfg.Baseline.Enabled,
		deceptionScores,
		cfg.Deception.HoneypotThreshold,
	)

	var exportEngine *export.Engine

	if cfg.Export.Enabled {

		var err error

		exportEngine, err = export.New(
			export.Config{
				URL:                cfg.Export.URL,
				InsecureSkipVerify: cfg.Export.TLS.InsecureSkipVerify,
				CACertFile:         cfg.Export.TLS.CACertFile,
				Timeout:            cfg.Export.Timeout,
			},
		)

		if err != nil {
			return nil, fmt.Errorf("setting up alert export failed: %w", err)
		}
	}

	auditEngine, err := audit.New(
		cfg.Audit.Enabled,
		cfg.Audit.Path,
		logger.RotationConfig{
			Enabled:    cfg.Logging.Rotation.Enabled,
			MaxSizeMB:  cfg.Logging.Rotation.MaxSizeMB,
			MaxBackups: cfg.Logging.Rotation.MaxBackups,
			MaxAgeDays: cfg.Logging.Rotation.MaxAgeDays,
			Compress:   cfg.Logging.Rotation.Compress,
		},
	)

	if err != nil {
		return nil, fmt.Errorf("setting up audit log failed: %w", err)
	}

	vulnDB := vuln.New()

	if cfg.Vulnerability.Enabled {

		count, err := vulnDB.LoadCSV(cfg.Vulnerability.DataPath)

		if err != nil {
			return nil, fmt.Errorf("loading vulnerability snapshot failed: %w", err)
		}

		logger.Log.Info(
			"Vulnerability snapshot loaded",
			zap.String("path", cfg.Vulnerability.DataPath),
			zap.Int("advisories", count),
		)
	}

	parserEngine := parser.New(eventBus)

	debugEngine := debug.New(eventBus)

	// Exactly one of these is used, based on cfg.Capture.Mode — see
	// Application.CaptureMode's doc comment.
	var captureEngine *capture.Engine
	var ipfixEngine *ipfix.Engine

	switch cfg.Capture.Mode {

	case "ipfix":

		ipfixEngine = ipfix.New(cfg.Capture.IPFIX.ListenAddr, eventBus)

	default:

		captureEngine = capture.New(
			cfg.Capture.Interface,
			eventBus,
		)

		captureEngine.Snaplen = cfg.Capture.Snaplen
		captureEngine.Promiscuous = cfg.Capture.Promiscuous
		captureEngine.BPFFilter = cfg.Capture.BPFFilter
	}

	// Phase 1 storage migration: if the configured SQLite path is new and
	// the previous bbolt file exists next to it, import the legacy snapshot
	// once. The legacy file is never deleted automatically.
	if err := persist.MigrateLegacyPersistence(cfg.Persist.Path); err != nil {
		return nil, fmt.Errorf("migrating legacy persistence failed: %w", err)
	}

	snapshotter, err := persist.NewSnapshotter(
		cfg.Persist.Path,
		assetEngine,
		flowEngine,
		storeEngine,
		detectEngine,
		cfg.Persist.FlushInterval,
		cfg.Persist.Retention,
	)

	if err != nil {
		return nil, fmt.Errorf("initializing persistence failed: %w", err)
	}

	return &Application{
		EventBus: eventBus,

		AssetEngine: assetEngine,

		ParserEngine: parserEngine,

		FlowEngine: flowEngine,

		ICSEngine: icsEngine,

		HostnameEngine: hostnameEngine,

		StoreEngine: storeEngine,

		DetectEngine: detectEngine,

		DebugEngine: debugEngine,

		ExportEngine: exportEngine,

		AuditEngine: auditEngine,

		Snapshotter: snapshotter,

		CaptureMode: cfg.Capture.Mode,

		DebugEnabled: cfg.Debug.Enabled,

		API: api.New(
			assetEngine,
			flowEngine,
			storeEngine,
			detectEngine,
			captureEngine,
			ipfixEngine,
			snapshotter,
			eventBus,
			vulnDB,
			api.Config{
				Host: cfg.API.Host,
				Port: cfg.API.Port,

				Mode:       cfg.API.Mode,
				CORSOrigin: cfg.API.CORSOrigin,

				Username: cfg.API.Username,
				Password: cfg.API.Password,

				ModbusPort: icsEngine.ModbusPort,
				S7Port:     icsEngine.S7Port,

				HoneypotThreshold: cfg.Deception.HoneypotThreshold,

				VulnerabilityEnabled: cfg.Vulnerability.Enabled,

				CaptureMode: cfg.Capture.Mode,

				TLSEnabled:      cfg.API.TLS.Enabled,
				TLSCertFile:     cfg.API.TLS.CertFile,
				TLSKeyFile:      cfg.API.TLS.KeyFile,
				TLSMinVersion:   cfg.API.TLS.MinVersion,
				TLSCipherSuites: cfg.API.TLS.CipherSuites,
			},
		),

		CaptureEngine: captureEngine,
		IPFIXEngine:   ipfixEngine,
	}, nil

}

func (a *Application) Start() {

	// Rehydrate every engine's in-memory state from disk before
	// anything starts consuming live traffic, so the very first
	// packets processed see the same state a long-running process
	// would have had.
	if err := a.Snapshotter.Restore(); err != nil {

		logger.Log.Warn(
			"Restoring persisted state failed, starting from empty state",
			zap.Error(err),
		)
	}

	a.AssetEngine.Start(
		a.EventBus,
	)

	a.HostnameEngine.Start()

	a.ParserEngine.Start()

	go a.API.Start()

	a.FlowEngine.Start()

	a.ICSEngine.Start()

	a.StoreEngine.Start(
		a.EventBus,
	)

	a.DetectEngine.Start(
		a.EventBus,
	)

	// If baseline learning had already completed in a previous run
	// (state restored from disk above), asset.Engine needs to hear
	// about that now — the one-time publish that would normally
	// trigger this happened in that earlier process, not this one.
	// Must come after both engines' Start() (asset.Engine has to
	// already be subscribed to receive it) — see
	// PublishBaselineStateIfEstablished's doc comment.
	a.DetectEngine.PublishBaselineStateIfEstablished()

	if a.ExportEngine != nil {

		a.ExportEngine.Start(
			a.EventBus,
			a.DetectEngine.GetAlerts(),
		)
	}

	// Always started — a.AuditEngine is a working no-op when
	// audit.enabled is false, see audit.New's doc comment. Subscribes
	// to core.EventAuditAction, which internal/api's handlers publish
	// to regardless of whether anything's listening.
	a.AuditEngine.Start(a.EventBus)

	a.Snapshotter.Start()

	go func() {

		if a.CaptureEngine != nil {

			if err := a.CaptureEngine.Start(); err != nil {

				logger.Log.Fatal(
					"Capture engine failed",
					zap.Error(err),
				)
			}

			return
		}

		if err := a.IPFIXEngine.Start(); err != nil {

			logger.Log.Fatal(
				"IPFIX collector failed",
				zap.Error(err),
			)
		}

	}()

	if a.DebugEnabled {
		a.DebugEngine.Start()
	}

	logger.Log.Info(
		"Application started",
	)

	time.Sleep(time.Second)
}

// Shutdown flushes the latest state to disk and closes the
// persistence file cleanly. Call this from a signal handler (e.g.
// SIGINT/SIGTERM) so a deliberate stop doesn't lose the last few
// seconds of state that hadn't been flushed yet.
func (a *Application) Shutdown() {

	logger.Log.Info(
		"Shutting down, flushing persisted state",
	)

	if err := a.Snapshotter.Close(); err != nil {

		logger.Log.Warn(
			"Closing persistence failed",
			zap.Error(err),
		)
	}
}
