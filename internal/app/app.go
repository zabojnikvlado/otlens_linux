// Package app wires every engine together into a running
// application: it owns the shared core.EventBus, constructs each
// engine (capture, parser, flow, asset, ics, store, detect, debug,
// persist) with its config-driven settings, and controls their
// startup/shutdown order. This is the one place in the codebase that
// knows about every other internal package — every other package
// only knows about core and whatever specific engines it directly
// depends on.
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/asset"
	"github.com/zabojnikvlado/otlens_linux/internal/capture"
	"github.com/zabojnikvlado/otlens_linux/internal/config"
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/dcerpc"
	"github.com/zabojnikvlado/otlens_linux/internal/debug"
	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	passivedns "github.com/zabojnikvlado/otlens_linux/internal/dns"
	"github.com/zabojnikvlado/otlens_linux/internal/flow"
	"github.com/zabojnikvlado/otlens_linux/internal/hostname"
	"github.com/zabojnikvlado/otlens_linux/internal/ics"
	"github.com/zabojnikvlado/otlens_linux/internal/ipfix"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"github.com/zabojnikvlado/otlens_linux/internal/parser"
	"github.com/zabojnikvlado/otlens_linux/internal/persist"
	"github.com/zabojnikvlado/otlens_linux/internal/protocolobs"
	"github.com/zabojnikvlado/otlens_linux/internal/smb"
	"github.com/zabojnikvlado/otlens_linux/internal/store"
	"github.com/zabojnikvlado/otlens_linux/internal/tcpreassembly"
	"github.com/zabojnikvlado/otlens_linux/internal/threatintel"
	"github.com/zabojnikvlado/otlens_linux/internal/udpconversation"
	"github.com/zabojnikvlado/otlens_linux/internal/vuln"
	"go.uber.org/zap"
)

type Application struct {
	EventBus *core.EventBus

	AssetEngine *asset.Engine

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

	DNSEngine         *passivedns.Engine
	SMBEngine         *smb.Engine
	DCERPCEngine      *dcerpc.Engine
	ProtocolEngine    *protocolobs.Engine
	TCPReassembler    *tcpreassembly.Engine
	UDPConversations  *udpconversation.Engine
	ThreatIntel       *threatintel.Store
	VulnerabilityDB   *vuln.Database
	threatIntelCancel context.CancelFunc

	StoreEngine *store.Engine

	DetectEngine *detect.Engine

	DebugEngine *debug.Engine

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

	assetEngine := asset.NewEngine(deceptionScores, cfg.Deception.HoneypotThreshold)

	eventBus := core.NewEventBus()

	flowEngine := flow.New(eventBus, deceptionScores, cfg.Deception.HoneypotThreshold)

	icsEngine := ics.New(eventBus, ics.Config{
		ModbusPort:     cfg.ICS.ModbusPort,
		S7Port:         cfg.ICS.S7Port,
		EtherNetIPPort: cfg.ICS.EtherNetIPPort,
		DNP3Port:       cfg.ICS.DNP3Port,
		OPCUAPort:      cfg.ICS.OPCUAPort,
		BACnetPort:     cfg.ICS.BACnetPort,
		IEC104Port:     cfg.ICS.IEC104Port,
	})

	hostnameEngine := hostname.New(eventBus)

	dnsEngine := passivedns.NewWithTimeout(eventBus, cfg.Detect.ThreatIntel.MaxDNSObservations, cfg.Capture.UDPConversations.Protocols.DNS.Timeout)
	tcpReassembler := tcpreassembly.New(eventBus, tcpreassembly.Config{Enabled: cfg.Capture.TCPReassembly.Enabled, MaxConnections: cfg.Capture.TCPReassembly.MaxConnections, MaxBufferPerDirection: cfg.Capture.TCPReassembly.MaxBufferPerDirection, MaxTotalBuffer: cfg.Capture.TCPReassembly.MaxTotalBuffer, IdleTimeout: cfg.Capture.TCPReassembly.IdleTimeout, ClosedTimeout: cfg.Capture.TCPReassembly.ClosedTimeout, MaxOutOfOrderSegments: cfg.Capture.TCPReassembly.MaxOutOfOrderSegments, MaxSequenceGap: cfg.Capture.TCPReassembly.MaxSequenceGap, GapRecoveryTimeout: cfg.Capture.TCPReassembly.GapRecoveryTimeout, ShardCount: cfg.Capture.TCPReassembly.ShardCount, OverlapPolicy: cfg.Capture.TCPReassembly.OverlapPolicy})
	udpConversations := udpconversation.New(eventBus, udpconversation.ManagerConfig{
		Disabled:                  !cfg.Capture.UDPConversations.Enabled,
		MaxActive:                 cfg.Capture.UDPConversations.MaxActive,
		MaxPacketsPerConversation: cfg.Capture.UDPConversations.MaxPacketsPerConversation,
		IdleTimeout:               cfg.Capture.UDPConversations.IdleTimeout,
	})
	smbEngine := smb.New(eventBus, cfg.Capture.TCPReassembly.Enabled)
	dcerpcEngine := dcerpc.New(eventBus)
	protocolEngine := protocolobs.NewWithConfig(eventBus, protocolobs.CorrelatorConfig{
		Timeout:     cfg.Capture.UDPConversations.Protocols.DNS.Timeout,
		DHCPTimeout: cfg.Capture.UDPConversations.Protocols.DHCP.Timeout,
		SNMPTimeout: cfg.Capture.UDPConversations.Protocols.SNMP.Timeout,
		SIPTimeout:  cfg.Capture.UDPConversations.Protocols.SIP.Timeout,
		MaxPending:  cfg.Capture.UDPConversations.MaxPendingRequests,
	})
	var tiStore *threatintel.Store
	if cfg.Detect.ThreatIntel.Enabled {
		// Feed definitions are managed centrally. The sensor keeps only a
		// local in-memory snapshot received during its normal Central sync.
		tiStore = threatintel.New(nil, nil, cfg.Detect.ThreatIntel.RefreshInterval, cfg.Detect.ThreatIntel.HTTPTimeout)
	}

	storeEngine := store.NewEngine(cfg.Store.MaxValueChanges, cfg.Store.MaxControlEvents)

	detectEngine := detect.NewEngine(
		cfg.Baseline.LearningDuration,
		cfg.Detect.ARPConfirmThreshold,
		cfg.Baseline.Enabled,
		deceptionScores,
		cfg.Deception.HoneypotThreshold,
		cfg.Detect.Segmentation.Enabled,
		cfg.Detect.Segmentation.VLANLevels,
		cfg.Detect.Segmentation.MaxLevelJump,
		cfg.Detect.Reconnaissance.Enabled,
		cfg.Detect.Reconnaissance.Window,
		cfg.Detect.Reconnaissance.HostScanThreshold,
		cfg.Detect.Reconnaissance.PortScanThreshold,
		cfg.Detect.C2Beacon.Enabled,
		cfg.Detect.C2Beacon.MinSamples,
		cfg.Detect.C2Beacon.MaxCoefficientOfVariation,
		cfg.Detect.C2Beacon.MinInterval,
		cfg.Detect.C2Beacon.MaxInterval,
		cfg.Detect.C2Beacon.MaxTrackedDestinations,
	)
	detectEngine.SetThreatIntel(tiStore)
	detectEngine.ConfigureOTValueAnomaly(detect.OTValueAnomalyConfig{Enabled: cfg.Detect.OTValueAnomaly.Enabled, MinSamples: cfg.Detect.OTValueAnomaly.MinSamples, ZScoreThreshold: cfg.Detect.OTValueAnomaly.ZScoreThreshold, RateMultiplier: cfg.Detect.OTValueAnomaly.RateMultiplier, StuckAfter: cfg.Detect.OTValueAnomaly.StuckAfter, MissingAfter: cfg.Detect.OTValueAnomaly.MissingAfter, ToggleWindow: cfg.Detect.OTValueAnomaly.ToggleWindow, ToggleThreshold: cfg.Detect.OTValueAnomaly.ToggleThreshold, UnexpectedWrites: cfg.Detect.OTValueAnomaly.UnexpectedWrites, CheckInterval: cfg.Detect.OTValueAnomaly.CheckInterval})
	detectEngine.ConfigureLateralMovement(detect.LateralMovementConfig{Enabled: cfg.Detect.LateralMovement.Enabled, Window: cfg.Detect.LateralMovement.Window, FanOutThreshold: cfg.Detect.LateralMovement.FanOutThreshold, LargeTransferBytes: cfg.Detect.LateralMovement.LargeTransferBytes, PivotWindow: cfg.Detect.LateralMovement.PivotWindow, AdminPorts: cfg.Detect.LateralMovement.AdminPorts})
	detectEngine.ConfigureC2Correlation(detect.C2CorrelationConfig{Enabled: cfg.Detect.C2Correlation.Enabled, MinScore: cfg.Detect.C2Correlation.MinScore, DNSWindow: cfg.Detect.C2Correlation.DNSWindow, NXDomainThreshold: cfg.Detect.C2Correlation.NXDomainThreshold, UniqueSubdomainThreshold: cfg.Detect.C2Correlation.UniqueSubdomainThreshold, LongLabelLength: cfg.Detect.C2Correlation.LongLabelLength})

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

		DNSEngine:        dnsEngine,
		SMBEngine:        smbEngine,
		DCERPCEngine:     dcerpcEngine,
		ProtocolEngine:   protocolEngine,
		TCPReassembler:   tcpReassembler,
		UDPConversations: udpConversations,
		ThreatIntel:      tiStore,
		VulnerabilityDB:  vuln.New(),

		StoreEngine: storeEngine,

		DetectEngine: detectEngine,

		DebugEngine: debugEngine,

		Snapshotter: snapshotter,

		CaptureMode: cfg.Capture.Mode,

		DebugEnabled: cfg.Debug.Enabled,

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

	a.DNSEngine.Start()
	a.SMBEngine.Start()
	a.DCERPCEngine.Start()
	a.UDPConversations.Start()
	a.ProtocolEngine.Start()
	a.TCPReassembler.Start()
	if a.ThreatIntel != nil {
		ctx, cancel := context.WithCancel(context.Background())
		a.threatIntelCancel = cancel
		go a.ThreatIntel.Run(ctx)
	}

	a.ParserEngine.Start()

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

	if a.threatIntelCancel != nil {
		a.threatIntelCancel()
	}
	a.DNSEngine.Stop()
	a.ProtocolEngine.Stop()
	a.TCPReassembler.Stop()
	a.UDPConversations.Stop()

	if err := a.Snapshotter.Close(); err != nil {

		logger.Log.Warn(
			"Closing persistence failed",
			zap.Error(err),
		)
	}
}
