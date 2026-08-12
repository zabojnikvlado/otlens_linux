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
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/asset"
	"github.com/zabojnikvlado/otlens_linux/internal/behaviorbaseline"
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
	"github.com/zabojnikvlado/otlens_linux/internal/nba"
	"github.com/zabojnikvlado/otlens_linux/internal/netutil"
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
	BehaviorBaseline  *behaviorbaseline.Engine
	AnomalyEngine     *nba.Engine
	RiskEngine        *nba.RiskEngine
	CorrelationEngine *nba.CorrelationEngine
	ThreatIntel       *threatintel.Store
	VulnerabilityDB   *vuln.Database
	threatIntelCancel context.CancelFunc

	StoreEngine *store.Engine

	DetectEngine *detect.Engine

	DebugEngine *debug.Engine

	Snapshotter *persist.Snapshotter
}

func findBehaviorAsset(engine *asset.Engine, identity string) *asset.Asset {
	if engine == nil || identity == "" {
		return nil
	}
	if strings.HasPrefix(identity, "mac:") {
		mac := strings.TrimPrefix(identity, "mac:")
		if found := engine.Get(mac); found != nil {
			return found
		}
		for _, candidate := range engine.GetAll() {
			if strings.EqualFold(candidate.MAC, mac) {
				return candidate
			}
		}
		return nil
	}
	if strings.HasPrefix(identity, "ip:") {
		ip := strings.TrimPrefix(identity, "ip:")
		for _, candidate := range engine.GetAll() {
			if candidate.IP == ip {
				return candidate
			}
		}
	}
	return nil
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
		SensorID:                  cfg.Central.SensorID,
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
	behaviorBaseline := behaviorbaseline.New(eventBus, behaviorbaseline.Config{
		Enabled:               cfg.Baseline.BehaviorEnabled,
		SensorID:              cfg.Central.SensorID,
		LearningDuration:      cfg.Baseline.LearningDuration,
		BucketDuration:        cfg.Baseline.BucketDuration,
		MaxProfiles:           cfg.Baseline.MaxProfiles,
		MaxAssetProfiles:      cfg.Baseline.MaxAssetProfiles,
		MinAssetSamples:       cfg.Baseline.MinAssetSamples,
		MinAssetAge:           cfg.Baseline.MinAssetAge,
		ReadinessThreshold:    cfg.Baseline.ReadinessThreshold,
		MaxLearningMultiplier: cfg.Baseline.MaxLearningMultiplier,
		CandidateMinSamples:   cfg.Baseline.CandidateMinSamples,
		CandidateMinDays:      cfg.Baseline.CandidateMinDays,
		MinStatSamples:        cfg.Baseline.MinStatSamples,
		MaintenanceWindows:    cfg.Baseline.MaintenanceWindows,
	})
	anomalyEngine := nba.New(eventBus, behaviorBaseline, nba.Config{
		Enabled:      cfg.NBA.Enabled,
		MinScore:     cfg.NBA.MinScore,
		MaxAnomalies: cfg.NBA.MaxAnomalies,
		Cooldown:     cfg.NBA.Cooldown,
	})
	riskEngine := nba.NewRiskEngine(eventBus, func(anomaly nba.Anomaly) nba.RiskContext {
		source := findBehaviorAsset(assetEngine, anomaly.AssetID)
		destination := findBehaviorAsset(assetEngine, anomaly.PeerID)
		context := nba.RiskContext{}
		if source != nil {
			if source.Score > 1 {
				context.AssetCriticality = float64(min(source.Score, 100))
			}
			context.Honeypot = source.Score >= cfg.Deception.HoneypotThreshold
		}
		if destination != nil {
			context.Honeypot = context.Honeypot || destination.Score >= cfg.Deception.HoneypotThreshold
			context.InterVLAN = source != nil && source.VLANID != 0 && destination.VLANID != 0 && source.VLANID != destination.VLANID
			context.ExternalDestination = netutil.IsPublicInternetUnicast(destination.IP)
		} else if strings.HasPrefix(anomaly.PeerID, "ip:") {
			context.ExternalDestination = netutil.IsPublicInternetUnicast(strings.TrimPrefix(anomaly.PeerID, "ip:"))
		}
		return context
	}, nba.RiskConfig{Enabled: cfg.NBA.RiskEnabled, MaxAssessments: cfg.NBA.MaxAssessments})
	correlationEngine := nba.NewCorrelationEngine(eventBus, nba.CorrelationConfig{
		Enabled: cfg.NBA.CorrelationEnabled, Window: cfg.NBA.CorrelationWindow,
		ExpireAfter: cfg.NBA.FindingExpireAfter, MaxFindings: cfg.NBA.MaxFindings,
		MaxAssessmentsPerFinding: cfg.NBA.MaxAssessmentsPerFinding,
		MinFindingScore:          cfg.NBA.MinFindingScore, AlertThreshold: cfg.NBA.AlertThreshold,
		IncidentThreshold: cfg.NBA.IncidentThreshold,
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
	segmentationPolicy := make([]detect.SegmentationPolicyRule, 0, len(cfg.Detect.Segmentation.Policy))
	for _, r := range cfg.Detect.Segmentation.Policy {
		segmentationPolicy = append(segmentationPolicy, detect.SegmentationPolicyRule{SourceZone: r.SourceZone, DestinationZone: r.DestinationZone, Protocol: r.Protocol, Direction: r.Direction, Allowed: r.Allowed})
	}
	detectEngine.ConfigureSegmentationPolicy(segmentationPolicy)
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
		behaviorBaseline,
		anomalyEngine,
		riskEngine,
		correlationEngine,
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

		DNSEngine:         dnsEngine,
		SMBEngine:         smbEngine,
		DCERPCEngine:      dcerpcEngine,
		ProtocolEngine:    protocolEngine,
		TCPReassembler:    tcpReassembler,
		UDPConversations:  udpConversations,
		BehaviorBaseline:  behaviorBaseline,
		AnomalyEngine:     anomalyEngine,
		RiskEngine:        riskEngine,
		CorrelationEngine: correlationEngine,
		ThreatIntel:       tiStore,
		VulnerabilityDB:   vuln.New(),

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

// ResetData applies a Data Management reset consistently across persisted
// engine state and transient protocol/conversation buffers that are not stored in
// SQLite. Without this, old observations could be uploaded again immediately
// after an apparently successful reset.
func (a *Application) ResetData(operation string) error {
	switch operation {
	case "telemetry", "database", "factory", "analysis":
		if a.DNSEngine != nil {
			a.DNSEngine.Reset()
		}
		if a.SMBEngine != nil {
			a.SMBEngine.Reset()
		}
		if a.ProtocolEngine != nil {
			a.ProtocolEngine.Reset()
		}
		if a.UDPConversations != nil {
			a.UDPConversations.Reset()
		}
	case "assets":
		// UDP conversations are flow-like inventory and belong with asset/flow
		// data. DNS/SMB/protocol evidence is intentionally retained.
		if a.UDPConversations != nil {
			a.UDPConversations.Reset()
		}
	}
	return a.Snapshotter.Reset(operation)
}

// CompleteLearning freezes every sensor-side learning component against the
// same point in time. Normal completion is rejected until each enabled
// baseline has reached its configured minimum duration; force is an explicit
// break-glass override. Flipping DetectEngine's baseline mode also stops OT
// value and learned-policy accumulation because those detectors share that
// learning gate. BehaviorBaseline has its own persisted completion state, and
// NBA must rebuild its evaluator from the final frozen snapshot immediately.
func (a *Application) CompleteLearning(force bool) error {
	if a.DetectEngine == nil || a.BehaviorBaseline == nil {
		return fmt.Errorf("learning engines are not initialized")
	}

	now := time.Now().UTC()
	legacy := a.DetectEngine.BaselineStatus()
	behavior := a.BehaviorBaseline.Status(now)
	if !legacy.Enabled && !behavior.Enabled {
		return fmt.Errorf("baseline learning is disabled")
	}

	if legacy.Enabled && legacy.Mode != detect.BaselineModeMonitoring {
		if legacy.LearningStarted.IsZero() {
			return fmt.Errorf("baseline learning has not started")
		}
		if !force && now.Before(legacy.LearningEndsAt) {
			return fmt.Errorf("minimum learning duration has not elapsed")
		}
	}
	if behavior.Enabled && behavior.Mode != behaviorbaseline.ModeMonitoring {
		if behavior.LearningStarted.IsZero() {
			return fmt.Errorf("behavior baseline learning has not started")
		}
		if !force && now.Before(behavior.LearningEndsAt) {
			return fmt.Errorf("minimum behavior learning duration has not elapsed")
		}
	}

	if _, err := a.DetectEngine.CompleteBaseline(force); err != nil {
		return err
	}
	if _, err := a.BehaviorBaseline.CompleteLearning(force); err != nil {
		return err
	}
	if a.AnomalyEngine != nil {
		a.AnomalyEngine.ResetEvaluatorCache()
	}
	if a.Snapshotter != nil {
		if err := a.Snapshotter.Flush(); err != nil {
			return fmt.Errorf("learning completed but persistence flush failed: %w", err)
		}
	}
	return nil
}

func (a *Application) Start() {

	// Rehydrate every engine's in-memory state from disk before
	// anything starts consuming live traffic, so the very first
	// packets processed see the same state a long-running process
	// would have had.
	if err := a.Snapshotter.Restore(); err != nil {

		logger.Log.Warn(
			"Restoring persisted state was incomplete; successfully restored components were kept",
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
	a.BehaviorBaseline.Start()
	a.AnomalyEngine.Start()
	a.RiskEngine.Start()
	a.CorrelationEngine.Start()
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
	a.AnomalyEngine.Stop()
	a.RiskEngine.Stop()
	a.CorrelationEngine.Stop()
	a.BehaviorBaseline.Stop()
	a.TCPReassembler.Stop()
	a.UDPConversations.Stop()

	if err := a.Snapshotter.Close(); err != nil {

		logger.Log.Warn(
			"Closing persistence failed",
			zap.Error(err),
		)
	}
}
