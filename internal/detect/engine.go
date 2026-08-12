// Package detect is the anomaly/rule detection layer, currently
// implementing three independent checks (see arpspoof.go, baseline.go,
// icscritical.go), all reported through the same deduplicated Alert
// model (alert.go):
//
//   - ARP spoofing: an IP's claimed MAC changes after being confirmed.
//   - Baseline deviation: two assets communicate in a way never seen
//     during the configured learning window.
//   - ICS critical operations: security-relevant Modbus/S7comm
//     control functions (e.g. S7 PLCStop) flagged by internal/ics.
package detect

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/ics"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"github.com/zabojnikvlado/otlens_linux/internal/threatintel"
	"go.uber.org/zap"
)

const defaultARPConfirmThreshold = 3

// Engine is the anomaly/rule detection layer: it consumes the
// already-parsed data other engines produce (core.Packet, ics.Message)
// and raises deduplicated Alerts — the same storage-efficient pattern
// as store.Engine's Tags, applied to security findings instead of
// process variables.
type Engine struct {
	mutex sync.RWMutex

	// ARP spoofing state: last confirmed MAC per IP, plus an
	// in-progress candidate MAC + how many times it's repeated,
	// used to debounce against single stray packets (see arpspoof.go).
	knownMAC       map[string]string
	candidateMAC   map[string]string
	candidateCount map[string]int

	// arpConfirmThreshold is how many consecutive conflicting claims
	// for the same IP are required before companion duplicate-IP/gateway
	// alerts are escalated. A repeated claimant is never auto-promoted
	// to trusted identity; an analyst must approve the change.
	arpConfirmThreshold int

	// Baseline learning state — see baseline.go.
	baselineEnabled  bool
	baselineMode     BaselineMode
	learningStarted  time.Time
	learningDuration time.Duration
	learnedPatterns  map[string]bool
	learnedAssets    map[string]bool
	assetFirstSeen   map[string]time.Time
	assetSamples     map[string]uint64
	patternCreatedAt []time.Time

	// eventBus is retained (not just used transiently in Start) so
	// baseline.go can publish core.EventBaselineLearningComplete the
	// moment learning finishes, and asset_unconfirmed.go can react to
	// core.EventAssetUnconfirmed.
	eventBus *core.EventBus

	alerts map[string]*Alert

	// rules holds every configured rule (built-in + custom) — see
	// rules.go. customRuleSeq is the counter behind each new custom
	// rule's "custom-N" ID.
	rules         map[string]*Rule
	customRuleSeq int

	// deceptionScores/honeypotThreshold — see config.Deception and
	// honeypot.go. Read-only after construction, so no lock needed to
	// read them.
	deceptionScores   map[string]int
	honeypotThreshold int

	// segmentationEnabled/vlanLevels/maxLevelJump — see
	// config.SensorConfig.Detect.Segmentation and segmentation.go. Central may
	// replace the local defaults at runtime; segmentationManaged records that
	// such an authoritative Central snapshot has been applied so it can be
	// restored from SQLite before capture starts after a sensor restart.
	segmentationEnabled      bool
	segmentationManaged      bool
	vlanLevels               map[uint16]float64
	maxLevelJump             float64
	localSegmentationEnabled bool
	localVLANLevels          map[uint16]float64
	localMaxLevelJump        float64
	segmentationPolicy       []SegmentationPolicyRule
	ipVLANMutex              sync.RWMutex
	ipVLAN                   map[string]uint16
	ipVLANSeen               map[string]time.Time

	// reconnaissanceEnabled/reconWindow/hostScanThreshold/
	// portScanThreshold — see config.SensorConfig.Detect.
	// Reconnaissance and reconnaissance.go. scanMutex guards
	// hostScanSeen/portScanSeen, both pruned to reconWindow on access
	// (see reconnaissance.go) rather than by a separate background
	// sweep, so memory use tracks actual recent activity without
	// needing its own goroutine.
	reconnaissanceEnabled bool
	reconWindow           time.Duration
	hostScanThreshold     int
	portScanThreshold     int
	scanMutex             sync.Mutex
	hostScanSeen          map[string]map[string]time.Time         // srcIP -> dstIP -> last seen
	portScanSeen          map[string]map[string]map[int]time.Time // srcIP -> dstIP -> port -> last seen
	reconSignals          map[string][]time.Time

	// c2BeaconEnabled/*/beaconMutex/beaconHistory/beaconLastTouch — see
	// config.SensorConfig.Detect.C2Beacon and c2beacon.go.
	// beaconHistory holds, per "srcIP|dstIP|dstPort" key, the most
	// recent MinSamples-ish SYN timestamps (bounded, see
	// c2beacon.go's maxBeaconSamplesPerKey); beaconLastTouch tracks
	// when each key was last updated, purely so
	// MaxTrackedDestinations eviction has something to evict by
	// (oldest-touched first) when the map grows too large.
	c2BeaconEnabled         bool
	c2BeaconMinSamples      int
	c2BeaconMaxCV           float64
	c2BeaconMinInterval     time.Duration
	c2BeaconMaxInterval     time.Duration
	c2BeaconMaxTrackedDests int
	beaconMutex             sync.Mutex
	beaconHistory           map[string][]time.Time
	beaconLastTouch         map[string]time.Time

	threatIntel *threatintel.Store

	otAnomaly OTValueAnomalyConfig
	otMutex   sync.Mutex
	otValues  map[string]*otValueState

	lateral     LateralMovementConfig
	lateralData lateralState

	c2Correlation C2CorrelationConfig
	c2DNSMutex    sync.Mutex
	c2NXDomains   map[string][]time.Time
	c2Subdomains  map[string]map[string]time.Time

	// Product built-in policy/context state. Central supplies operator-owned
	// asset roles/zones; protocol/management relationships are learned locally
	// during baseline and remain bounded maps keyed by observed assets.
	policyMutex   sync.Mutex
	assetContexts map[string]AssetPolicyContext
	otAssets      map[string]bool
	// Access, command authority and time-setting authority are learned
	// separately. A historian that merely reads a PLC during learning must not
	// become authorized to write/operate it after learning.
	trustedOTAccess          map[string]map[string]bool
	trustedOTMasters         map[string]map[string]bool
	trustedOTTimeSources     map[string]map[string]bool
	trustedOTProtocols       map[string]map[string]bool
	trustedRemoteMgmt        map[string]bool
	policyLearningQuarantine map[string]time.Time
	engineeringTargets       map[string]map[string]time.Time
	remoteTransfers          map[string]*packetWindow
	ioBursts                 map[string][]time.Time
	dnpSelect                map[string]time.Time
	icsErrors                map[string][]time.Time
	reporting                map[string]*reportingState
	hostnameByMAC            map[string]string
	gratuitousARP            map[string][]time.Time
	externalPeers            map[string]map[string]bool
	externalFlows            map[string]externalFlowState
	externalFlowLastSweep    time.Time
	dnsTunnel                map[string]*dnsTunnelState
	lastPacketObserved       time.Time
}

// NewEngine creates a detection engine. learningDuration controls
// how long baseline.go spends learning "normal" asset-to-asset
// communication before it starts alerting on anything new — see
// BaselineStatus/handleBaseline. arpConfirmThreshold of 0 or less
// falls back to defaultARPConfirmThreshold.
//
// baselineEnabled false skips the learning phase entirely: the
// engine starts directly in BaselineModeMonitoring with an empty
// learned set, so every device/communication is "new" from the very
// first packet — useful for a deployment where the network's normal
// baseline is already known/trusted and there's no reason to wait
// out a learning window before alerting starts for real.
//
// deceptionScores/honeypotThreshold configure honeypot.go's lateral-
// movement detection — see config.Deception.
func NewEngine(
	learningDuration time.Duration,
	arpConfirmThreshold int,
	baselineEnabled bool,
	deceptionScores map[string]int,
	honeypotThreshold int,
	segmentationEnabled bool,
	vlanLevels map[uint16]float64,
	maxLevelJump float64,
	reconnaissanceEnabled bool,
	reconWindow time.Duration,
	hostScanThreshold int,
	portScanThreshold int,
	c2BeaconEnabled bool,
	c2BeaconMinSamples int,
	c2BeaconMaxCV float64,
	c2BeaconMinInterval time.Duration,
	c2BeaconMaxInterval time.Duration,
	c2BeaconMaxTrackedDests int,
) *Engine {

	if arpConfirmThreshold <= 0 {
		arpConfirmThreshold = defaultARPConfirmThreshold
	}

	if deceptionScores == nil {
		deceptionScores = make(map[string]int)
	}

	if vlanLevels == nil {
		vlanLevels = make(map[uint16]float64)
	}
	localVLANLevels := make(map[uint16]float64, len(vlanLevels))
	for vlan, level := range vlanLevels {
		localVLANLevels[vlan] = level
	}

	if maxLevelJump <= 0 {
		maxLevelJump = 1
	}

	e := &Engine{
		knownMAC:       make(map[string]string),
		candidateMAC:   make(map[string]string),
		candidateCount: make(map[string]int),

		arpConfirmThreshold: arpConfirmThreshold,

		baselineEnabled:  baselineEnabled,
		learningDuration: learningDuration,
		learnedPatterns:  make(map[string]bool),
		learnedAssets:    make(map[string]bool),
		assetFirstSeen:   make(map[string]time.Time),
		assetSamples:     make(map[string]uint64),

		alerts: make(map[string]*Alert),

		rules: builtinRules(),

		deceptionScores:   deceptionScores,
		honeypotThreshold: honeypotThreshold,

		segmentationEnabled:      segmentationEnabled,
		vlanLevels:               localVLANLevels,
		maxLevelJump:             maxLevelJump,
		localSegmentationEnabled: segmentationEnabled,
		localVLANLevels:          localVLANLevels,
		localMaxLevelJump:        maxLevelJump,
		ipVLAN:                   make(map[string]uint16),
		ipVLANSeen:               make(map[string]time.Time),

		reconnaissanceEnabled: reconnaissanceEnabled,
		reconWindow:           reconWindow,
		hostScanThreshold:     hostScanThreshold,
		portScanThreshold:     portScanThreshold,
		hostScanSeen:          make(map[string]map[string]time.Time),
		portScanSeen:          make(map[string]map[string]map[int]time.Time),
		reconSignals:          make(map[string][]time.Time),

		c2BeaconEnabled:         c2BeaconEnabled,
		c2BeaconMinSamples:      c2BeaconMinSamples,
		c2BeaconMaxCV:           c2BeaconMaxCV,
		c2BeaconMinInterval:     c2BeaconMinInterval,
		c2BeaconMaxInterval:     c2BeaconMaxInterval,
		c2BeaconMaxTrackedDests: c2BeaconMaxTrackedDests,
		beaconHistory:           make(map[string][]time.Time),
		beaconLastTouch:         make(map[string]time.Time),

		otValues:     make(map[string]*otValueState),
		lateralData:  lateralState{fanout: make(map[string]map[string]time.Time), transfers: make(map[string]*trafficWindow), inboundAdmin: make(map[string]map[string]time.Time)},
		c2NXDomains:  make(map[string][]time.Time),
		c2Subdomains: make(map[string]map[string]time.Time),

		assetContexts:            make(map[string]AssetPolicyContext),
		otAssets:                 make(map[string]bool),
		trustedOTAccess:          make(map[string]map[string]bool),
		trustedOTMasters:         make(map[string]map[string]bool),
		trustedOTTimeSources:     make(map[string]map[string]bool),
		trustedOTProtocols:       make(map[string]map[string]bool),
		trustedRemoteMgmt:        make(map[string]bool),
		policyLearningQuarantine: make(map[string]time.Time),
		engineeringTargets:       make(map[string]map[string]time.Time),
		remoteTransfers:          make(map[string]*packetWindow),
		ioBursts:                 make(map[string][]time.Time),
		dnpSelect:                make(map[string]time.Time),
		icsErrors:                make(map[string][]time.Time),
		reporting:                make(map[string]*reportingState),
		hostnameByMAC:            make(map[string]string),
		gratuitousARP:            make(map[string][]time.Time),
		externalPeers:            make(map[string]map[string]bool),
		externalFlows:            make(map[string]externalFlowState),
		dnsTunnel:                make(map[string]*dnsTunnelState),
	}

	if e.reconWindow <= 0 {
		e.reconWindow = 60 * time.Second
	}
	if e.hostScanThreshold <= 0 {
		e.hostScanThreshold = 15
	}
	if e.portScanThreshold <= 0 {
		e.portScanThreshold = 15
	}

	if e.c2BeaconMinSamples <= 0 {
		e.c2BeaconMinSamples = 6
	}
	if e.c2BeaconMaxCV <= 0 {
		e.c2BeaconMaxCV = 0.15
	}
	if e.c2BeaconMinInterval <= 0 {
		e.c2BeaconMinInterval = 5 * time.Second
	}
	if e.c2BeaconMaxInterval <= 0 {
		e.c2BeaconMaxInterval = time.Hour
	}
	if e.c2BeaconMaxTrackedDests <= 0 {
		e.c2BeaconMaxTrackedDests = 5000
	}

	if !baselineEnabled {

		// Skip straight to monitoring — handleBaseline's lazy
		// learning-start check (`if e.baselineMode == ""`) only fires
		// when the mode is still unset, so setting it here up front
		// means learning never starts at all. asset.Engine finds out
		// via the existing PublishBaselineStateIfEstablished restart-
		// safety call in app.go (which checks exactly this condition
		// — mode already monitoring — regardless of whether that's
		// because learning genuinely finished in an earlier run, or,
		// as here, because it was configured off from the start).
		e.baselineMode = BaselineModeMonitoring

		logger.Log.Info(
			"Baseline learning disabled (baseline.enabled: false) — starting directly in monitoring mode",
		)
	}

	return e
}

func (e *Engine) SetThreatIntel(store *threatintel.Store) { e.threatIntel = store }
func (e *Engine) ConfigureOTValueAnomaly(c OTValueAnomalyConfig) {
	if c.MinSamples <= 0 {
		c.MinSamples = 20
	}
	if c.ZScoreThreshold <= 0 {
		c.ZScoreThreshold = 4
	}
	if c.RateMultiplier <= 0 {
		c.RateMultiplier = 6
	}
	if c.StuckAfter <= 0 {
		c.StuckAfter = 30 * time.Minute
	}
	if c.MissingAfter <= 0 {
		c.MissingAfter = 10 * time.Minute
	}
	if c.ToggleWindow <= 0 {
		c.ToggleWindow = 5 * time.Minute
	}
	if c.ToggleThreshold <= 0 {
		c.ToggleThreshold = 10
	}
	if c.CheckInterval <= 0 {
		c.CheckInterval = time.Minute
	}
	e.otAnomaly = c
}
func (e *Engine) ConfigureLateralMovement(c LateralMovementConfig) {
	if c.Window <= 0 {
		c.Window = 5 * time.Minute
	}
	if c.FanOutThreshold <= 0 {
		c.FanOutThreshold = 5
	}
	if c.LargeTransferBytes == 0 {
		c.LargeTransferBytes = 100 * 1024 * 1024
	}
	if c.PivotWindow <= 0 {
		c.PivotWindow = 10 * time.Minute
	}
	if len(c.AdminPorts) == 0 {
		c.AdminPorts = []uint16{22, 135, 139, 445, 3389, 5985, 5986}
	}
	e.lateral = c
}
func (e *Engine) ConfigureC2Correlation(c C2CorrelationConfig) {
	if c.MinScore <= 0 {
		c.MinScore = 60
	}
	if c.DNSWindow <= 0 {
		c.DNSWindow = 10 * time.Minute
	}
	if c.NXDomainThreshold <= 0 {
		c.NXDomainThreshold = 20
	}
	if c.UniqueSubdomainThreshold <= 0 {
		c.UniqueSubdomainThreshold = 20
	}
	if c.LongLabelLength <= 0 {
		c.LongLabelLength = 45
	}
	e.c2Correlation = c
}

func (e *Engine) Start(bus *core.EventBus) {

	logger.Log.Info(
		"Detect engine started",
	)

	e.eventBus = bus

	e.startARPWatch(bus)
	e.startICSWatch(bus)
	e.startICSParseErrorWatch(bus)
	e.startBaselineWatch(bus)
	e.startAssetUnconfirmedWatch(bus)
	e.startValueOutOfRangeWatch(bus)
	e.startHoneypotWatch(bus)
	e.startHoneypotClearedWatch(bus)
	e.startExternalCommunicationWatch(bus)
	e.startSegmentationWatch(bus)
	e.startReconnaissanceWatch(bus)
	e.startC2BeaconWatch(bus)
	e.startThreatIntelWatch(bus)
	e.startOTValueAnomalyWatch(bus)
	e.startLateralMovementWatch(bus)
	e.startSMBLateralWatch(bus)
	e.startC2CorrelationWatch(bus)
	e.startDNSTunnelWatch(bus)
	e.startBehaviorFindingWatch(bus)
	e.startBuiltinNetworkPolicyWatch(bus)
	e.startIdentityPolicyWatch(bus)
	e.startOTReportingWatch(bus)
	e.startCustomRuleWatch(bus)

}

func (e *Engine) startARPWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok || (packet.L4Protocol != "ARP" && packet.NDPSrcIP == "") {
				continue
			}

			if packet.L4Protocol == "ARP" {
				e.handleARP(packet)
				continue
			}
			// Feed authoritative IPv6 Neighbor Discovery through the same guarded
			// identity-change state machine as ARP.
			claim := packet
			claim.ARPSrcIP = packet.NDPSrcIP
			claim.ARPSrcMAC = packet.NDPSrcMAC
			e.handleARP(claim)

		}

	}()

}

func (e *Engine) startICSWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventICSMessage)

	go func() {

		for event := range ch {

			msg, ok := event.Data.(ics.Message)

			if !ok {
				continue
			}

			e.handleICS(msg)

		}

	}()

}

func (e *Engine) startBaselineWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok {
				continue
			}

			e.handleBaseline(packet)

		}

	}()

}

// logNewAlert records a newly created alert in the sensor log.
func (e *Engine) logNewAlert(alert *Alert) {

	logger.Log.Warn(
		"Alert raised",
		zap.String("type", string(alert.Type)),
		zap.String("severity", alert.Severity),
		zap.String("message", alert.Message),
	)

}

// ApproveAlert marks an existing alert as reviewed and accepted as
// expected/benign (AlertStatusApproved). It reports false if no
// alert with that ID exists (e.g. already evicted, or a stale ID
// from a client's cached view).
func (e *Engine) ApproveAlert(id string) bool {
	e.mutex.Lock()
	alert, exists := e.alerts[id]
	if !exists {
		e.mutex.Unlock()
		return false
	}
	alert.Status = AlertStatusApproved
	alert.StatusChangedAt = time.Now()
	alert.Synced = false

	// Copy the fields needed for trust promotion before releasing the alert
	// mutex. Policy-learning state uses a separate mutex and must never be
	// mutated while holding e.mutex, otherwise concurrent detector paths could
	// invert lock order.
	alertType, alertIP := alert.Type, alert.IP
	evidence := make(map[string]interface{}, len(alert.Evidence))
	for k, v := range alert.Evidence {
		evidence[k] = v
	}

	// A post-learning communication deviation becomes trusted baseline only
	// after an analyst explicitly approves it. Older builds silently learned it
	// on first sight, which could normalize malicious traffic.
	if alert.Type == AlertNewCommunication {
		baselineKey := evidenceString(evidence, "baseline_key")
		if baselineKey == "" {
			baselineKey = alert.ID
		}
		e.learnedPatterns[baselineKey] = true
	}
	// ARP identity changes are never auto-promoted by packet repetition. An
	// explicit analyst approval is the trust transition.
	if alert.Type == AlertARPSpoof || alert.Type == AlertDuplicateIP || alert.Type == AlertGatewayMACChanged {
		newMAC := alert.NewMAC
		if newMAC == "" {
			newMAC = evidenceString(evidence, "new_mac")
		}
		if alert.IP != "" && newMAC != "" {
			e.knownMAC[alert.IP] = newMAC
			delete(e.candidateMAC, alert.IP)
			delete(e.candidateCount, alert.IP)
		}
	}
	e.mutex.Unlock()

	src := evidenceString(evidence, "source_ip")
	if src == "" {
		src = evidenceString(evidence, "client_ip")
	}
	dst := evidenceString(evidence, "target_ip")
	if dst == "" {
		dst = evidenceString(evidence, "destination_ip")
	}
	if dst == "" && alertType == AlertUnexpectedOTProtocol {
		dst = alertIP
	}
	protocol := evidenceString(evidence, "protocol")
	if protocol == "" {
		protocol = evidenceString(evidence, "ot_protocol")
	}
	port := evidenceUint16(evidence, "service_port")
	if port == 0 {
		port = evidenceUint16(evidence, "destination_port")
	}

	// Approval is also an explicit relationship-policy decision for findings
	// that represent previously unknown access/authority. This provides the
	// operator-owned "approved sources/destinations" layer without silently
	// learning security-sensitive traffic.
	switch alertType {
	case AlertUnauthorizedOTCommand, AlertUnauthorizedOTWrite, AlertUnexpectedEngineeringAccess:
		e.approveOTAccessRelationship(src, dst, protocol, port, true)
	case AlertDirectOTProtocolAccess:
		e.approveOTAccessRelationship(src, dst, protocol, port, false)
	case AlertUnexpectedOTProtocol:
		e.approveOTAccessRelationship(src, dst, protocol, port, false)
	case AlertUnauthorizedTimeChange:
		e.approveOTTimeSource(src, dst)
	case AlertFirstSeenRemoteManagement, AlertRemoteAdminIntoOT:
		e.approveRemoteManagement(src, dst, port)
	case AlertSMBIntoOT:
		e.approveRemoteManagement(src, dst, 445)
	}
	return true
}

func evidenceString(evidence map[string]interface{}, key string) string {
	if evidence == nil {
		return ""
	}
	if v, ok := evidence[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func evidenceUint16(evidence map[string]interface{}, key string) uint16 {
	if evidence == nil {
		return 0
	}
	switch v := evidence[key].(type) {
	case uint16:
		return v
	case uint32:
		if v <= 65535 {
			return uint16(v)
		}
	case uint64:
		if v <= 65535 {
			return uint16(v)
		}
	case int:
		if v >= 0 && v <= 65535 {
			return uint16(v)
		}
	case float64:
		if v >= 0 && v <= 65535 {
			return uint16(v)
		}
	case string:
		if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 16); err == nil {
			return uint16(n)
		}
	}
	return 0
}

// allowAlertOccurrenceLocked applies the operator verdict before an alert is
// updated. Approved alert IDs are remembered as accepted patterns and are no
// longer raised or counted. A confirmed alert is only acknowledged: when the
// same condition is observed again it becomes new and visible again.
// Caller must hold e.mutex.
func (e *Engine) allowAlertOccurrenceLocked(alert *Alert) bool {
	switch alert.Status {
	case AlertStatusApproved:
		return false
	case AlertStatusConfirmed:
		alert.Status = AlertStatusNew
		alert.StatusChangedAt = time.Now()
		alert.Synced = false
	}
	return true
}

// ConfirmAlert marks an existing alert as reviewed and confirmed as
// a genuine issue (AlertStatusConfirmed). Reports false under the
// same conditions as ApproveAlert.
func (e *Engine) ConfirmAlert(id string) bool {
	return e.setAlertStatus(id, AlertStatusConfirmed)
}

func (e *Engine) setAlertStatus(id string, status AlertStatus) bool {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[id]

	if !exists {
		return false
	}

	alert.Status = status
	alert.StatusChangedAt = time.Now()
	alert.Synced = false

	return true
}

// CountAlerts returns the number of distinct tracked alerts.
func (e *Engine) CountAlerts() int {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return len(e.alerts)
}

// GetAlerts returns a snapshot of every tracked alert. Each element
// is a shallow copy, not a pointer into the live map — see
// asset.Engine.GetAll's doc comment for why that matters (a data
// race between this and setAlertStatus()/logNewAlert()'s Count/
// LastSeen bump otherwise).
func (e *Engine) GetAlerts() []*Alert {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]*Alert, 0, len(e.alerts))

	for _, alert := range e.alerts {

		clone := *alert

		result = append(
			result,
			&clone,
		)

	}

	return result
}

// maxDirtyAlertsPerSync caps how many alerts a single GetDirtyAlerts
// call returns. Matters most right after upgrading to a build that has
// this dirty-tracking at all: every alert already on disk from before
// this field existed comes back with Synced's zero value (false), so
// without this cap a sensor that's accumulated a large backlog would
// still try to send its entire alert set on the very first sync after
// upgrading — the exact failure this change exists to prevent. Anything
// left uncapped just stays dirty and goes out over the next several
// sync cycles instead.
const maxDirtyAlertsPerSync = 1000

// GetDirtyAlerts returns a snapshot of only the alerts that have
// changed (new, Count/LastSeen bumped, or a Status change) since they
// were last successfully reported to Central — see MarkAlertsSynced.
// This is what the periodic telemetry sync actually sends, instead of
// GetAlerts' full set, so a sensor that's accumulated a large number of
// distinct findings over time doesn't re-serialize and re-upload all of
// them every single sync. Capped at maxDirtyAlertsPerSync per call —
// see that constant's comment.
func (e *Engine) GetDirtyAlerts() []*Alert {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make([]*Alert, 0)

	for _, alert := range e.alerts {

		if alert.Synced {
			continue
		}

		clone := *alert

		result = append(
			result,
			&clone,
		)

		if len(result) >= maxDirtyAlertsPerSync {
			break
		}

	}

	return result
}

// MarkAlertsSynced marks only the exact alert versions that Central just
// acknowledged. An alert may change while the telemetry HTTP request is in
// flight; matching by ID alone would incorrectly mark that newer local state as
// synchronized even though Central only received the older snapshot. Comparing
// all persisted/telemetry-visible fields keeps the newer version dirty so it is
// sent on the next cycle.
func (e *Engine) MarkAlertsSynced(sent []*Alert) {

	if len(sent) == 0 {
		return
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	now := time.Now()
	for _, snapshot := range sent {
		if snapshot == nil || snapshot.ID == "" {
			continue
		}
		alert, ok := e.alerts[snapshot.ID]
		if !ok {
			continue
		}
		if !sameAlertSyncVersion(alert, snapshot) {
			// The live alert advanced after GetDirtyAlerts captured snapshot.
			// Leave it dirty; the next telemetry cycle must carry that version.
			continue
		}
		alert.Synced = true
		alert.lastSyncTouch = now
	}
}

func sameAlertSyncVersion(current, sent *Alert) bool {
	if current == nil || sent == nil {
		return false
	}
	return current.ID == sent.ID &&
		current.Type == sent.Type &&
		current.Severity == sent.Severity &&
		current.Message == sent.Message &&
		current.IP == sent.IP &&
		current.PreviousMAC == sent.PreviousMAC &&
		current.NewMAC == sent.NewMAC &&
		current.FirstSeen.Equal(sent.FirstSeen) &&
		current.LastSeen.Equal(sent.LastSeen) &&
		current.Count == sent.Count &&
		current.Status == sent.Status &&
		current.StatusChangedAt.Equal(sent.StatusChangedAt) &&
		sameAlertEvidence(current.Evidence, sent.Evidence)
}

func sameAlertEvidence(current, sent map[string]interface{}) bool {
	left, leftErr := json.Marshal(current)
	right, rightErr := json.Marshal(sent)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

// Alerts, e.g. at startup after loading from disk.
func (e *Engine) RestoreAlerts(alerts []*Alert) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Restore is used both at startup and for destructive resets. Always
	// replace the map so RestoreAlerts(nil) actually clears persisted alerts.
	e.alerts = make(map[string]*Alert, len(alerts))

	for _, alert := range alerts {

		if alert.Status == "" {
			// Data persisted before AlertStatus existed — treat as
			// unreviewed rather than leaving an invalid empty status.
			alert.Status = AlertStatusNew
		}

		e.alerts[alert.ID] = alert

		// Repair baseline state produced by older builds: only explicitly
		// approved new-communication deviations are trusted after restart.
		if alert.Type == AlertNewCommunication {
			if alert.Status == AlertStatusApproved {
				e.learnedPatterns[alert.ID] = true
			} else {
				delete(e.learnedPatterns, alert.ID)
			}
		}
	}
}

// PruneAlerts removes alerts not updated within maxAge (Count/LastSeen
// stop advancing once the underlying condition stops recurring).
// Returns the number removed.
//
// Deliberately NOT pruned by age: learnedPatterns (baseline.go) and
// knownMAC (arpspoof.go). Both represent "this is legitimate,
// already-seen-and-accepted" state, not history — aging them out
// would cause an infrequent-but-perfectly-normal pattern (a monthly
// maintenance job, a rarely-rebooted device re-ARPing) to look
// "new" again after the retention window passes and spuriously
// re-trigger the exact alerts this baseline was built to prevent.
func (e *Engine) PruneAlerts(maxAge time.Duration) int {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)

	removed := 0

	for id, alert := range e.alerts {

		if alert.LastSeen.Before(cutoff) {
			delete(e.alerts, id)
			removed++
		}
	}

	return removed
}

// Clear removes every tracked alert — the admin UI's "wipe database"
// action. Unlike PruneAlerts, this isn't selective; it's
// a full reset. Deliberately does NOT touch baseline learning state
// (learnedPatterns/learnedAssets) or the ARP knownMAC map — those
// represent "what's normal," not alert history, and wiping them
// would force baseline learning to start over and could re-trigger
// spurious ARP-spoof alerts for perfectly legitimate, already-known
// mappings. Also deliberately does NOT touch rules (built-in
// enabled/disabled toggles, or custom rules) — those are
// configuration a person set up on purpose, not observed data; wiping
// the network's observed history shouldn't also silently delete
// someone's custom rules or re-enable ones they'd turned off.
func (e *Engine) Clear() {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.alerts = make(map[string]*Alert)
}

// BaselineSnapshot is the persisted shape of baseline learning
// progress: what mode it's in, when learning started, and every
// pattern/asset learned so far. Restoring this on startup means a
// restart doesn't throw away hours of learning or reset the clock
// back to "just started learning" — and, for LearnedAssets
// specifically, doesn't re-flag every already-known device as
// newly unconfirmed on every restart.
type BaselineSnapshot struct {
	Mode             BaselineMode
	LearningStarted  time.Time
	LearnedPatterns  map[string]bool
	LearnedAssets    map[string]bool
	AssetFirstSeen   map[string]time.Time
	AssetSamples     map[string]uint64
	PatternCreatedAt []time.Time
}

// BaselineSnapshot captures the current baseline state for
// persistence.
func (e *Engine) BaselineSnapshot() BaselineSnapshot {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	patterns := make(map[string]bool, len(e.learnedPatterns))

	for k, v := range e.learnedPatterns {
		patterns[k] = v
	}

	assets := make(map[string]bool, len(e.learnedAssets))

	for k, v := range e.learnedAssets {
		assets[k] = v
	}
	firstSeen := make(map[string]time.Time, len(e.assetFirstSeen))
	for k, v := range e.assetFirstSeen {
		firstSeen[k] = v
	}
	samples := make(map[string]uint64, len(e.assetSamples))
	for k, v := range e.assetSamples {
		samples[k] = v
	}

	return BaselineSnapshot{
		Mode:             e.baselineMode,
		LearningStarted:  e.learningStarted,
		LearnedPatterns:  patterns,
		LearnedAssets:    assets,
		AssetFirstSeen:   firstSeen,
		AssetSamples:     samples,
		PatternCreatedAt: append([]time.Time(nil), e.patternCreatedAt...),
	}
}

// RestoreBaseline rehydrates baseline learning state from a
// previously persisted snapshot.
func (e *Engine) RestoreBaseline(snapshot BaselineSnapshot) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if snapshot.Mode == "" {
		// Nothing was ever persisted (fresh database) — leave the
		// zero value so handleBaseline starts the clock on the
		// first packet, same as a genuinely first-ever run.
		return
	}

	e.baselineMode = snapshot.Mode
	e.learningStarted = snapshot.LearningStarted

	for k, v := range snapshot.LearnedPatterns {
		e.learnedPatterns[k] = v
	}

	for k, v := range snapshot.LearnedAssets {
		e.learnedAssets[k] = v
	}
	for k, v := range snapshot.AssetFirstSeen {
		e.assetFirstSeen[k] = v
	}
	for k, v := range snapshot.AssetSamples {
		e.assetSamples[k] = v
	}
	e.patternCreatedAt = append([]time.Time(nil), snapshot.PatternCreatedAt...)
}

// ResetBaseline actually clears learning state back to zero,
// regardless of what it currently is — unlike calling
// RestoreBaseline(BaselineSnapshot{}), which deliberately does
// *nothing* when handed an empty snapshot (see that function's
// comment: an empty snapshot means "nothing was ever persisted," so
// leaving whatever's already in memory untouched is correct at
// startup). That early-return makes RestoreBaseline the wrong tool
// for an explicit "start learning over" request while the engine is
// already running and possibly already in BaselineModeMonitoring —
// it would silently no-op instead of resetting anything. This is
// what Data Management's "learning" reset (and the "database"/
// "factory" resets, which include a learning reset) actually need:
// the next packet after this call restarts the learn-then-monitor
// cycle from scratch, exactly like a brand-new sensor's first packet.
func (e *Engine) ResetBaseline() {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.baselineEnabled {
		e.baselineMode = ""
	} else {
		// A reset must not accidentally enable learning when the operator
		// explicitly configured baseline.enabled=false.
		e.baselineMode = BaselineModeMonitoring
	}
	e.learningStarted = time.Time{}
	e.learnedPatterns = make(map[string]bool)
	e.learnedAssets = make(map[string]bool)
	e.assetFirstSeen = make(map[string]time.Time)
	e.assetSamples = make(map[string]uint64)
	e.patternCreatedAt = nil
}

// KnownMACSnapshot captures the current confirmed IP->MAC mapping
// used by ARP spoofing detection, for persistence. The in-progress
// candidate/debounce state is deliberately not persisted — it's
// only a few packets' worth of transient state, and restarting the
// debounce window on startup is a fine tradeoff for the simplicity
// of not persisting it.
func (e *Engine) KnownMACSnapshot() map[string]string {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make(map[string]string, len(e.knownMAC))

	for k, v := range e.knownMAC {
		result[k] = v
	}

	return result
}

// RestoreKnownMAC rehydrates the confirmed IP->MAC mapping from a
// previously persisted snapshot, so a restart doesn't forget every
// known-good mapping and treat normal traffic as suspicious again.
func (e *Engine) RestoreKnownMAC(knownMAC map[string]string) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.knownMAC = make(map[string]string, len(knownMAC))
	for k, v := range knownMAC {
		e.knownMAC[k] = v
	}
}
