package detect

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/zabojnikvlado/otlens/internal/core"
	"github.com/zabojnikvlado/otlens/internal/logger"
	"go.uber.org/zap"
)

// BaselineMode is the current phase of the "learn normal, then
// alarm on anything new" workflow.
type BaselineMode string

const (
	BaselineModeLearning   BaselineMode = "learning"
	BaselineModeMonitoring BaselineMode = "monitoring"
)

// handleBaseline implements two parallel baselines from the same
// packet stream, sharing one learning clock: asset-communication
// patterns (protocol + service between two devices — see
// baselineKey) and asset identity (device MAC addresses — see
// extractMACs). Both use the same "identity over history" idea
// store.Tag uses for OT registers: track what's normal once, then
// only alert on genuine deviations.
//
// Everything here runs on a single goroutine (this function is only
// ever called from one Subscribe loop), which is what lets the
// exactly-once core.EventBaselineLearningComplete publish below be
// exactly once — there's no separate concurrent watcher for asset
// identity that could race against the mode-flip check.
func (e *Engine) handleBaseline(packet core.Packet) {

	macs := extractMACs(packet)

	hasIPEndpoints := packet.SrcIP != "" && packet.DstIP != ""

	if len(macs) == 0 && !hasIPEndpoints {
		return
	}

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.baselineMode == "" {

		// First packet ever seen — start the learning clock now,
		// rather than at process startup, so time spent waiting for
		// the capture interface to come up doesn't eat into the
		// learning window.
		e.baselineMode = BaselineModeLearning
		e.learningStarted = now

		logger.Log.Info(
			"Baseline learning started",
			zap.Duration("duration", e.learningDuration),
		)
	}

	justCompleted := false

	if e.baselineMode == BaselineModeLearning && now.Sub(e.learningStarted) >= e.learningDuration {

		e.baselineMode = BaselineModeMonitoring
		justCompleted = true

		logger.Log.Info(
			"Baseline learning complete, now monitoring for deviations",
			zap.Int("learned_patterns", len(e.learnedPatterns)),
			zap.Int("learned_assets", len(e.learnedAssets)),
		)
	}

	if e.baselineMode == BaselineModeLearning {

		for _, mac := range macs {
			e.learnedAssets[mac] = true
		}
	}

	if justCompleted {
		e.publishBaselineComplete()
	}

	if !hasIPEndpoints {
		return
	}

	key := baselineKey(
		packet.L4Protocol,
		packet.SrcIP,
		packet.SrcPort,
		packet.DstIP,
		packet.DstPort,
	)

	if e.baselineMode == BaselineModeLearning {

		e.learnedPatterns[key] = true
		return
	}

	if e.learnedPatterns[key] {
		return
	}

	if !e.isRuleEnabledLocked(string(AlertNewCommunication)) {
		return
	}

	e.raiseBaselineAlert(key, packet)
}

// publishBaselineComplete sends the current learned-asset set as a
// one-time core.EventBaselineLearningComplete, so internal/asset can
// decide whether a device discovered from here on is already known
// or genuinely new. Caller must hold e.mutex.
func (e *Engine) publishBaselineComplete() {

	assets := make([]string, 0, len(e.learnedAssets))

	for mac := range e.learnedAssets {
		assets = append(assets, mac)
	}

	e.eventBus.Publish(
		core.Event{
			Type: core.EventBaselineLearningComplete,
			Data: core.BaselineComplete{LearnedAssetMACs: assets},
		},
	)
}

// PublishBaselineStateIfEstablished re-publishes the learned-asset
// snapshot if baseline learning had already completed before this
// process started (e.g. state restored from a previous run's
// persisted snapshot). Without this, a restart occurring after
// learning had already finished would leave internal/asset never
// receiving the one-time publish from *this* session — the mode-flip
// that would normally trigger it happened in a previous process — and
// it would default every subsequently-discovered device to
// "confirmed" instead of correctly flagging genuinely new ones.
//
// Call once, after both this engine's Start and asset.Engine's Start
// have run (so asset.Engine is already subscribed to receive it).
func (e *Engine) PublishBaselineStateIfEstablished() {

	e.mutex.RLock()
	mode := e.baselineMode
	assets := make([]string, 0, len(e.learnedAssets))
	for mac := range e.learnedAssets {
		assets = append(assets, mac)
	}
	e.mutex.RUnlock()

	if mode != BaselineModeMonitoring {
		return
	}

	e.eventBus.Publish(
		core.Event{
			Type: core.EventBaselineLearningComplete,
			Data: core.BaselineComplete{LearnedAssetMACs: assets},
		},
	)
}

// extractMACs pulls every non-multicast device MAC address a packet
// identifies (Ethernet source/destination, plus the ARP payload's
// claimed source for ARP packets). This deliberately duplicates
// asset.Engine's own small MAC-extraction logic rather than importing
// internal/asset for it — see core.BaselineComplete's doc comment for
// why these two packages avoid importing each other.
func extractMACs(packet core.Packet) []string {

	var macs []string

	if packet.SrcMAC != "" && !isMulticastMACAddr(packet.SrcMAC) {
		macs = append(macs, packet.SrcMAC)
	}

	if packet.DstMAC != "" && !isMulticastMACAddr(packet.DstMAC) {
		macs = append(macs, packet.DstMAC)
	}

	if packet.ARPSrcMAC != "" && !isMulticastMACAddr(packet.ARPSrcMAC) {
		macs = append(macs, packet.ARPSrcMAC)
	}

	return macs
}

func isMulticastMACAddr(mac string) bool {

	hw, err := net.ParseMAC(mac)

	if err != nil || len(hw) == 0 {
		return false
	}

	return hw[0]&0x01 != 0
}

// raiseBaselineAlert creates or updates the deduplicated Alert for
// one specific never-before-seen communication pattern. Caller must
// hold e.mutex.
//
// The pattern is also added to learnedPatterns once alerted, so a
// legitimate-but-rare relationship (e.g. a monthly maintenance job
// connecting for the first time after the learning window closed)
// alerts once instead of on every single packet of that first
// occurrence — the operator can review and dismiss it, but isn't
// flooded.
func (e *Engine) raiseBaselineAlert(key string, packet core.Packet) {

	e.learnedPatterns[key] = true

	now := time.Now()

	alert, exists := e.alerts[key]

	if !exists {

		alert = &Alert{
			ID: key,

			Type:     AlertNewCommunication,
			Severity: "medium",
			Message: fmt.Sprintf(
				"New %s communication: %s:%d <-> %s:%d (not seen during baseline learning)",
				packet.L4Protocol, packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort,
			),

			IP: packet.SrcIP,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)
	}

	alert.LastSeen = now
	alert.Count++
}

// baselineKey builds a direction-independent identity for "asset A
// talks to asset B on this service", deliberately ignoring the
// ephemeral client source port. Without that, every single new
// client-initiated connection (a fresh random OS-assigned port each
// time) would look like a brand new, never-before-seen pattern, and
// the monitoring phase would alert constantly on completely normal
// traffic.
//
// The service port is approximated as whichever of the two ports is
// lower: real services conventionally listen on low/well-known ports
// (102, 502, 443...) while OS-assigned ephemeral client ports are
// always in the upper range. This is a heuristic, not a protocol
// negotiation — it can occasionally misidentify the service port for
// unusual setups, which is acceptable for a baseline signal but not
// something to build hard enforcement on.
func baselineKey(
	protocol string,
	ip1 string,
	port1 uint16,
	ip2 string,
	port2 uint16,
) string {

	servicePort := port1

	if port2 < port1 {
		servicePort = port2
	}

	a, b := ip1, ip2

	if a > b {
		a, b = b, a
	}

	return fmt.Sprintf(
		"baseline|%s|%s|%s|%s",
		protocol,
		a,
		b,
		strconv.Itoa(int(servicePort)),
	)
}

// BaselineStatus reports the current learning/monitoring state, so
// it's visible over the API rather than only in the startup logs.
type BaselineStatus struct {
	Mode            BaselineMode `json:"mode"`
	LearningStarted time.Time    `json:"learning_started"`
	LearningEndsAt  time.Time    `json:"learning_ends_at"`
	LearnedPatterns int          `json:"learned_patterns"`
	LearnedAssets   int          `json:"learned_assets"`
}

func (e *Engine) BaselineStatus() BaselineStatus {

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	mode := e.baselineMode

	if mode == "" {
		// No traffic observed yet — clock hasn't started, but this
		// is the mode it will start in.
		mode = BaselineModeLearning
	}

	return BaselineStatus{
		Mode:            mode,
		LearningStarted: e.learningStarted,
		LearningEndsAt:  e.learningStarted.Add(e.learningDuration),
		LearnedPatterns: len(e.learnedPatterns),
		LearnedAssets:   len(e.learnedAssets),
	}
}
