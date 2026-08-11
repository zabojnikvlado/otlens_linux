package detect

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
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
		e.baselineMode = BaselineModeLearning
		e.learningStarted = now
		logger.Log.Info("Baseline learning started", zap.Duration("minimum_duration", e.learningDuration))
	}

	// Per-asset maturity is collected throughout learning. A device first seen
	// near the end of the global window therefore cannot make the baseline look
	// mature after only a handful of packets.
	if e.baselineMode == BaselineModeLearning {
		for _, mac := range macs {
			e.learnedAssets[mac] = true
			if e.assetFirstSeen[mac].IsZero() {
				e.assetFirstSeen[mac] = now
			}
			e.assetSamples[mac]++
		}
	}

	var key string
	if hasIPEndpoints {
		key = baselineKeyForPacket(packet)
		if e.baselineMode == BaselineModeLearning && !e.learnedPatterns[key] {
			e.learnedPatterns[key] = true
			e.patternCreatedAt = append(e.patternCreatedAt, now)
			if len(e.patternCreatedAt) > 10000 {
				e.patternCreatedAt = append([]time.Time(nil), e.patternCreatedAt[len(e.patternCreatedAt)-10000:]...)
			}
		}
	}

	justCompleted := false
	if e.baselineMode == BaselineModeLearning && now.Sub(e.learningStarted) >= e.learningDuration {
		readiness, ready, reason := e.baselineReadinessLocked(now)
		maxDuration := 2 * e.learningDuration
		if maxDuration < e.learningDuration {
			maxDuration = e.learningDuration
		}
		forced := now.Sub(e.learningStarted) >= maxDuration
		if ready || forced {
			e.baselineMode = BaselineModeMonitoring
			justCompleted = true
			logger.Log.Info("Baseline learning complete, now monitoring for deviations",
				zap.Int("learned_patterns", len(e.learnedPatterns)), zap.Int("learned_assets", len(e.learnedAssets)),
				zap.Float64("readiness", readiness), zap.Bool("forced", forced), zap.String("readiness_reason", reason))
		}
	}

	if justCompleted {
		e.publishBaselineComplete()
	}
	if !hasIPEndpoints || e.baselineMode == BaselineModeLearning {
		return
	}
	if e.learnedPatterns[key] {
		return
	}
	e.raiseBaselineAlert(key, packet)
}

// baselineReadinessLocked returns a 0..1 quality score and the gating decision.
// LearningDuration is a minimum: the baseline continues while most assets are
// still low-sample or the network is still discovering many new patterns.
// Caller must hold e.mutex.
func (e *Engine) baselineReadinessLocked(now time.Time) (float64, bool, string) {
	if e.learningStarted.IsZero() {
		return 0, false, "waiting for first traffic"
	}
	elapsed := now.Sub(e.learningStarted)
	durationScore := float64(elapsed) / float64(e.learningDuration)
	if durationScore > 1 {
		durationScore = 1
	}

	minAge := e.learningDuration / 4
	minSamples := uint64(50)
	if e.learningDuration < 5*time.Minute {
		if minAge < time.Millisecond {
			minAge = time.Millisecond
		}
		minSamples = 5
	} else if minAge < 5*time.Minute {
		minAge = 5 * time.Minute
	}
	if minAge > time.Hour {
		minAge = time.Hour
	}
	mature := 0
	for mac := range e.learnedAssets {
		if e.assetSamples[mac] >= minSamples && !e.assetFirstSeen[mac].IsZero() && now.Sub(e.assetFirstSeen[mac]) >= minAge {
			mature++
		}
	}
	maturityRatio := 0.0
	if len(e.learnedAssets) > 0 {
		maturityRatio = float64(mature) / float64(len(e.learnedAssets))
	}

	window := e.learningDuration / 10
	if window < time.Minute {
		window = time.Minute
	}
	if window > 30*time.Minute {
		window = 30 * time.Minute
	}
	cutoff := now.Add(-window)
	recent := 0
	for _, at := range e.patternCreatedAt {
		if !at.Before(cutoff) {
			recent++
		}
	}
	novelty := 0.0
	if len(e.learnedPatterns) > 0 {
		novelty = float64(recent) / float64(len(e.learnedPatterns))
	}
	stability := 1 - math.Min(1, novelty/.05)
	readiness := .45*durationScore + .40*maturityRatio + .15*stability
	ready := elapsed >= e.learningDuration && readiness >= .85 && maturityRatio >= .75 && novelty <= .05
	reason := "baseline still accumulating coverage"
	switch {
	case elapsed < e.learningDuration:
		reason = "minimum learning duration not reached"
	case maturityRatio < .75:
		reason = "too many assets still have low-sample profiles"
	case novelty > .05:
		reason = "new communication patterns are still arriving too quickly"
	case ready:
		reason = "baseline maturity and stability thresholds satisfied"
	}
	return readiness, ready, reason
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

// CompleteBaseline freezes the legacy communication/asset baseline and moves
// every detector that keys its learning state off baselineMode into monitoring.
// This includes policy learning and OT value learning. The normal path is only
// allowed after learningDuration; force is an explicit operator override.
func (e *Engine) CompleteBaseline(force bool) (bool, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if !e.baselineEnabled {
		e.baselineMode = BaselineModeMonitoring
		return false, nil
	}
	if e.baselineMode == BaselineModeMonitoring {
		return false, nil
	}
	if e.baselineMode == "" || e.learningStarted.IsZero() {
		return false, fmt.Errorf("baseline learning has not started")
	}
	if !force && time.Since(e.learningStarted) < e.learningDuration {
		return false, fmt.Errorf("minimum learning duration has not elapsed")
	}

	e.baselineMode = BaselineModeMonitoring
	e.publishBaselineComplete()
	logger.Log.Info("Baseline learning manually completed, now monitoring for deviations",
		zap.Int("learned_patterns", len(e.learnedPatterns)),
		zap.Int("learned_assets", len(e.learnedAssets)),
		zap.Bool("forced", force))
	return true, nil
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
// A post-learning pattern is deliberately NOT added to learnedPatterns here.
// It becomes trusted baseline only after an analyst explicitly approves the
// alert. Episode deduplication below prevents a continuous packet stream from
// flooding the alert store while it is awaiting review.
func (e *Engine) raiseBaselineAlert(key string, packet core.Packet) {
	now := packet.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	service := packet.DstPort
	message := fmt.Sprintf("New %s communication: %s:%d <-> %s:%d (not seen during trusted baseline)", packet.L4Protocol, packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
	evidence := map[string]interface{}{"source_ip": packet.SrcIP, "destination_ip": packet.DstIP, "source_port": packet.SrcPort, "destination_port": packet.DstPort, "protocol": packet.L4Protocol, "service_port": service}
	e.raiseBuiltinAlertLocked(string(AlertNewCommunication), AlertNewCommunication, "medium", key, message, packet.SrcIP, evidence, now, alertEpisodeGap)
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
func baselineKeyForPacket(packet core.Packet) string {
	service := packet.SrcPort
	flags := strings.ToUpper(packet.TCPFlags)
	if strings.EqualFold(packet.L4Protocol, "tcp") && strings.Contains(flags, "SYN") {
		if strings.Contains(flags, "ACK") && packet.SrcPort != 0 {
			service = packet.SrcPort
		} else if !strings.Contains(flags, "ACK") && packet.DstPort != 0 {
			service = packet.DstPort
		} else if packet.DstPort < service {
			service = packet.DstPort
		}
	} else if packet.DstPort < service {
		service = packet.DstPort
	}
	a, b := packet.SrcIP, packet.DstIP
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("baseline|%s|%s|%s|%s", packet.L4Protocol, a, b, strconv.Itoa(int(service)))
}

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
	Enabled                   bool          `json:"enabled"`
	ManualCompletionSupported bool          `json:"manual_completion_supported"`
	Mode                      BaselineMode  `json:"mode"`
	LearningStarted           time.Time     `json:"learning_started"`
	LearningEndsAt            time.Time     `json:"learning_ends_at"`
	MinimumDuration           time.Duration `json:"minimum_duration"`
	Readiness                 float64       `json:"readiness"`
	Ready                     bool          `json:"ready"`
	ReadinessReason           string        `json:"readiness_reason,omitempty"`
	LearnedPatterns           int           `json:"learned_patterns"`
	LearnedAssets             int           `json:"learned_assets"`
	MatureAssets              int           `json:"mature_assets"`
	LearningAssets            int           `json:"learning_assets"`
	NewPatternRate            float64       `json:"new_pattern_rate"`
}

func (e *Engine) BaselineStatus() BaselineStatus {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	mode := e.baselineMode
	if mode == "" {
		mode = BaselineModeLearning
	}
	now := time.Now()
	readiness, ready, reason := e.baselineReadinessLocked(now)
	minAge := e.learningDuration / 4
	minSamples := uint64(50)
	if e.learningDuration < 5*time.Minute {
		if minAge < time.Millisecond {
			minAge = time.Millisecond
		}
		minSamples = 5
	} else if minAge < 5*time.Minute {
		minAge = 5 * time.Minute
	}
	if minAge > time.Hour {
		minAge = time.Hour
	}
	mature := 0
	for mac := range e.learnedAssets {
		if e.assetSamples[mac] >= minSamples && !e.assetFirstSeen[mac].IsZero() && now.Sub(e.assetFirstSeen[mac]) >= minAge {
			mature++
		}
	}
	window := e.learningDuration / 10
	if window < time.Minute {
		window = time.Minute
	}
	if window > 30*time.Minute {
		window = 30 * time.Minute
	}
	cutoff := now.Add(-window)
	recent := 0
	for _, at := range e.patternCreatedAt {
		if !at.Before(cutoff) {
			recent++
		}
	}
	novelty := 0.0
	if len(e.learnedPatterns) > 0 {
		novelty = float64(recent) / float64(len(e.learnedPatterns))
	}
	return BaselineStatus{Enabled: e.baselineEnabled, ManualCompletionSupported: true, Mode: mode, LearningStarted: e.learningStarted, LearningEndsAt: e.learningStarted.Add(e.learningDuration), MinimumDuration: e.learningDuration, Readiness: readiness, Ready: ready, ReadinessReason: reason, LearnedPatterns: len(e.learnedPatterns), LearnedAssets: len(e.learnedAssets), MatureAssets: mature, LearningAssets: len(e.learnedAssets) - mature, NewPatternRate: novelty}
}
