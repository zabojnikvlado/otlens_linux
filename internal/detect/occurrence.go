package detect

import (
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/ics"
)

const (
	alertEpisodeGap            = 5 * time.Minute
	alertFreshnessSyncInterval = time.Minute
)

// behaviorDetectionsSuppressed reports whether detectors that need a mature
// behavior/baseline model should collect state without raising alerts.
func (e *Engine) behaviorDetectionsSuppressed() bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.baselineEnabled && e.baselineMode != BaselineModeMonitoring
}

// recordEpisodeAlertLocked updates a deduplicated alert using episode semantics.
// A continuous packet stream is one occurrence. Count increments only when the
// condition is first seen or comes back after a quiet gap. LastSeen remains live,
// while telemetry dirtying is throttled so persistent traffic cannot force a
// Central write for every packet. Caller must hold e.mutex.
func (e *Engine) recordEpisodeAlertLocked(alert *Alert, now time.Time, gap time.Duration) bool {
	if alert == nil || alert.Status == AlertStatusApproved {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	if gap <= 0 {
		gap = alertEpisodeGap
	}

	previous := alert.LastSeen
	newEpisode := alert.Count == 0 || previous.IsZero() || now.Sub(previous) > gap

	if newEpisode {
		if alert.Status == AlertStatusConfirmed {
			alert.Status = AlertStatusNew
			alert.StatusChangedAt = now
		}
		alert.Count++
		alert.Synced = false
		alert.lastSyncTouch = now
	} else if alert.lastSyncTouch.IsZero() || now.Sub(alert.lastSyncTouch) >= alertFreshnessSyncInterval {
		alert.Synced = false
		alert.lastSyncTouch = now
	}

	alert.LastSeen = now
	return true
}

// ResetOTAnomalyState clears statistical OT anomaly history without changing
// configured detector thresholds.
func (e *Engine) ResetOTAnomalyState() {
	e.otMutex.Lock()
	e.otValues = make(map[string]*otValueState)
	e.otMutex.Unlock()
}

// ResetLearningState starts the complete sensor learning stack from a clean
// detector state. Rules/configuration and alert review history are not removed;
// Data Management operations decide separately whether to clear alerts.
func (e *Engine) ResetLearningState() {
	e.ResetBaseline()
	e.RestoreKnownMAC(map[string]string{})

	e.mutex.Lock()
	e.candidateMAC = make(map[string]string)
	e.candidateCount = make(map[string]int)
	e.mutex.Unlock()

	e.scanMutex.Lock()
	e.hostScanSeen = make(map[string]map[string]time.Time)
	e.portScanSeen = make(map[string]map[string]map[int]time.Time)
	e.scanMutex.Unlock()

	e.beaconMutex.Lock()
	e.beaconHistory = make(map[string][]time.Time)
	e.beaconLastTouch = make(map[string]time.Time)
	e.beaconMutex.Unlock()

	e.ipVLANMutex.Lock()
	e.ipVLAN = make(map[string]uint16)
	e.ipVLANSeen = make(map[string]time.Time)
	e.ipVLANMutex.Unlock()

	e.lateralData.mutex.Lock()
	e.lateralData.fanout = make(map[string]map[string]time.Time)
	e.lateralData.transfers = make(map[string]*trafficWindow)
	e.lateralData.inboundAdmin = make(map[string]map[string]time.Time)
	e.lateralData.mutex.Unlock()

	e.c2DNSMutex.Lock()
	e.c2NXDomains = make(map[string][]time.Time)
	e.c2Subdomains = make(map[string]map[string]time.Time)
	e.c2DNSMutex.Unlock()

	e.ResetOTAnomalyState()
	e.resetPolicyLearningState()
}

// excludePacketFromLearning tells the statistical behavior learner that a hard
// security/policy detector has identified this flow. During learning the
// learner removes/quarantines the matching profile so commissioning-time attack
// traffic cannot become trusted normal behavior. In monitoring the event only
// prevents candidate promotion.
func (e *Engine) excludePacketFromLearning(packet core.Packet, reason string) {
	if packet.SrcIP == "" || packet.DstIP == "" {
		return
	}
	e.quarantinePolicyLearning(packet.SrcIP, packet.DstIP, time.Now().Add(24*time.Hour))
	// The statistical baseline receives the exclusion event below. Remove the
	// same flow from the legacy communication baseline as well so a hard
	// security hit observed during learning can never become trusted merely
	// because packet learning ran before the detector.
	e.mutex.Lock()
	if e.baselineMode == BaselineModeLearning {
		delete(e.learnedPatterns, e.baselineKeyForPacketLocked(packet))
	}
	e.mutex.Unlock()
	if e.eventBus == nil {
		return
	}
	service := packet.SrcPort
	flags := strings.ToUpper(packet.TCPFlags)
	if strings.EqualFold(packet.L4Protocol, "tcp") && strings.Contains(flags, "SYN") {
		if strings.Contains(flags, "ACK") && packet.SrcPort != 0 {
			service = packet.SrcPort
		} else if !strings.Contains(flags, "ACK") && packet.DstPort != 0 {
			service = packet.DstPort
		}
	}
	if service == 0 || (packet.DstPort != 0 && packet.DstPort < service && !strings.Contains(flags, "SYN")) {
		service = packet.DstPort
	}
	e.eventBus.Publish(core.Event{Type: core.EventLearningExclusion, Timestamp: time.Now().UTC(), Data: core.LearningExclusion{SrcIP: packet.SrcIP, DstIP: packet.DstIP, Protocol: packet.L4Protocol, ServicePort: service, Reason: reason, Until: time.Now().UTC().Add(24 * time.Hour)}})
}

func (e *Engine) excludeICSFromLearning(msg ics.Message, reason string) {
	if msg.SrcIP == "" || msg.DstIP == "" {
		return
	}
	// Use the request direction for policy authority regardless of whether the
	// exclusion originated from a request or response observation.
	src, dst := msg.SrcIP, msg.DstIP
	if msg.IsResponse {
		src, dst = msg.DstIP, msg.SrcIP
	}
	e.quarantinePolicyLearning(src, dst, time.Now().Add(24*time.Hour))
	if e.eventBus == nil {
		return
	}
	service := msg.DstPort
	if msg.IsResponse {
		service = msg.SrcPort
	}
	e.eventBus.Publish(core.Event{Type: core.EventLearningExclusion, Timestamp: time.Now().UTC(), Data: core.LearningExclusion{SrcIP: msg.SrcIP, DstIP: msg.DstIP, Protocol: msg.Protocol, ServicePort: service, Reason: reason, Until: time.Now().UTC().Add(24 * time.Hour)}})
}
