package detect

import (
	"fmt"
	"math"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// maxBeaconSamplesPerKey bounds memory per tracked destination —
// MinSamples worth of history is all that's ever needed to judge
// regularity, so keeping more than a handful past that just wastes
// memory without improving the measurement.
const maxBeaconSamplesPerKey = 20

// startC2BeaconWatch consumes core.EventPacketParsed to detect
// suspiciously regular outbound TCP connection timing — see
// handleC2Beacon's doc comment for what "suspiciously regular" means
// and why this is a behavioral heuristic, not a known-bad-IP match.
func (e *Engine) startC2BeaconWatch(bus *core.EventBus) {

	if !e.c2BeaconEnabled {
		return
	}

	ch := bus.Subscribe(
		core.EventPacketParsed,
	)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok {
				continue
			}

			e.handleC2Beacon(packet)

		}

	}()

}

// handleC2Beacon tracks, per (source IP, external destination IP,
// destination port), the timestamps of outbound TCP connection
// *attempts* — a SYN packet, not the SYN,ACK response, since that's
// the one signal that reliably marks "a new connection just started"
// rather than an ongoing one. Once enough attempts have been seen
// (MinSamples), the intervals between them are checked for regularity
// (low coefficient of variation — stddev/mean) within a plausible
// beacon range (MinInterval..MaxInterval). Malware that "checks in"
// with a command-and-control server on a fixed or lightly-jittered
// timer looks exactly like this; so, sometimes, does a legitimate
// periodic external service (a license check-in, a monitoring agent
// phoning a SaaS dashboard) — this can't tell the two apart on its own,
// which is why it's a behavioral heuristic to investigate, not a
// confirmed-malicious verdict.
//
// Deliberately scoped to internal source -> external destination only
// (see isPrivateIP): C2 conceptually means talking to an attacker's
// external infrastructure, and restricting to that cuts down on false
// positives from legitimate internal periodic services (health
// checks, replication, monitoring) that this isn't meant to catch.
func (e *Engine) handleC2Beacon(packet core.Packet) {

	if !e.c2BeaconEnabled || packet.TCPFlags != "SYN" || packet.SrcIP == "" || packet.DstIP == "" || packet.DstPort == 0 {
		return
	}

	if !isPrivateIP(packet.SrcIP) || isPrivateIP(packet.DstIP) {
		return
	}

	key := fmt.Sprintf("%s|%s|%d", packet.SrcIP, packet.DstIP, packet.DstPort)
	now := time.Now()

	e.beaconMutex.Lock()

	if e.beaconHistory == nil {
		e.beaconHistory = make(map[string][]time.Time)
		e.beaconLastTouch = make(map[string]time.Time)
	}

	if _, exists := e.beaconHistory[key]; !exists && len(e.beaconHistory) >= e.c2BeaconMaxTrackedDests {
		e.evictOldestBeaconLocked()
	}

	history := append(e.beaconHistory[key], now)
	if len(history) > maxBeaconSamplesPerKey {
		history = history[len(history)-maxBeaconSamplesPerKey:]
	}
	e.beaconHistory[key] = history
	e.beaconLastTouch[key] = now

	samples := make([]time.Time, len(history))
	copy(samples, history)

	e.beaconMutex.Unlock()

	if len(samples) < e.c2BeaconMinSamples {
		return
	}

	mean, cv, ok := beaconRegularity(samples)
	if !ok || mean < e.c2BeaconMinInterval || mean > e.c2BeaconMaxInterval || cv > e.c2BeaconMaxCV {
		return
	}

	e.raiseC2BeaconAlert(key, packet.SrcIP, packet.DstIP, packet.DstPort, mean, cv)
}

// evictOldestBeaconLocked drops whichever tracked destination was
// least recently touched — the backstop that keeps
// MaxTrackedDestinations an actual ceiling. Caller must hold
// beaconMutex.
func (e *Engine) evictOldestBeaconLocked() {

	var oldestKey string
	var oldestTime time.Time
	first := true

	for k, t := range e.beaconLastTouch {
		if first || t.Before(oldestTime) {
			oldestKey, oldestTime, first = k, t, false
		}
	}

	if oldestKey != "" {
		delete(e.beaconHistory, oldestKey)
		delete(e.beaconLastTouch, oldestKey)
	}
}

// beaconRegularity computes the mean interval and coefficient of
// variation (stddev/mean) between consecutive timestamps — samples
// must already be in chronological order (they are: beaconHistory is
// only ever appended to). ok is false if there aren't at least 2
// intervals to measure, or the mean interval is zero (guards a
// divide-by-zero; shouldn't happen with real packet timestamps, but
// cheap to check).
func beaconRegularity(samples []time.Time) (mean time.Duration, cv float64, ok bool) {

	if len(samples) < 3 {
		return 0, 0, false
	}

	intervals := make([]float64, 0, len(samples)-1)
	for i := 1; i < len(samples); i++ {
		intervals = append(intervals, samples[i].Sub(samples[i-1]).Seconds())
	}

	var sum float64
	for _, v := range intervals {
		sum += v
	}
	meanSeconds := sum / float64(len(intervals))
	if meanSeconds <= 0 {
		return 0, 0, false
	}

	var variance float64
	for _, v := range intervals {
		diff := v - meanSeconds
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	return time.Duration(meanSeconds * float64(time.Second)), math.Sqrt(variance) / meanSeconds, true
}

func (e *Engine) raiseC2BeaconAlert(key, srcIP, dstIP string, dstPort uint16, mean time.Duration, cv float64) {

	if !e.isRuleEnabled(string(AlertC2Beacon)) {
		return
	}

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[key]

	if exists && !e.allowAlertOccurrenceLocked(alert) {
		return
	}

	if !exists {

		alert = &Alert{
			ID: key,

			Type:     AlertC2Beacon,
			Severity: "critical",
			Message: fmt.Sprintf(
				"%s connects to %s:%d at a suspiciously regular ~%s interval (%.0f%% variation) — possible C2 beaconing",
				srcIP, dstIP, dstPort, mean.Round(time.Second), cv*100,
			),

			IP: srcIP,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)

	}

	alert.LastSeen = now
	alert.Count++
	alert.Synced = false

}
