package detect

import (
	"fmt"
	"math"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/ics"
)

func (e *Engine) startOTValueAnomalyWatch(bus *core.EventBus) {
	if !e.otAnomaly.Enabled {
		return
	}
	ch := bus.Subscribe(core.EventICSMessage)
	go func() {
		for ev := range ch {
			if m, ok := ev.Data.(ics.Message); ok {
				e.handleOTValueAnomaly(m)
			}
		}
	}()
	go func() {
		t := time.NewTicker(e.otAnomaly.CheckInterval)
		defer t.Stop()
		for range t.C {
			e.checkSilentOTTags(time.Now())
		}
	}()
}

func (e *Engine) handleOTValueAnomaly(m ics.Message) {
	value, ok := numericValue(m.Details["value"])
	if !ok {
		return
	}
	space := fmt.Sprint(m.Details["address_space"])
	if space == "<nil>" || space == "" {
		space = fmt.Sprint(m.Details["area"])
	}
	addr := uint32Value(m.Details["address"])
	deviceIP, devicePort := m.DstIP, m.DstPort
	if m.IsResponse {
		deviceIP, devicePort = m.SrcIP, m.SrcPort
	}
	key := fmt.Sprintf("%s|%s|%d|%d|%s|%d", m.Protocol, deviceIP, devicePort, m.UnitID, space, addr)
	now := m.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	e.otMutex.Lock()
	st := e.otValues[key]
	if st == nil {
		st = &otValueState{LastValue: value, LastSeen: now, LastChange: now, DeviceIP: deviceIP, DevicePort: devicePort, AddressSpace: space, Address: addr}
		e.otValues[key] = st
	}
	previous := st.LastValue
	changed := st.Samples > 0 && previous != value
	z := 0.0
	if st.Samples >= uint64(e.otAnomaly.MinSamples) && st.Samples > 1 {
		sd := math.Sqrt(st.M2 / float64(st.Samples-1))
		if sd > 0 {
			z = math.Abs(value-st.Mean) / sd
		}
	}
	delta := math.Abs(value - previous)
	rateLimit := st.TypicalDelta * e.otAnomaly.RateMultiplier
	if changed {
		st.LastChange = now
		st.ToggleTimes = append(st.ToggleTimes, now)
		if st.Samples > 0 {
			if st.TypicalDelta == 0 {
				st.TypicalDelta = delta
			} else {
				st.TypicalDelta = .9*st.TypicalDelta + .1*delta
			}
		}
	}
	cutoff := now.Add(-e.otAnomaly.ToggleWindow)
	j := 0
	for _, x := range st.ToggleTimes {
		if !x.Before(cutoff) {
			st.ToggleTimes[j] = x
			j++
		}
	}
	st.ToggleTimes = st.ToggleTimes[:j]
	st.Samples++
	d := value - st.Mean
	st.Mean += d / float64(st.Samples)
	st.M2 += d * (value - st.Mean)
	st.LastValue = value
	st.LastSeen = now
	sampleCount := st.Samples
	toggles := len(st.ToggleTimes)
	lastChange := st.LastChange
	e.otMutex.Unlock()

	if sampleCount > uint64(e.otAnomaly.MinSamples) && z >= e.otAnomaly.ZScoreThreshold {
		e.raiseOTAnomaly("statistical", key, deviceIP, value, 75, fmt.Sprintf("value %.3f deviates %.1f standard deviations from learned behavior", value, z), map[string]interface{}{"anomaly_score": minInt(100, int(z*15)), "anomaly_confidence": 75, "z_score": z})
	}
	if changed && rateLimit > 0 && delta > rateLimit {
		e.raiseOTAnomaly("rate_of_change", key, deviceIP, value, 80, fmt.Sprintf("value changed by %.3f; learned typical change is %.3f", delta, st.TypicalDelta), map[string]interface{}{"anomaly_score": minInt(100, int(delta/rateLimit*70)), "anomaly_confidence": 80, "delta": delta, "rate_limit": rateLimit})
	}
	if toggles >= e.otAnomaly.ToggleThreshold {
		e.raiseOTAnomaly("excessive_toggle", key, deviceIP, value, 75, fmt.Sprintf("tag changed %d times within %s", toggles, e.otAnomaly.ToggleWindow), map[string]interface{}{"anomaly_score": 80, "anomaly_confidence": 75, "toggle_count": toggles})
	}
	if e.otAnomaly.UnexpectedWrites && isOTWrite(m) {
		e.raiseOTAnomaly("unexpected_write", key, deviceIP, value, 85, fmt.Sprintf("write operation %s observed for OT tag", m.FunctionName), map[string]interface{}{"anomaly_score": 85, "anomaly_confidence": 85, "source_ip": m.SrcIP, "function": m.FunctionName})
	}
	_ = lastChange
}

func (e *Engine) checkSilentOTTags(now time.Time) {
	e.otMutex.Lock()
	defer e.otMutex.Unlock()
	for key, st := range e.otValues {
		if st.Samples < uint64(e.otAnomaly.MinSamples) {
			continue
		}
		if now.Sub(st.LastSeen) >= e.otAnomaly.MissingAfter {
			go e.raiseOTAnomaly("missing_updates", key, st.DeviceIP, st.LastValue, 85, fmt.Sprintf("no update observed for %s", now.Sub(st.LastSeen).Round(time.Second)), map[string]interface{}{"anomaly_score": 85, "anomaly_confidence": 85, "last_seen": st.LastSeen})
		}
		if now.Sub(st.LastChange) >= e.otAnomaly.StuckAfter && now.Sub(st.LastSeen) < e.otAnomaly.MissingAfter {
			go e.raiseOTAnomaly("stuck_value", key, st.DeviceIP, st.LastValue, 70, fmt.Sprintf("value unchanged for %s while polling continues", now.Sub(st.LastChange).Round(time.Second)), map[string]interface{}{"anomaly_score": 70, "anomaly_confidence": 70, "last_change": st.LastChange})
		}
	}
}

func (e *Engine) raiseOTAnomaly(kind, key, ip string, value float64, confidence int, reason string, evidence map[string]interface{}) {
	if e.behaviorDetectionsSuppressed() {
		return
	}
	if !e.isRuleEnabled(string(AlertOTValueAnomaly)) {
		return
	}
	id := "ot_anomaly|" + kind + "|" + key
	now := time.Now()
	evidence["anomaly_type"] = kind
	evidence["value"] = value
	e.mutex.Lock()
	defer e.mutex.Unlock()
	a, exists := e.alerts[id]
	if exists && a.Status == AlertStatusApproved {
		return
	}
	if !exists {
		sev := "medium"
		if confidence >= 85 {
			sev = "high"
		}
		a = &Alert{ID: id, Type: AlertOTValueAnomaly, Severity: sev, Message: fmt.Sprintf("OT value anomaly on %s: %s", ip, reason), IP: ip, FirstSeen: now, Status: AlertStatusNew, Evidence: evidence}
		e.alerts[id] = a
		e.logNewAlert(a)
	}
	e.recordEpisodeAlertLocked(a, now, alertEpisodeGap)
}
func numericValue(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int8:
		return float64(x), true
	case int16:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint8:
		return float64(x), true
	case uint16:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float32:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}
func uint32Value(v any) uint32 {
	switch x := v.(type) {
	case uint32:
		return x
	case uint16:
		return uint32(x)
	case int:
		return uint32(x)
	case int64:
		return uint32(x)
	case float64:
		return uint32(x)
	}
	return 0
}
func isOTWrite(m ics.Message) bool {
	return !m.IsResponse && (m.FunctionName == "Write Single Coil" || m.FunctionName == "Write Single Register" || m.FunctionName == "Write Multiple Coils" || m.FunctionName == "Write Multiple Registers" || m.FunctionName == "WriteVar")
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
