package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// startValueOutOfRangeWatch consumes core.EventValueOutOfRange,
// published by internal/store the moment an OT variable's value
// (observed after baseline learning completed) falls outside the
// range that same variable occupied during learning — see
// store.Tag.MinValue/MaxValue. Raising this as a normal Alert keeps
// it visible alongside every other finding in the Alerts tab.
func (e *Engine) startValueOutOfRangeWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventValueOutOfRange)

	go func() {

		for event := range ch {

			ov, ok := event.Data.(core.OutOfRangeValue)

			if !ok {
				continue
			}

			e.handleValueOutOfRange(ov)

		}

	}()

}

func (e *Engine) handleValueOutOfRange(ov core.OutOfRangeValue) {

	if !e.isRuleEnabled(string(AlertValueOutOfRange)) {
		return
	}

	if ov.TagKey == "" {
		return
	}

	// Deduplicated per tag, same as every other alert type here —
	// repeated out-of-range hits on the same variable update one
	// alert's Count/LastSeen rather than creating a new one each
	// time.
	key := fmt.Sprintf("outofrange|%s", ov.TagKey)

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[key]

	if exists && !e.allowAlertOccurrenceLocked(alert) {
		return
	}

	if !exists {

		message := fmt.Sprintf(
			"%s:%d %s %d value %v outside learned range [%v, %v]",
			ov.DeviceIP, ov.DevicePort, ov.AddressSpace, ov.Address,
			ov.Value, ov.MinValue, ov.MaxValue,
		)

		alert = &Alert{
			ID: key,

			Type:     AlertValueOutOfRange,
			Severity: "medium",
			Message:  message,

			IP: ov.DeviceIP,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)
	}

	alert.LastSeen = now
	alert.Count++
}
