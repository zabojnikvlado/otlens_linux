package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// startAssetUnconfirmedWatch consumes core.EventAssetUnconfirmed,
// published by internal/asset the moment it discovers a device after
// baseline learning completed that wasn't part of the learned set —
// see baseline.go's handleBaseline/publishBaselineComplete for the
// producer side. Raising this as a normal Alert keeps it visible
// alongside every other finding in the Alerts tab, in addition to the
// device itself showing as unconfirmed on the Assets tab and in red
// on the topology graph.
func (e *Engine) startAssetUnconfirmedWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventAssetUnconfirmed)

	go func() {

		for event := range ch {

			ua, ok := event.Data.(core.UnconfirmedAsset)

			if !ok {
				continue
			}

			e.handleAssetUnconfirmed(ua)

		}

	}()

}

func (e *Engine) handleAssetUnconfirmed(ua core.UnconfirmedAsset) {

	if !e.isRuleEnabled(string(AlertNewAsset)) {
		return
	}

	if ua.MAC == "" {
		return
	}

	key := fmt.Sprintf("newasset|%s", ua.MAC)

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[key]

	if !exists {

		message := fmt.Sprintf("New device detected: %s", ua.MAC)

		if ua.IP != "" {
			message = fmt.Sprintf("New device detected: %s (%s)", ua.MAC, ua.IP)
		}

		alert = &Alert{
			ID: key,

			Type:     AlertNewAsset,
			Severity: "medium",
			Message:  message,

			IP: ua.IP,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)
	}

	alert.LastSeen = now
	alert.Count++
}
