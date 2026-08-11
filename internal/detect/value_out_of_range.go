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
	if e.behaviorDetectionsSuppressed() || ov.TagKey == "" {
		return
	}
	message := fmt.Sprintf("%s:%d %s %d value %v outside learned robust range [%v, %v]", ov.DeviceIP, ov.DevicePort, ov.AddressSpace, ov.Address, ov.Value, ov.MinValue, ov.MaxValue)
	if ov.Reason == "rate_of_change" {
		message = fmt.Sprintf("%s:%d %s %d changed by %.3f at %.3f units/s; learned rate limit is %.3f units/s", ov.DeviceIP, ov.DevicePort, ov.AddressSpace, ov.Address, ov.Delta, ov.Rate, ov.RateLimit)
	}
	evidence := map[string]interface{}{"tag_key": ov.TagKey, "reason": ov.Reason, "value": ov.Value, "min": ov.MinValue, "max": ov.MaxValue, "rate": ov.Rate, "rate_limit": ov.RateLimit}
	e.raiseBuiltinAlert(string(AlertValueOutOfRange), AlertValueOutOfRange, "medium", "outofrange|"+ov.TagKey, message, ov.DeviceIP, evidence, time.Now(), alertEpisodeGap)
}
