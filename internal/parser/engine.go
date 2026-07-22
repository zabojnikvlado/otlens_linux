package parser

import (
	"github.com/zabojnikvlado/otlens/internal/core"
	"github.com/zabojnikvlado/otlens/internal/logger"
)

type Engine struct {
	EventBus *core.EventBus
}

func New(bus *core.EventBus) *Engine {
	return &Engine{
		EventBus: bus,
	}
}

func (e *Engine) Start() {

	logger.Log.Info(
		"Parser engine started",
	)

	ch := e.EventBus.Subscribe(core.EventPacketCaptured)

	go func() {

		for event := range ch {

			e.handle(event)

		}

	}()

}

func (e *Engine) handle(event core.Event) {

	frame, ok := event.Data.(core.RawFrame)

	if !ok {
		return
	}

	parsedPacket := Parse(frame)

	e.EventBus.Publish(
		core.Event{
			Type: core.EventPacketParsed,
			Data: parsedPacket,
		},
	)

}
