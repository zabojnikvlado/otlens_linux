package udpconversation

import (
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

// Engine consumes parsed UDP packets and periodically expires idle
// conversations.
type Engine struct {
	bus     *core.EventBus
	manager *Manager

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func New(bus *core.EventBus, config ManagerConfig) *Engine {
	return &Engine{
		bus:     bus,
		manager: NewManagerWithConfig(config),
		stop:    make(chan struct{}),
	}
}

func (e *Engine) Start() {
	if e.bus == nil {
		return
	}
	packets := e.bus.Subscribe(core.EventPacketParsed)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			select {
			case <-e.stop:
				return
			case event := <-packets:
				switch packet := event.Data.(type) {
				case core.Packet:
					if packet.L4Protocol == "UDP" {
						e.process(packet)
					}
				case *core.Packet:
					if packet != nil && packet.L4Protocol == "UDP" {
						e.process(*packet)
					}
				}
			}
		}
	}()

	if e.manager.config.IdleTimeout > 0 {
		interval := e.manager.config.IdleTimeout / 2
		if interval < time.Second {
			interval = time.Second
		}
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-e.stop:
					return
				case now := <-ticker.C:
					e.manager.ExpireIdle(now)
				}
			}
		}()
	}
}

func (e *Engine) process(packet core.Packet) {
	if e.manager.config.Disabled {
		e.bus.Publish(core.Event{
			Type:      core.EventUDPConversationPacket,
			Timestamp: packet.Timestamp,
			Data:      ContextualPacket{Packet: packet},
		})
		return
	}
	_, context, _ := e.manager.ObserveWithContext(packet)
	e.bus.Publish(core.Event{
		Type:      core.EventUDPConversationPacket,
		Timestamp: packet.Timestamp,
		Data: ContextualPacket{
			Packet:  packet,
			Context: context,
		},
	})
}

func (e *Engine) Stop() {
	e.stopOnce.Do(func() { close(e.stop) })
	e.wg.Wait()
}

func (e *Engine) Manager() *Manager {
	return e.manager
}

func (e *Engine) Reset() {
	if e.manager != nil {
		e.manager.Reset()
	}
}

func (e *Engine) Stats() ManagerStats {
	return e.manager.Stats()
}
