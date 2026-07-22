package core

import "sync"

// EventBus is a concurrency-safe in-process publish/subscribe hub. Every
// engine in OTLens communicates through it, keeping the processing pipeline
// decoupled while allowing capture to continue even when a consumer is slow.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[EventType][]chan Event
}

func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[EventType][]chan Event),
	}
}

// Subscribe returns a buffered channel receiving future events of eventType.
// Each subscription is an independent fan-out consumer.
func (b *EventBus) Subscribe(eventType EventType) chan Event {
	ch := make(chan Event, 1000)

	b.mu.Lock()
	b.subscribers[eventType] = append(b.subscribers[eventType], ch)
	b.mu.Unlock()

	return ch
}

// Publish is deliberately non-blocking. If a consumer has filled its buffer,
// its oldest queued event is dropped before the newest event is queued. This
// prevents one slow detector/debug/API consumer from backpressuring packet
// capture and the rest of the pipeline.
//
// The subscription slice is copied under the read lock, so publishers do not
// iterate a map/slice concurrently with a future subscription.
func (b *EventBus) Publish(event Event) {
	b.mu.RLock()
	subscribers := append([]chan Event(nil), b.subscribers[event.Type]...)
	b.mu.RUnlock()

	for _, subscriber := range subscribers {
		select {
		case subscriber <- event:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- event:
			default:
			}
		}
	}
}
