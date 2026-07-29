package central

import (
	"fmt"
	"testing"
	"time"
)

func TestLiveHubPublishesAndReplays(t *testing.T) {
	hub := NewLiveHub(2)
	first, _ := hub.subscribe(0)
	defer hub.unsubscribe(first)

	hub.Publish(LiveEvent{Type: "alert.created", Message: "one"})
	select {
	case got := <-first.ch:
		if got.ID != 1 || got.Type != "alert.created" || got.Time.IsZero() {
			t.Fatalf("unexpected live event: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("live event was not delivered")
	}

	hub.Publish(LiveEvent{Type: "incident.updated", Message: "two"})
	hub.Publish(LiveEvent{Type: "discovery.completed", Message: "three"})
	second, replay := hub.subscribe(1)
	defer hub.unsubscribe(second)
	if len(replay) != 2 || replay[0].ID != 2 || replay[1].ID != 3 {
		t.Fatalf("unexpected replay: %+v", replay)
	}
}

func TestLiveHubDoesNotBlockOnSlowSubscriber(t *testing.T) {
	hub := NewLiveHub(10)
	sub, _ := hub.subscribe(0)
	defer hub.unsubscribe(sub)
	for i := 0; i < 200; i++ {
		hub.Publish(LiveEvent{Type: "sensor.health"})
	}
	if len(hub.replay) != 10 {
		t.Fatalf("expected bounded replay, got %d", len(hub.replay))
	}
}

func TestLiveHubSnapshotIsBoundedAndOrdered(t *testing.T) {
	h := NewLiveHub(10)
	for i := 0; i < 6; i++ {
		h.Publish(LiveEvent{Type: "test.event", Message: fmt.Sprintf("%d", i)})
	}
	got := h.snapshot(2, 3)
	if len(got) != 3 {
		t.Fatalf("snapshot len=%d want 3", len(got))
	}
	if got[0].ID != 3 || got[2].ID != 5 {
		t.Fatalf("unexpected IDs: %#v", got)
	}
}

func TestLiveEventRBACDenyByDefault(t *testing.T) {
	perms := Permissions{View: []string{ViewAlerts}}
	if !canViewLiveEvent(perms, LiveEvent{Type: "alert.created"}) {
		t.Fatal("alerts view should receive alert events")
	}
	if canViewLiveEvent(perms, LiveEvent{Type: "sensor.health"}) {
		t.Fatal("alerts-only role must not receive sensor events")
	}
	if canViewLiveEvent(perms, LiveEvent{Type: "future.unclassified"}) {
		t.Fatal("unclassified live events must be denied by default")
	}
}

func TestLiveEventHistoryFiltering(t *testing.T) {
	perms := Permissions{View: []string{ViewAssets}}
	in := []LiveEvent{{Type: "asset-risk.changed"}, {Type: "alert.created"}, {Type: "stream.ready"}}
	got := filterLiveEvents(perms, in)
	if len(got) != 2 || got[0].Type != "asset-risk.changed" || got[1].Type != "stream.ready" {
		t.Fatalf("unexpected filtered events: %#v", got)
	}
}
