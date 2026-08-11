package flow

import (
	"testing"
	"time"
)

func TestMarkFlowsSyncedDoesNotAcknowledgeNewerLiveVersion(t *testing.T) {
	at := time.Now().UTC()
	engine := &Engine{flows: map[string]*Flow{
		"f": {ID: "f", Packets: 11, Bytes: 1100, LastSeen: at.Add(time.Second), Synced: false},
	}}
	engine.MarkFlowsSynced([]SyncSnapshot{{ID: "f", Packets: 10, Bytes: 1000, LastSeen: at}})
	if engine.flows["f"].Synced {
		t.Fatal("newer live flow was incorrectly acknowledged by an older telemetry snapshot")
	}
}

func TestMarkFlowsSyncedAcknowledgesExactVersion(t *testing.T) {
	at := time.Now().UTC()
	engine := &Engine{flows: map[string]*Flow{
		"f": {ID: "f", Packets: 10, Bytes: 1000, LastSeen: at, Synced: false},
	}}
	engine.MarkFlowsSynced([]SyncSnapshot{{ID: "f", Packets: 10, Bytes: 1000, LastSeen: at}})
	if !engine.flows["f"].Synced {
		t.Fatal("exact flow telemetry version was not acknowledged")
	}
}
