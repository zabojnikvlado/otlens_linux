package detect

import (
	"testing"
	"time"
)

func TestMarkAlertsSyncedDoesNotAcknowledgeNewerLiveVersion(t *testing.T) {
	at := time.Now().UTC()
	engine := &Engine{alerts: map[string]*Alert{
		"a": {ID: "a", Type: AlertNewCommunication, Severity: "high", Message: "x", IP: "10.0.0.1", FirstSeen: at, LastSeen: at.Add(time.Second), Count: 2, Status: AlertStatusNew, Evidence: map[string]interface{}{"score": 90}, Synced: false},
	}}
	sent := &Alert{ID: "a", Type: AlertNewCommunication, Severity: "high", Message: "x", IP: "10.0.0.1", FirstSeen: at, LastSeen: at, Count: 1, Status: AlertStatusNew, Evidence: map[string]interface{}{"score": float64(90)}}
	engine.MarkAlertsSynced([]*Alert{sent})
	if engine.alerts["a"].Synced {
		t.Fatal("newer live alert was incorrectly acknowledged by an older telemetry snapshot")
	}
}

func TestMarkAlertsSyncedAcknowledgesEquivalentJSONEvidence(t *testing.T) {
	at := time.Now().UTC()
	engine := &Engine{alerts: map[string]*Alert{
		"a": {ID: "a", Type: AlertNewCommunication, Severity: "high", Message: "x", IP: "10.0.0.1", FirstSeen: at, LastSeen: at, Count: 1, Status: AlertStatusNew, Evidence: map[string]interface{}{"score": 90}, Synced: false},
	}}
	sent := &Alert{ID: "a", Type: AlertNewCommunication, Severity: "high", Message: "x", IP: "10.0.0.1", FirstSeen: at, LastSeen: at, Count: 1, Status: AlertStatusNew, Evidence: map[string]interface{}{"score": float64(90)}}
	engine.MarkAlertsSynced([]*Alert{sent})
	if !engine.alerts["a"].Synced {
		t.Fatal("equivalent serialized alert evidence should acknowledge the exact version")
	}
}
