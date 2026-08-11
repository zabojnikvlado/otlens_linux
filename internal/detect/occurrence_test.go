package detect

import (
	"testing"
	"time"
)

func TestRecordEpisodeAlertLockedCountsEpisodesNotPackets(t *testing.T) {
	e := &Engine{}
	start := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	alert := &Alert{ID: "recon|host", Status: AlertStatusNew, Synced: true}

	if !e.recordEpisodeAlertLocked(alert, start, 5*time.Minute) {
		t.Fatal("first occurrence was rejected")
	}
	if alert.Count != 1 || !alert.LastSeen.Equal(start) || alert.Synced {
		t.Fatalf("unexpected first episode state: %+v", alert)
	}

	alert.Synced = true
	if !e.recordEpisodeAlertLocked(alert, start.Add(30*time.Second), 5*time.Minute) {
		t.Fatal("continuous occurrence was rejected")
	}
	if alert.Count != 1 {
		t.Fatalf("continuous traffic incremented episode count: %d", alert.Count)
	}
	if !alert.Synced {
		t.Fatal("continuous traffic dirtied telemetry before freshness interval")
	}

	if !e.recordEpisodeAlertLocked(alert, start.Add(6*time.Minute), 5*time.Minute) {
		t.Fatal("second episode was rejected")
	}
	if alert.Count != 2 {
		t.Fatalf("new episode count = %d, want 2", alert.Count)
	}
}

func TestRecordEpisodeAlertLockedRespectsReviewVerdict(t *testing.T) {
	e := &Engine{}
	start := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	alert := &Alert{ID: "x", Status: AlertStatusConfirmed, Count: 1, LastSeen: start}

	if !e.recordEpisodeAlertLocked(alert, start.Add(time.Minute), 5*time.Minute) {
		t.Fatal("confirmed continuous condition should still update last seen")
	}
	if alert.Status != AlertStatusConfirmed || alert.Count != 1 {
		t.Fatalf("continuous confirmed condition reopened: status=%s count=%d", alert.Status, alert.Count)
	}

	if !e.recordEpisodeAlertLocked(alert, start.Add(7*time.Minute), 5*time.Minute) {
		t.Fatal("new episode after quiet gap rejected")
	}
	if alert.Status != AlertStatusNew || alert.Count != 2 {
		t.Fatalf("new episode did not reopen confirmed alert: status=%s count=%d", alert.Status, alert.Count)
	}

	approved := &Alert{ID: "approved", Status: AlertStatusApproved, Count: 4, LastSeen: start}
	if e.recordEpisodeAlertLocked(approved, start.Add(10*time.Minute), 5*time.Minute) {
		t.Fatal("approved condition should be suppressed")
	}
	if approved.Count != 4 || !approved.LastSeen.Equal(start) {
		t.Fatalf("approved alert was mutated: %+v", approved)
	}
}

func TestRestoreAlertsOnlyTrustsApprovedNewCommunication(t *testing.T) {
	e := &Engine{
		alerts:          make(map[string]*Alert),
		learnedPatterns: map[string]bool{"pending": true, "approved": true},
	}
	e.RestoreAlerts([]*Alert{
		{ID: "pending", Type: AlertNewCommunication, Status: AlertStatusNew},
		{ID: "approved", Type: AlertNewCommunication, Status: AlertStatusApproved},
	})
	if e.learnedPatterns["pending"] {
		t.Fatal("unreviewed post-learning communication was silently trusted")
	}
	if !e.learnedPatterns["approved"] {
		t.Fatal("approved communication was not restored as trusted")
	}
}

func TestResetLearningStateClearsBehaviorCaches(t *testing.T) {
	e := &Engine{
		baselineEnabled: true,
		baselineMode:    BaselineModeMonitoring,
		learningStarted: time.Now(),
		learnedPatterns: map[string]bool{"x": true},
		learnedAssets:   map[string]bool{"m": true},
		knownMAC:        map[string]string{"10.0.0.1": "aa:bb:cc:dd:ee:ff"},
		candidateMAC:    map[string]string{"10.0.0.1": "11:22:33:44:55:66"},
		candidateCount:  map[string]int{"10.0.0.1": 2},
		hostScanSeen:    map[string]map[string]time.Time{"10.0.0.1": {"10.0.0.2": time.Now()}},
		portScanSeen:    make(map[string]map[string]map[int]time.Time),
		beaconHistory:   map[string][]time.Time{"x": {time.Now()}},
		beaconLastTouch: map[string]time.Time{"x": time.Now()},
		ipVLAN:          map[string]uint16{"10.0.0.1": 10},
		c2NXDomains:     map[string][]time.Time{"x": {time.Now()}},
		c2Subdomains:    map[string]map[string]time.Time{"x": {"a": time.Now()}},
		otValues:        map[string]*otValueState{"x": {}},
	}
	e.lateralData.fanout = map[string]map[string]time.Time{"x": {"y": time.Now()}}
	e.lateralData.transfers = map[string]*trafficWindow{"x": {Bytes: 1}}
	e.lateralData.inboundAdmin = map[string]map[string]time.Time{"x": {"y": time.Now()}}

	e.ResetLearningState()
	if e.baselineMode != "" || !e.learningStarted.IsZero() || len(e.learnedPatterns) != 0 || len(e.learnedAssets) != 0 {
		t.Fatalf("baseline state survived reset: %+v", e.BaselineStatus())
	}
	if len(e.knownMAC) != 0 || len(e.hostScanSeen) != 0 || len(e.beaconHistory) != 0 || len(e.ipVLAN) != 0 || len(e.c2NXDomains) != 0 || len(e.otValues) != 0 {
		t.Fatal("one or more detector learning caches survived reset")
	}
}

func TestResetLearningDoesNotEnableDisabledBaseline(t *testing.T) {
	e := &Engine{
		baselineEnabled: false,
		baselineMode:    BaselineModeMonitoring,
		learnedPatterns: map[string]bool{"x": true},
		learnedAssets:   map[string]bool{"m": true},
		knownMAC:        map[string]string{},
		candidateMAC:    map[string]string{},
		candidateCount:  map[string]int{},
		hostScanSeen:    map[string]map[string]time.Time{},
		portScanSeen:    map[string]map[string]map[int]time.Time{},
		beaconHistory:   map[string][]time.Time{},
		beaconLastTouch: map[string]time.Time{},
		ipVLAN:          map[string]uint16{},
		c2NXDomains:     map[string][]time.Time{},
		c2Subdomains:    map[string]map[string]time.Time{},
		otValues:        map[string]*otValueState{},
	}
	e.ResetLearningState()
	if e.baselineMode != BaselineModeMonitoring {
		t.Fatalf("disabled baseline was accidentally re-enabled by reset: mode=%q", e.baselineMode)
	}
	if e.behaviorDetectionsSuppressed() {
		t.Fatal("behavior detectors were suppressed even though baseline learning is disabled")
	}
}
