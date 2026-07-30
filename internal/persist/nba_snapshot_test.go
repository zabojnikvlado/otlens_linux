package persist

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/nba"
)

func TestNBASnapshotsRoundTripThroughPersistence(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "nba.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.EnsureBucket(bucketMeta); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	anomalies := nba.Snapshot{Version: 1, Anomalies: []nba.Anomaly{{ID: "a", Timestamp: now, Score: 70}}, Last: map[string]time.Time{"a": now}, Telemetry: nba.Telemetry{AnomaliesTotal: 1}}
	risks := nba.RiskSnapshot{Version: 1, Items: []nba.RiskAssessment{{AnomalyID: "a", Timestamp: now, RiskScore: 80}}, Telemetry: nba.RiskTelemetry{AssessmentsTotal: 1}}
	correlation := nba.CorrelationSnapshot{Version: 1, Findings: []nba.Finding{{ID: "f", FirstSeen: now, Score: 80}}, Telemetry: nba.CorrelationTelemetry{FindingsCreated: 1}}
	if err := saveBlob(db, bucketMeta, blobKeyNBA, anomalies); err != nil {
		t.Fatal(err)
	}
	if err := saveBlob(db, bucketMeta, blobKeyNBARisk, risks); err != nil {
		t.Fatal(err)
	}
	if err := saveBlob(db, bucketMeta, blobKeyNBACorrelation, correlation); err != nil {
		t.Fatal(err)
	}
	var restoredAnomalies nba.Snapshot
	var restoredRisks nba.RiskSnapshot
	var restoredCorrelation nba.CorrelationSnapshot
	if err := loadBlob(db, bucketMeta, blobKeyNBA, &restoredAnomalies); err != nil {
		t.Fatal(err)
	}
	if err := loadBlob(db, bucketMeta, blobKeyNBARisk, &restoredRisks); err != nil {
		t.Fatal(err)
	}
	if err := loadBlob(db, bucketMeta, blobKeyNBACorrelation, &restoredCorrelation); err != nil {
		t.Fatal(err)
	}
	if len(restoredAnomalies.Anomalies) != 1 || restoredAnomalies.Last["a"].IsZero() || restoredAnomalies.Telemetry.AnomaliesTotal != 1 {
		t.Fatalf("unexpected anomaly snapshot: %#v", restoredAnomalies)
	}
	if len(restoredRisks.Items) != 1 || restoredRisks.Telemetry.AssessmentsTotal != 1 {
		t.Fatalf("unexpected risk snapshot: %#v", restoredRisks)
	}
	if len(restoredCorrelation.Findings) != 1 || restoredCorrelation.Telemetry.FindingsCreated != 1 {
		t.Fatalf("unexpected correlation snapshot: %#v", restoredCorrelation)
	}
}
