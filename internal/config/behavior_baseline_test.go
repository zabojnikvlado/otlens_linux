package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBehaviorBaselineConfigDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Baseline.BehaviorEnabled || config.Baseline.BucketDuration != time.Hour || config.Baseline.MaxProfiles != 100_000 || config.Baseline.MaxAssetProfiles != 100_000 {
		t.Fatalf("unexpected behavior baseline defaults: %#v", config.Baseline)
	}
	if !config.NBA.Enabled || config.NBA.MinScore != 40 || config.NBA.MaxAnomalies != 10_000 || config.NBA.Cooldown != 5*time.Minute || !config.NBA.RiskEnabled || config.NBA.MaxAssessments != 10_000 {
		t.Fatalf("unexpected NBA defaults: %#v", config.NBA)
	}
	if !config.NBA.CorrelationEnabled || config.NBA.CorrelationWindow != 15*time.Minute || config.NBA.FindingExpireAfter != 30*time.Minute ||
		config.NBA.MaxFindings != 10_000 || config.NBA.MaxAssessmentsPerFinding != 256 || config.NBA.MinFindingScore != 40 ||
		config.NBA.AlertThreshold != 70 || config.NBA.IncidentThreshold != 85 {
		t.Fatalf("unexpected correlation defaults: %#v", config.NBA)
	}
}
