package management

import "time"

type Sensor struct {
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	SiteID                 string    `json:"site_id"`
	Status                 string    `json:"status"`
	Version                string    `json:"version"`
	Hostname               string    `json:"hostname"`
	LastSeen               time.Time `json:"last_seen"`
	CertificateFingerprint string    `json:"certificate_fingerprint,omitempty"`
}

type Site struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type RuleSet struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   int64     `json:"version"`
	Rules     []Rule    `json:"rules"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Rule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Enabled   bool   `json:"enabled"`
	Field     string `json:"field,omitempty"`
	Value     string `json:"value,omitempty"`
	Severity  string `json:"severity,omitempty"`
	AlertType string `json:"alert_type,omitempty"`
}

type SensorRegistration struct {
	ID                     string `json:"id" binding:"required"`
	Name                   string `json:"name"`
	SiteID                 string `json:"site_id"`
	Version                string `json:"version"`
	Hostname               string `json:"hostname"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
}

type Heartbeat struct {
	SensorID string                 `json:"sensor_id" binding:"required"`
	Version  string                 `json:"version"`
	Hostname string                 `json:"hostname"`
	Uptime   int64                  `json:"uptime"`
	Health   map[string]string      `json:"health"`
	Metrics  map[string]interface{} `json:"metrics"`
}

type SyncState struct {
	SensorID      string `json:"sensor_id"`
	ConfigVersion int64  `json:"config_version"`
	RulesVersion  int64  `json:"rules_version"`
}

type SyncResponse struct {
	ConfigVersion int64    `json:"config_version"`
	RulesVersion  int64    `json:"rules_version"`
	RuleSet       *RuleSet `json:"rule_set,omitempty"`
}
