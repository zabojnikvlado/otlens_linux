package management

import (
	"encoding/json"
	"time"
)

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

type RuleCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type RuleGroup struct {
	Operator   string          `json:"operator"`
	Conditions []RuleCondition `json:"conditions"`
}

type RuleAction struct {
	Type string `json:"type"`
}

type RuleSuppression struct {
	Mode            string `json:"mode"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
}

type Rule struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description,omitempty"`
	Category      string          `json:"category,omitempty"`
	Kind          string          `json:"kind"`
	Enabled       bool            `json:"enabled"`
	Severity      string          `json:"severity,omitempty"`
	Priority      int             `json:"priority,omitempty"`
	Simulation    bool            `json:"simulation,omitempty"`
	Version       int             `json:"version,omitempty"`
	Groups        []RuleGroup     `json:"groups,omitempty"`
	GroupOperator string          `json:"group_operator,omitempty"`
	Actions       []RuleAction    `json:"actions,omitempty"`
	Suppression   RuleSuppression `json:"suppression,omitempty"`
	Schedule      string          `json:"schedule,omitempty"`
	Field         string          `json:"field,omitempty"`
	Value         string          `json:"value,omitempty"`
	AlertType     string          `json:"alert_type,omitempty"`
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

type Command struct {
	ID     int64  `json:"id"`
	Type   string `json:"type"`
	Target string `json:"target"`
}

type SyncResponse struct {
	ConfigVersion int64     `json:"config_version"`
	RulesVersion  int64     `json:"rules_version"`
	RuleSet       *RuleSet  `json:"rule_set,omitempty"`
	Commands      []Command `json:"commands,omitempty"`
}

// TelemetrySnapshot is the periodically uploaded sensor view used by the
// Central Topology, Assets and OT Tags tabs. Sensors remain the source of
// truth for passive discovery; Central only aggregates and persists it.
type TelemetrySnapshot struct {
	SensorID   string          `json:"sensor_id"`
	CapturedAt time.Time       `json:"captured_at"`
	Topology   json.RawMessage `json:"topology"`
	Tags       json.RawMessage `json:"tags"`
	TagChanges json.RawMessage `json:"tag_changes,omitempty"`
	TagEvents  json.RawMessage `json:"tag_events,omitempty"`
	Alerts     json.RawMessage `json:"alerts,omitempty"`
	Baseline   json.RawMessage `json:"baseline,omitempty"`
	Rules      json.RawMessage `json:"rules,omitempty"`
}
