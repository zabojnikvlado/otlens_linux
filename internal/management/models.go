package management

import (
	"encoding/json"
	"time"
)

type Sensor struct {
	ID                     string     `json:"id"`
	Name                   string     `json:"name"`
	SiteID                 string     `json:"site_id"`
	Status                 string     `json:"status"`
	Version                string     `json:"version"`
	Hostname               string     `json:"hostname"`
	LastSeen               time.Time  `json:"last_seen"`
	CertificateFingerprint string     `json:"certificate_fingerprint,omitempty"`
	GoVersion              string     `json:"go_version,omitempty"`
	LibpcapVersion         string     `json:"libpcap_version,omitempty"`
	GopacketVersion        string     `json:"gopacket_version,omitempty"`
	CaptureBackend         string     `json:"capture_backend,omitempty"`
	CaptureInterface       string     `json:"capture_interface,omitempty"`
	CaptureSnaplen         int32      `json:"capture_snaplen,omitempty"`
	CapturePromiscuous     bool       `json:"capture_promiscuous,omitempty"`
	LastHeartbeatAt        *time.Time `json:"last_heartbeat_at,omitempty"`
	LastSyncAttemptAt      *time.Time `json:"last_sync_attempt_at,omitempty"`
	LastSyncSuccessAt      *time.Time `json:"last_sync_success_at,omitempty"`
	LastDataReceivedAt     *time.Time `json:"last_data_received_at,omitempty"`
	SyncStatus             string     `json:"sync_status,omitempty"`
	PendingRecords         int64      `json:"pending_records,omitempty"`
	SyncFailures           int        `json:"sync_failures,omitempty"`
	LastSyncError          string     `json:"last_sync_error,omitempty"`
	SyncSequence           int64      `json:"sync_sequence,omitempty"`
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
	Versions map[string]string      `json:"versions,omitempty"`
	Capture  map[string]interface{} `json:"capture,omitempty"`
	Sync     SyncHealth             `json:"sync,omitempty"`
}

type SyncHealth struct {
	LastAttemptAt       time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt       time.Time `json:"last_success_at,omitempty"`
	LastDataSentAt      time.Time `json:"last_data_sent_at,omitempty"`
	PendingRecords      int64     `json:"pending_records,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	Sequence            int64     `json:"sequence,omitempty"`
}

type TelemetryAck struct {
	Accepted         bool      `json:"accepted"`
	BatchID          string    `json:"batch_id"`
	AcceptedSequence int64     `json:"accepted_sequence"`
	StoredAt         time.Time `json:"stored_at"`
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
	BatchID    string          `json:"batch_id,omitempty"`
	Sequence   int64           `json:"sequence,omitempty"`
	Checksum   string          `json:"checksum,omitempty"`
}

type AnalysisJob struct {
	ID               string          `json:"id"`
	SensorID         string          `json:"sensor_id"`
	Filename         string          `json:"filename"`
	SHA256           string          `json:"sha256"`
	SizeBytes        int64           `json:"size_bytes"`
	Status           string          `json:"status"`
	Protocols        []string        `json:"protocols,omitempty"`
	Packets          int             `json:"packets,omitempty"`
	AssetsDiscovered int             `json:"assets_discovered,omitempty"`
	FlowsDiscovered  int             `json:"flows_discovered,omitempty"`
	TagsDiscovered   int             `json:"tags_discovered,omitempty"`
	AlertsGenerated  int             `json:"alerts_generated,omitempty"`
	Error            string          `json:"error,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	StartedAt        *time.Time      `json:"started_at,omitempty"`
	CompletedAt      *time.Time      `json:"completed_at,omitempty"`
	Result           json.RawMessage `json:"result,omitempty"`
}

type AnalysisResult struct {
	Packets          int      `json:"packets"`
	AssetsDiscovered int      `json:"assets_discovered"`
	FlowsDiscovered  int      `json:"flows_discovered"`
	TagsDiscovered   int      `json:"tags_discovered"`
	AlertsGenerated  int      `json:"alerts_generated"`
	Protocols        []string `json:"protocols,omitempty"`
	Error            string   `json:"error,omitempty"`
}
