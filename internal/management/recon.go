package management

import "time"

type ReconPolicy struct {
	AllowedNetworks       []string `json:"allowed_networks"`
	DeniedTargets         []string `json:"denied_targets"`
	Ports                 []int    `json:"ports"`
	PacketsPerSecond      int      `json:"packets_per_second"`
	ConcurrentTargets     int      `json:"concurrent_targets"`
	TimeoutSeconds        int      `json:"timeout_seconds"`
	RequireManualApproval bool     `json:"require_manual_approval"`
	OTProtocols           []string `json:"ot_protocols,omitempty"`
	CredentialID          string   `json:"credential_id,omitempty"`
	AuthenticatedMethods  []string `json:"authenticated_methods,omitempty"`
}

type ReconJob struct {
	ID          string        `json:"id"`
	SensorID    string        `json:"sensor_id"`
	CampaignID  string        `json:"campaign_id,omitempty"`
	Targets     []string      `json:"targets"`
	Profile     string        `json:"profile"`
	Status      string        `json:"status"`
	Policy      ReconPolicy   `json:"policy"`
	CreatedAt   time.Time     `json:"created_at"`
	StartedAt   *time.Time    `json:"started_at,omitempty"`
	CompletedAt *time.Time    `json:"completed_at,omitempty"`
	Error       string        `json:"error,omitempty"`
	Results     []ReconResult `json:"results,omitempty"`
}

type ReconCampaign struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	SensorID  string      `json:"sensor_id"`
	Targets   []string    `json:"targets"`
	Profile   string      `json:"profile"`
	Policy    ReconPolicy `json:"policy"`
	Enabled   bool        `json:"enabled"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	LastRunAt *time.Time  `json:"last_run_at,omitempty"`
}

type ReconChange struct {
	Kind     string `json:"kind"`
	Field    string `json:"field"`
	Previous string `json:"previous,omitempty"`
	Current  string `json:"current,omitempty"`
	Severity string `json:"severity"`
}

type ReconService struct {
	Port       int    `json:"port"`
	Transport  string `json:"transport"`
	Service    string `json:"service"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	Banner     string `json:"banner,omitempty"`
	TLSSubject string `json:"tls_subject,omitempty"`
	TLSIssuer  string `json:"tls_issuer,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
}

type ReconEvidence struct {
	Field      string    `json:"field"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	Confidence int       `json:"confidence"`
	ObservedAt time.Time `json:"observed_at"`
}

type ReconAuditStep struct {
	Stage      string    `json:"stage"`
	Status     string    `json:"status"`
	Detail     string    `json:"detail,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type ReconResult struct {
	Target     string            `json:"target"`
	Reachable  bool              `json:"reachable"`
	Hostname   string            `json:"hostname,omitempty"`
	Vendor     string            `json:"vendor,omitempty"`
	OS         string            `json:"os,omitempty"`
	Model      string            `json:"model,omitempty"`
	Firmware   string            `json:"firmware,omitempty"`
	Serial     string            `json:"serial,omitempty"`
	OTIdentity map[string]string `json:"ot_identity,omitempty"`
	Services   []ReconService    `json:"services,omitempty"`
	Evidence   []ReconEvidence   `json:"evidence,omitempty"`
	Audit      []ReconAuditStep  `json:"audit,omitempty"`
	Changes    []ReconChange     `json:"changes,omitempty"`
	Error      string            `json:"error,omitempty"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
}

type ReconCommand struct {
	JobID      string                 `json:"job_id"`
	Targets    []string               `json:"targets"`
	Profile    string                 `json:"profile"`
	Policy     ReconPolicy            `json:"policy"`
	Credential *ReconCredentialSecret `json:"credential,omitempty"`
}
