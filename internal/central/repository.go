package central

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

type Repository struct {
	db                *sql.DB
	siemAlertsEnabled bool
}

func OpenPostgres(dsn string) (*Repository, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	// Bootstrap the complete Central schema in dependency order. The binary must
	// be able to start against a newly-created, empty PostgreSQL database without
	// requiring the operator to run db/central_phase3.sql manually first.
	schema := `
CREATE TABLE IF NOT EXISTS sites (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS sensors (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL DEFAULT '',
 site_id TEXT REFERENCES sites(id),
 status TEXT NOT NULL DEFAULT 'offline',
 version TEXT NOT NULL DEFAULT '',
 hostname TEXT NOT NULL DEFAULT '',
 certificate_fingerprint TEXT,
 go_version TEXT NOT NULL DEFAULT '',
 libpcap_version TEXT NOT NULL DEFAULT '',
 gopacket_version TEXT NOT NULL DEFAULT '',
 capture_backend TEXT NOT NULL DEFAULT '',
 capture_interface TEXT NOT NULL DEFAULT '',
 capture_snaplen INTEGER NOT NULL DEFAULT 0,
 capture_promiscuous BOOLEAN NOT NULL DEFAULT FALSE,
 last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS rule_sets (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 version BIGINT NOT NULL DEFAULT 1,
 rules JSONB NOT NULL DEFAULT '[]'::jsonb,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS sensor_rule_sets (
 sensor_id TEXT PRIMARY KEY REFERENCES sensors(id) ON DELETE CASCADE,
 rule_set_id TEXT NOT NULL REFERENCES rule_sets(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sensor_telemetry (
 sensor_id TEXT PRIMARY KEY REFERENCES sensors(id) ON DELETE CASCADE,
 captured_at TIMESTAMPTZ NOT NULL,
 topology JSONB NOT NULL DEFAULT '{"Nodes":[],"Edges":[],"HoneypotThreshold":10}'::jsonb,
 tags JSONB NOT NULL DEFAULT '[]'::jsonb,
 tag_changes JSONB NOT NULL DEFAULT '[]'::jsonb,
 tag_events JSONB NOT NULL DEFAULT '[]'::jsonb,
 alerts JSONB NOT NULL DEFAULT '[]'::jsonb,
 baseline JSONB NOT NULL DEFAULT '{}'::jsonb,
 rules JSONB NOT NULL DEFAULT '[]'::jsonb,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS go_version TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS libpcap_version TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS gopacket_version TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_backend TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_interface TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_snaplen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_promiscuous BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS sensors_last_seen_idx ON sensors(last_seen);
CREATE INDEX IF NOT EXISTS sensor_telemetry_captured_at_idx ON sensor_telemetry(captured_at);
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS tag_changes JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS tag_events JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS alerts JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS baseline JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS rules JSONB NOT NULL DEFAULT '[]'::jsonb;
CREATE TABLE IF NOT EXISTS sensor_commands (
 id BIGSERIAL PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 command_type TEXT NOT NULL,
 target TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sensor_commands_pending ON sensor_commands(sensor_id,id) WHERE delivered_at IS NULL;
CREATE TABLE IF NOT EXISTS siem_outbox (
 id BIGSERIAL PRIMARY KEY,
 event_key TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL,
 payload JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 attempts INTEGER NOT NULL DEFAULT 0,
 last_error TEXT NOT NULL DEFAULT '',
 delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_siem_outbox_pending ON siem_outbox(next_attempt_at,id) WHERE delivered_at IS NULL;
CREATE TABLE IF NOT EXISTS analysis_jobs (
 id TEXT PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 filename TEXT NOT NULL,
 stored_path TEXT NOT NULL,
 sha256 TEXT NOT NULL,
 size_bytes BIGINT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued',
 protocols JSONB NOT NULL DEFAULT '["auto"]'::jsonb,
 packets INTEGER NOT NULL DEFAULT 0,
 assets_discovered INTEGER NOT NULL DEFAULT 0,
 flows_discovered INTEGER NOT NULL DEFAULT 0,
 tags_discovered INTEGER NOT NULL DEFAULT 0,
 alerts_generated INTEGER NOT NULL DEFAULT 0,
 result JSONB NOT NULL DEFAULT '{}'::jsonb,
 error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 started_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_sensor_status ON analysis_jobs(sensor_id,status,created_at);
CREATE TABLE IF NOT EXISTS system_backups (
 id TEXT PRIMARY KEY,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 payload JSONB NOT NULL,
 size_bytes BIGINT NOT NULL DEFAULT 0,
 sha256 TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("ensure central database schema: %w", err)
	}
	return &Repository{db: db}, nil
}
func (r *Repository) Close() error { return r.db.Close() }

func (r *Repository) ConfigureSIEM(alertsEnabled bool) {
	r.siemAlertsEnabled = alertsEnabled
}

func (r *Repository) RegisterSensor(ctx context.Context, s management.SensorRegistration) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var site interface{}
	if s.SiteID != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sites(id,name) VALUES($1,$1) ON CONFLICT(id) DO NOTHING`, s.SiteID); err != nil {
			return err
		}
		site = s.SiteID
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sensors(id,name,site_id,status,version,hostname,certificate_fingerprint,last_seen)
VALUES($1,$2,$3,'online',$4,$5,$6,NOW())
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,site_id=EXCLUDED.site_id,version=EXCLUDED.version,hostname=EXCLUDED.hostname,certificate_fingerprint=EXCLUDED.certificate_fingerprint,last_seen=NOW(),status='online'`, s.ID, s.Name, site, s.Version, s.Hostname, s.CertificateFingerprint)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (r *Repository) Heartbeat(ctx context.Context, h management.Heartbeat) error {
	status := "online"
	if captureStatus := strings.ToLower(strings.TrimSpace(h.Health["capture"])); captureStatus == "running" || captureStatus == "stopped" {
		status = captureStatus
	}
	stringValue := func(values map[string]string, key string) string {
		if values == nil {
			return ""
		}
		return values[key]
	}
	interfaceValue := func(key string) interface{} {
		if h.Capture == nil {
			return nil
		}
		return h.Capture[key]
	}
	toString := func(value interface{}) string {
		if value == nil {
			return ""
		}
		return fmt.Sprint(value)
	}
	toInt32 := func(value interface{}) int32 {
		switch typed := value.(type) {
		case float64:
			return int32(typed)
		case int:
			return int32(typed)
		case int32:
			return typed
		case int64:
			return int32(typed)
		default:
			return 0
		}
	}
	toBool := func(value interface{}) bool {
		typed, ok := value.(bool)
		return ok && typed
	}
	_, err := r.db.ExecContext(ctx, `UPDATE sensors SET
 status=$4,version=$2,hostname=$3,go_version=$5,libpcap_version=$6,gopacket_version=$7,
 capture_backend=$8,capture_interface=$9,capture_snaplen=$10,capture_promiscuous=$11,last_seen=NOW()
 WHERE id=$1`, h.SensorID, h.Version, h.Hostname, status,
		stringValue(h.Versions, "go"), stringValue(h.Versions, "libpcap"), stringValue(h.Versions, "gopacket"),
		toString(interfaceValue("backend")), toString(interfaceValue("interface")), toInt32(interfaceValue("snaplen")), toBool(interfaceValue("promiscuous")))
	return err
}
func (r *Repository) ListSensors(ctx context.Context) ([]management.Sensor, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,name,COALESCE(site_id,''),status,version,hostname,last_seen,COALESCE(certificate_fingerprint,''),
COALESCE(go_version,''),COALESCE(libpcap_version,''),COALESCE(gopacket_version,''),COALESCE(capture_backend,''),
COALESCE(capture_interface,''),COALESCE(capture_snaplen,0),COALESCE(capture_promiscuous,FALSE) FROM sensors ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.Sensor
	for rows.Next() {
		var s management.Sensor
		if err := rows.Scan(&s.ID, &s.Name, &s.SiteID, &s.Status, &s.Version, &s.Hostname, &s.LastSeen, &s.CertificateFingerprint,
			&s.GoVersion, &s.LibpcapVersion, &s.GopacketVersion, &s.CaptureBackend, &s.CaptureInterface, &s.CaptureSnaplen, &s.CapturePromiscuous); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func (r *Repository) PutRuleSet(ctx context.Context, rs management.RuleSet) error {
	data, err := json.Marshal(rs.Rules)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO rule_sets(id,name,version,rules,updated_at) VALUES($1,$2,1,$3,NOW()) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,version=rule_sets.version+1,rules=EXCLUDED.rules,updated_at=NOW()`, rs.ID, rs.Name, data)
	return err
}
func (r *Repository) GetRuleSet(ctx context.Context, id string) (*management.RuleSet, error) {
	var rs management.RuleSet
	var data []byte
	err := r.db.QueryRowContext(ctx, `SELECT id,name,version,rules,updated_at FROM rule_sets WHERE id=$1`, id).Scan(&rs.ID, &rs.Name, &rs.Version, &data, &rs.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &rs.Rules); err != nil {
		return nil, err
	}
	return &rs, nil
}
func (r *Repository) AssignedRuleSet(ctx context.Context, sensorID string) (*management.RuleSet, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `SELECT rule_set_id FROM sensor_rule_sets WHERE sensor_id=$1`, sensorID).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetRuleSet(ctx, id)
}
func (r *Repository) AssignRuleSet(ctx context.Context, sensorID, ruleSetID string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO sensor_rule_sets(sensor_id,rule_set_id) VALUES($1,$2) ON CONFLICT(sensor_id) DO UPDATE SET rule_set_id=EXCLUDED.rule_set_id`, sensorID, ruleSetID)
	return err
}
func (r *Repository) MarkOffline(ctx context.Context, olderThan time.Duration) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sensors SET status='offline' WHERE last_seen < NOW() - ($1 * INTERVAL '1 second')`, int64(olderThan/time.Second))
	return err
}

func (r *Repository) PutTelemetry(ctx context.Context, x management.TelemetrySnapshot) error {
	if x.CapturedAt.IsZero() {
		x.CapturedAt = time.Now().UTC()
	}
	defaults := func(v json.RawMessage, fallback string) json.RawMessage {
		if len(v) == 0 {
			return json.RawMessage(fallback)
		}
		return v
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO sensor_telemetry(sensor_id,captured_at,topology,tags,tag_changes,tag_events,alerts,baseline,rules,updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW()) ON CONFLICT(sensor_id) DO UPDATE SET captured_at=EXCLUDED.captured_at,topology=EXCLUDED.topology,tags=EXCLUDED.tags,tag_changes=EXCLUDED.tag_changes,tag_events=EXCLUDED.tag_events,alerts=EXCLUDED.alerts,baseline=EXCLUDED.baseline,rules=EXCLUDED.rules,updated_at=NOW()`, x.SensorID, x.CapturedAt, x.Topology, x.Tags, defaults(x.TagChanges, "[]"), defaults(x.TagEvents, "[]"), defaults(x.Alerts, "[]"), defaults(x.Baseline, "{}"), defaults(x.Rules, "[]"))
	if err != nil {
		return err
	}
	var alerts []map[string]interface{}
	if r.siemAlertsEnabled && len(x.Alerts) > 0 && json.Unmarshal(x.Alerts, &alerts) == nil {
		for _, alert := range alerts {
			id := firstString(alert, "ID", "id")
			if id == "" {
				continue
			}
			count := fmt.Sprint(firstValue(alert, "Count", "count"))
			lastSeen := fmt.Sprint(firstValue(alert, "LastSeen", "last_seen"))
			status := fmt.Sprint(firstValue(alert, "Status", "status"))
			eventKey := fmt.Sprintf("alert:%s:%s:%s:%s:%s", x.SensorID, id, count, lastSeen, status)
			envelope := map[string]interface{}{
				"source":     "otlens-central",
				"kind":       "alert",
				"event_time": x.CapturedAt,
				"sensor_id":  x.SensorID,
				"alert":      alert,
			}
			payload, marshalErr := json.Marshal(envelope)
			if marshalErr != nil {
				return marshalErr
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO siem_outbox(event_key,kind,payload) VALUES($1,'alert',$2) ON CONFLICT(event_key) DO NOTHING`, eventKey, payload); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func firstValue(m map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return ""
}

func firstString(m map[string]interface{}, keys ...string) string {
	return fmt.Sprint(firstValue(m, keys...))
}

func (r *Repository) Telemetry(ctx context.Context) ([]management.TelemetrySnapshot, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id,captured_at,topology,tags,tag_changes,tag_events,alerts,baseline,rules FROM sensor_telemetry ORDER BY sensor_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.TelemetrySnapshot
	for rows.Next() {
		var x management.TelemetrySnapshot
		if err := rows.Scan(&x.SensorID, &x.CapturedAt, &x.Topology, &x.Tags, &x.TagChanges, &x.TagEvents, &x.Alerts, &x.Baseline, &x.Rules); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (r *Repository) QueueCommands(ctx context.Context, sensorID, typ string, targets []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, target := range targets {
		if target == "" {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO sensor_commands(sensor_id,command_type,target) VALUES($1,$2,$3)`, sensorID, typ, target); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (r *Repository) PopCommands(ctx context.Context, sensorID string) ([]management.Command, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,command_type,target FROM sensor_commands WHERE sensor_id=$1 AND delivered_at IS NULL ORDER BY id FOR UPDATE`, sensorID)
	if err != nil {
		return nil, err
	}
	var out []management.Command
	var ids []int64
	for rows.Next() {
		var c management.Command
		if err = rows.Scan(&c.ID, &c.Type, &c.Target); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
		ids = append(ids, c.ID)
	}
	rows.Close()
	for _, id := range ids {
		if _, err = tx.ExecContext(ctx, `UPDATE sensor_commands SET delivered_at=NOW() WHERE id=$1`, id); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

type SIEMOutboxEvent struct {
	ID       int64
	Kind     string
	Payload  json.RawMessage
	Attempts int
}

func (r *Repository) EnqueueSIEM(ctx context.Context, eventKey, kind string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO siem_outbox(event_key,kind,payload) VALUES($1,$2,$3) ON CONFLICT(event_key) DO NOTHING`, eventKey, kind, data)
	return err
}

func (r *Repository) PendingSIEM(ctx context.Context, limit, maxAttempts int) ([]SIEMOutboxEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id,kind,payload,attempts FROM siem_outbox WHERE delivered_at IS NULL AND next_attempt_at <= NOW()`
	args := []interface{}{}
	if maxAttempts > 0 {
		query += ` AND attempts < $1`
		args = append(args, maxAttempts)
	}
	query += ` ORDER BY id LIMIT $` + fmt.Sprint(len(args)+1)
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SIEMOutboxEvent
	for rows.Next() {
		var e SIEMOutboxEvent
		if err := rows.Scan(&e.ID, &e.Kind, &e.Payload, &e.Attempts); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *Repository) MarkSIEMDelivered(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE siem_outbox SET delivered_at=NOW(),last_error='' WHERE id=$1`, id)
	return err
}

func (r *Repository) MarkSIEMFailed(ctx context.Context, id int64, retryAfter time.Duration, message string) error {
	if retryAfter <= 0 {
		retryAfter = 15 * time.Second
	}
	_, err := r.db.ExecContext(ctx, `UPDATE siem_outbox SET attempts=attempts+1,last_error=$2,next_attempt_at=NOW()+($3*INTERVAL '1 second') WHERE id=$1`, id, message, int64(retryAfter/time.Second))
	return err
}

func (r *Repository) CreateAnalysisJob(ctx context.Context, job management.AnalysisJob, storedPath string) error {
	protocols, _ := json.Marshal(job.Protocols)
	_, err := r.db.ExecContext(ctx, `INSERT INTO analysis_jobs(id,sensor_id,filename,stored_path,sha256,size_bytes,status,protocols) VALUES($1,$2,$3,$4,$5,$6,'queued',$7)`, job.ID, job.SensorID, job.Filename, storedPath, job.SHA256, job.SizeBytes, protocols)
	return err
}

func (r *Repository) ListAnalysisJobs(ctx context.Context) ([]management.AnalysisJob, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,sensor_id,filename,sha256,size_bytes,status,protocols,packets,assets_discovered,flows_discovered,tags_discovered,alerts_generated,error,created_at,started_at,completed_at,result FROM analysis_jobs ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []management.AnalysisJob{}
	for rows.Next() {
		var j management.AnalysisJob
		var protocols, result []byte
		if err := rows.Scan(&j.ID, &j.SensorID, &j.Filename, &j.SHA256, &j.SizeBytes, &j.Status, &protocols, &j.Packets, &j.AssetsDiscovered, &j.FlowsDiscovered, &j.TagsDiscovered, &j.AlertsGenerated, &j.Error, &j.CreatedAt, &j.StartedAt, &j.CompletedAt, &result); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(protocols, &j.Protocols)
		j.Result = result
		out = append(out, j)
	}
	return out, rows.Err()
}

func (r *Repository) ClaimAnalysisJob(ctx context.Context, sensorID string) (*management.AnalysisJob, string, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	var j management.AnalysisJob
	var protocols []byte
	var path string
	err = tx.QueryRowContext(ctx, `SELECT id,sensor_id,filename,stored_path,sha256,size_bytes,protocols,created_at FROM analysis_jobs WHERE sensor_id=$1 AND status='queued' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`, sensorID).Scan(&j.ID, &j.SensorID, &j.Filename, &path, &j.SHA256, &j.SizeBytes, &protocols, &j.CreatedAt)
	if err != nil {
		return nil, "", err
	}
	_ = json.Unmarshal(protocols, &j.Protocols)
	now := time.Now().UTC()
	j.Status = "running"
	j.StartedAt = &now
	if _, err = tx.ExecContext(ctx, `UPDATE analysis_jobs SET status='running',started_at=NOW() WHERE id=$1`, j.ID); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return &j, path, nil
}

func (r *Repository) AnalysisJobPath(ctx context.Context, id, sensorID string) (string, string, error) {
	var path, name string
	err := r.db.QueryRowContext(ctx, `SELECT stored_path,filename FROM analysis_jobs WHERE id=$1 AND sensor_id=$2`, id, sensorID).Scan(&path, &name)
	return path, name, err
}

func (r *Repository) FinishAnalysisJob(ctx context.Context, id, sensorID string, result management.AnalysisResult) error {
	status := "completed"
	if result.Error != "" {
		status = "failed"
	}
	data, _ := json.Marshal(result)
	_, err := r.db.ExecContext(ctx, `UPDATE analysis_jobs SET status=$3,packets=$4,assets_discovered=$5,flows_discovered=$6,tags_discovered=$7,alerts_generated=$8,result=$9,error=$10,completed_at=NOW() WHERE id=$1 AND sensor_id=$2`, id, sensorID, status, result.Packets, result.AssetsDiscovered, result.FlowsDiscovered, result.TagsDiscovered, result.AlertsGenerated, data, result.Error)
	return err
}

func (r *Repository) DeleteAnalysisJob(ctx context.Context, id string) (string, error) {
	var path string
	err := r.db.QueryRowContext(ctx, `DELETE FROM analysis_jobs WHERE id=$1 RETURNING stored_path`, id).Scan(&path)
	return path, err
}

type BackupRecord struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

func (r *Repository) ResetCentral(ctx context.Context, operation string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	switch operation {
	case "telemetry", "database":
		// Telemetry reset must never remove configuration, rules, sensors,
		// sites, pending management commands, SIEM data or backups.
		_, err = tx.ExecContext(ctx, `TRUNCATE sensor_telemetry RESTART IDENTITY`)
	case "alerts":
		_, err = tx.ExecContext(ctx, `UPDATE sensor_telemetry SET alerts='[]'::jsonb, updated_at=NOW()`)
	case "siem":
		_, err = tx.ExecContext(ctx, `TRUNCATE siem_outbox RESTART IDENTITY`)
	case "analysis":
		_, err = tx.ExecContext(ctx, `TRUNCATE analysis_jobs RESTART IDENTITY`)
	case "rules":
		// Central rule assignments are configuration. This explicit reset is
		// intentionally separate from telemetry/database reset.
		_, err = tx.ExecContext(ctx, `TRUNCATE sensor_rule_sets, rule_sets CASCADE`)
	case "factory":
		_, err = tx.ExecContext(ctx, `TRUNCATE sensor_telemetry, sensor_commands, analysis_jobs, siem_outbox, sensor_rule_sets, rule_sets, sensors, sites RESTART IDENTITY CASCADE`)
	default:
		return fmt.Errorf("unsupported central reset operation %q", operation)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) CreateCentralBackup(ctx context.Context, id, name string) (BackupRecord, error) {
	payload := map[string]json.RawMessage{}
	queries := map[string]string{
		"sites":            `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM sites ORDER BY id) t`,
		"sensors":          `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM sensors ORDER BY id) t`,
		"rule_sets":        `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM rule_sets ORDER BY id) t`,
		"sensor_rule_sets": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM sensor_rule_sets ORDER BY sensor_id) t`,
		"sensor_telemetry": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM sensor_telemetry ORDER BY sensor_id) t`,
	}
	for key, q := range queries {
		var raw []byte
		if err := r.db.QueryRowContext(ctx, q).Scan(&raw); err != nil {
			return BackupRecord{}, err
		}
		payload[key] = raw
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return BackupRecord{}, err
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(data))
	if name == "" {
		name = "central-" + time.Now().UTC().Format("20060102-150405")
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO system_backups(id,kind,name,payload,size_bytes,sha256) VALUES($1,'central',$2,$3,$4,$5)`, id, name, data, len(data), sum)
	if err != nil {
		return BackupRecord{}, err
	}
	return BackupRecord{ID: id, Kind: "central", Name: name, SizeBytes: int64(len(data)), SHA256: sum, CreatedAt: time.Now().UTC()}, nil
}

func (r *Repository) ListBackups(ctx context.Context) ([]BackupRecord, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,kind,name,size_bytes,sha256,created_at FROM system_backups ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackupRecord
	for rows.Next() {
		var b BackupRecord
		if err := rows.Scan(&b.ID, &b.Kind, &b.Name, &b.SizeBytes, &b.SHA256, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (r *Repository) DeleteBackup(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM system_backups WHERE id=$1`, id)
	return err
}
func (r *Repository) BackupPayload(ctx context.Context, id string) ([]byte, string, error) {
	var b []byte
	var name string
	err := r.db.QueryRowContext(ctx, `SELECT payload,name FROM system_backups WHERE id=$1`, id).Scan(&b, &name)
	return b, name, err
}
