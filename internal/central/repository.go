package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

type Repository struct{ db *sql.DB }

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
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sensors_last_seen_idx ON sensors(last_seen);
CREATE INDEX IF NOT EXISTS sensor_telemetry_captured_at_idx ON sensor_telemetry(captured_at);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("ensure central database schema: %w", err)
	}
	return &Repository{db: db}, nil
}
func (r *Repository) Close() error { return r.db.Close() }

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
	_, err := r.db.ExecContext(ctx, `UPDATE sensors SET status='online',version=$2,hostname=$3,last_seen=NOW() WHERE id=$1`, h.SensorID, h.Version, h.Hostname)
	return err
}
func (r *Repository) ListSensors(ctx context.Context) ([]management.Sensor, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,name,site_id,status,version,hostname,last_seen,COALESCE(certificate_fingerprint,'') FROM sensors ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.Sensor
	for rows.Next() {
		var s management.Sensor
		if err := rows.Scan(&s.ID, &s.Name, &s.SiteID, &s.Status, &s.Version, &s.Hostname, &s.LastSeen, &s.CertificateFingerprint); err != nil {
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

func (r *Repository) PutTelemetry(ctx context.Context, sensorID string, capturedAt time.Time, topologyJSON, tagsJSON []byte) error {
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO sensor_telemetry(sensor_id,captured_at,topology,tags,updated_at)
VALUES($1,$2,$3,$4,NOW()) ON CONFLICT(sensor_id) DO UPDATE SET captured_at=EXCLUDED.captured_at,topology=EXCLUDED.topology,tags=EXCLUDED.tags,updated_at=NOW()`, sensorID, capturedAt, topologyJSON, tagsJSON)
	return err
}

func (r *Repository) Telemetry(ctx context.Context) ([]management.TelemetrySnapshot, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id,captured_at,topology,tags FROM sensor_telemetry ORDER BY sensor_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.TelemetrySnapshot
	for rows.Next() {
		var x management.TelemetrySnapshot
		if err := rows.Scan(&x.SensorID, &x.CapturedAt, &x.Topology, &x.Tags); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
