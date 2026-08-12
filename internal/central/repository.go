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
	"github.com/zabojnikvlado/otlens_linux/internal/topology"

	"errors"
)

type Repository struct {
	db                *sql.DB
	siemAlertsEnabled bool
	siemAuditEnabled  bool
	siemSource        string
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
CREATE TABLE IF NOT EXISTS schema_migrations (
 version BIGINT PRIMARY KEY,
 name TEXT NOT NULL,
 applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS central_runtime_state (
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
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
 auth_token_hash TEXT NOT NULL DEFAULT '',
 auth_token_rotated_at TIMESTAMPTZ,
 go_version TEXT NOT NULL DEFAULT '',
 libpcap_version TEXT NOT NULL DEFAULT '',
 gopacket_version TEXT NOT NULL DEFAULT '',
 capture_backend TEXT NOT NULL DEFAULT '',
 capture_interface TEXT NOT NULL DEFAULT '',
 capture_snaplen INTEGER NOT NULL DEFAULT 0,
 capture_promiscuous BOOLEAN NOT NULL DEFAULT FALSE,
 last_heartbeat_at TIMESTAMPTZ,
 last_sync_attempt_at TIMESTAMPTZ,
 last_sync_success_at TIMESTAMPTZ,
 last_data_received_at TIMESTAMPTZ,
 sync_status TEXT NOT NULL DEFAULT 'unknown',
 pending_records BIGINT NOT NULL DEFAULT 0,
 sync_failures INTEGER NOT NULL DEFAULT 0,
 last_sync_error TEXT NOT NULL DEFAULT '',
 sync_sequence BIGINT NOT NULL DEFAULT 0,
 last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS rule_sets (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 version BIGINT NOT NULL DEFAULT 1,
 rules JSONB NOT NULL DEFAULT '[]'::jsonb,
 dns_observations JSONB NOT NULL DEFAULT '[]'::jsonb,
 smb_observations JSONB NOT NULL DEFAULT '[]'::jsonb,
 batch_id TEXT NOT NULL DEFAULT '',
 sequence BIGINT NOT NULL DEFAULT 0,
 checksum TEXT NOT NULL DEFAULT '',
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
 udp_conversations JSONB NOT NULL DEFAULT '[]'::jsonb,
 udp_telemetry JSONB NOT NULL DEFAULT '{}'::jsonb,
 udp_protocol_exchanges JSONB NOT NULL DEFAULT '[]'::jsonb,
 batch_id TEXT NOT NULL DEFAULT '',
 sequence BIGINT NOT NULL DEFAULT 0,
 checksum TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS go_version TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS libpcap_version TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS gopacket_version TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_backend TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_interface TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_snaplen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_promiscuous BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS last_sync_attempt_at TIMESTAMPTZ;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS last_sync_success_at TIMESTAMPTZ;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS last_data_received_at TIMESTAMPTZ;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS sync_status TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS pending_records BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS sync_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS last_sync_error TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS sync_sequence BIGINT NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS sensor_metrics (
 id BIGSERIAL PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 uptime_seconds BIGINT NOT NULL DEFAULT 0,
 health JSONB NOT NULL DEFAULT '{}'::jsonb,
 metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
 versions JSONB NOT NULL DEFAULT '{}'::jsonb,
 capture JSONB NOT NULL DEFAULT '{}'::jsonb,
 sync JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_sensor_metrics_sensor_time ON sensor_metrics(sensor_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS sensors_last_seen_idx ON sensors(last_seen);
CREATE TABLE IF NOT EXISTS protocol_observations (
 id BIGSERIAL PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 observed_at TIMESTAMPTZ NOT NULL,
 protocol TEXT NOT NULL,
 transport TEXT NOT NULL DEFAULT '',
 src_ip TEXT NOT NULL DEFAULT '', dst_ip TEXT NOT NULL DEFAULT '',
 src_port INTEGER NOT NULL DEFAULT 0, dst_port INTEGER NOT NULL DEFAULT 0,
 operation TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '', resource TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '',
 encrypted BOOLEAN NOT NULL DEFAULT FALSE, from_analysis BOOLEAN NOT NULL DEFAULT FALSE,
 conversation_id TEXT NOT NULL DEFAULT '', flow_id TEXT NOT NULL DEFAULT '', direction TEXT NOT NULL DEFAULT '', rtt_millis DOUBLE PRECISION NOT NULL DEFAULT 0,
 attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
 UNIQUE(sensor_id,observed_at,protocol,src_ip,dst_ip,src_port,dst_port,operation,summary)
);
ALTER TABLE protocol_observations ADD COLUMN IF NOT EXISTS conversation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE protocol_observations ADD COLUMN IF NOT EXISTS flow_id TEXT NOT NULL DEFAULT '';
ALTER TABLE protocol_observations ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT '';
ALTER TABLE protocol_observations ADD COLUMN IF NOT EXISTS rtt_millis DOUBLE PRECISION NOT NULL DEFAULT 0;
DO $$
DECLARE legacy_unique TEXT;
BEGIN
 SELECT conname INTO legacy_unique
 FROM pg_constraint
 WHERE conrelid='protocol_observations'::regclass AND contype='u'
   AND pg_get_constraintdef(oid) LIKE '%sensor_id%observed_at%protocol%src_ip%dst_ip%src_port%dst_port%operation%summary%'
 LIMIT 1;
 IF legacy_unique IS NOT NULL THEN
  EXECUTE format('ALTER TABLE protocol_observations DROP CONSTRAINT %I', legacy_unique);
 END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_protocol_observations_event_unique ON protocol_observations(sensor_id,observed_at,protocol,src_ip,dst_ip,src_port,dst_port,operation,conversation_id,flow_id,direction,summary);
CREATE INDEX IF NOT EXISTS protocol_observations_sensor_time_idx ON protocol_observations(sensor_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS protocol_observations_protocol_time_idx ON protocol_observations(protocol, observed_at DESC);
CREATE INDEX IF NOT EXISTS sensor_telemetry_captured_at_idx ON sensor_telemetry(captured_at);
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS tag_changes JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS tag_events JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS alerts JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS baseline JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS rules JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS dns_observations JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS smb_observations JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS udp_conversations JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS udp_telemetry JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS udp_protocol_exchanges JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS batch_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS sequence BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS checksum TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS reconnaissance_credentials (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 type TEXT NOT NULL,
 username TEXT NOT NULL DEFAULT '',
 encrypted_secret BYTEA NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS reconnaissance_campaigns (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 profile TEXT NOT NULL DEFAULT 'safe-discovery',
 targets JSONB NOT NULL DEFAULT '[]'::jsonb,
 policy JSONB NOT NULL DEFAULT '{}'::jsonb,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 last_run_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS reconnaissance_jobs (
 id TEXT PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 profile TEXT NOT NULL DEFAULT 'safe-discovery',
 targets JSONB NOT NULL DEFAULT '[]'::jsonb,
 policy JSONB NOT NULL DEFAULT '{}'::jsonb,
 status TEXT NOT NULL DEFAULT 'queued',
 error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 started_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ
);
ALTER TABLE reconnaissance_jobs ADD COLUMN IF NOT EXISTS campaign_id TEXT REFERENCES reconnaissance_campaigns(id) ON DELETE SET NULL;
CREATE TABLE IF NOT EXISTS asset_recon_history (
 id BIGSERIAL PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_identity TEXT NOT NULL DEFAULT '',
 ip TEXT NOT NULL,
 job_id TEXT NOT NULL REFERENCES reconnaissance_jobs(id) ON DELETE CASCADE,
 result JSONB NOT NULL,
 changes JSONB NOT NULL DEFAULT '[]'::jsonb,
 observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_recon_history_asset ON asset_recon_history(sensor_id,ip,observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_recon_history_identity ON asset_recon_history(sensor_id,asset_identity,observed_at DESC);
CREATE TABLE IF NOT EXISTS asset_recon_profile (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_identity TEXT NOT NULL DEFAULT '',
 ip TEXT NOT NULL,
 hostname TEXT NOT NULL DEFAULT '',
 vendor TEXT NOT NULL DEFAULT '',
 operating_system TEXT NOT NULL DEFAULT '',
 model TEXT NOT NULL DEFAULT '',
 firmware TEXT NOT NULL DEFAULT '',
 serial TEXT NOT NULL DEFAULT '',
 ot_identity JSONB NOT NULL DEFAULT '{}'::jsonb,
 services JSONB NOT NULL DEFAULT '[]'::jsonb,
 evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
 last_profiled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(sensor_id,asset_identity)
);
ALTER TABLE asset_recon_profile ADD COLUMN IF NOT EXISTS model TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_recon_profile ADD COLUMN IF NOT EXISTS firmware TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_recon_profile ADD COLUMN IF NOT EXISTS serial TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_recon_profile ADD COLUMN IF NOT EXISTS ot_identity JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE asset_recon_profile ADD COLUMN IF NOT EXISTS asset_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_recon_history ADD COLUMN IF NOT EXISTS asset_identity TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_asset_recon_profile_ip ON asset_recon_profile(sensor_id,ip);
CREATE INDEX IF NOT EXISTS idx_asset_recon_history_identity ON asset_recon_history(sensor_id,asset_identity,observed_at DESC);
CREATE TABLE IF NOT EXISTS reconnaissance_results (
 id BIGSERIAL PRIMARY KEY,
 job_id TEXT NOT NULL REFERENCES reconnaissance_jobs(id) ON DELETE CASCADE,
 target TEXT NOT NULL,
 result JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recon_jobs_created ON reconnaissance_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_recon_results_job ON reconnaissance_results(job_id);
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
CREATE TABLE IF NOT EXISTS roles (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 built_in BOOLEAN NOT NULL DEFAULT FALSE,
 permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role_id TEXT NOT NULL REFERENCES roles(id),
 display_name TEXT NOT NULL DEFAULT '',
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 protected BOOLEAN NOT NULL DEFAULT FALSE,
 must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
 password_expires_at TIMESTAMPTZ,
 password_validity_days INTEGER,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 last_login_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 expires_at TIMESTAMPTZ NOT NULL,
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 user_agent TEXT NOT NULL DEFAULT '',
 ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_validity_days INTEGER;
ALTER TABLE users ADD COLUMN IF NOT EXISTS protected BOOLEAN NOT NULL DEFAULT FALSE;

-- Built-in authorization rows are control-plane invariants, not resettable
-- application data.  Guard them at the database layer as well as in the API:
-- this prevents an accidental DELETE or a future TRUNCATE ... CASCADE from
-- silently removing the last administrator or the canonical built-in roles.
CREATE OR REPLACE FUNCTION otlens_guard_auth_defaults_delete()
RETURNS trigger AS $$
BEGIN
 IF TG_TABLE_NAME = 'roles' AND OLD.id IN ('admin','analyst','view') THEN
  RAISE EXCEPTION 'OTLens built-in role % cannot be deleted', OLD.id USING ERRCODE = '55000';
 END IF;
 IF TG_TABLE_NAME = 'users' AND OLD.protected THEN
  RAISE EXCEPTION 'OTLens protected administrator account cannot be deleted' USING ERRCODE = '55000';
 END IF;
 RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS otlens_guard_builtin_roles_delete ON roles;
CREATE TRIGGER otlens_guard_builtin_roles_delete
BEFORE DELETE ON roles
FOR EACH ROW EXECUTE FUNCTION otlens_guard_auth_defaults_delete();

DROP TRIGGER IF EXISTS otlens_guard_protected_users_delete ON users;
CREATE TRIGGER otlens_guard_protected_users_delete
BEFORE DELETE ON users
FOR EACH ROW EXECUTE FUNCTION otlens_guard_auth_defaults_delete();

CREATE OR REPLACE FUNCTION otlens_guard_auth_defaults_truncate()
RETURNS trigger AS $$
BEGIN
 RAISE EXCEPTION 'OTLens roles/users tables are protected from TRUNCATE' USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS otlens_guard_roles_truncate ON roles;
CREATE TRIGGER otlens_guard_roles_truncate
BEFORE TRUNCATE ON roles
FOR EACH STATEMENT EXECUTE FUNCTION otlens_guard_auth_defaults_truncate();

DROP TRIGGER IF EXISTS otlens_guard_users_truncate ON users;
CREATE TRIGGER otlens_guard_users_truncate
BEFORE TRUNCATE ON users
FOR EACH STATEMENT EXECUTE FUNCTION otlens_guard_auth_defaults_truncate();

-- Sensors prune flows that have gone quiet for a while (see
-- internal/flow/engine.go's Prune) to bound their own SQLite growth —
-- that's correct and necessary on the sensor, but it means a connection
-- that only happened once can disappear from a later telemetry sync's
-- topology blob even though it genuinely occurred. This table is Central's
-- own durable, ever-growing record of every asset pair a sensor has ever
-- reported: PutTelemetry upserts into it on every sync (see
-- upsertTopologyEdges), and the /topology handler reads from here instead
-- of the live per-sensor snapshot, so a connection drawn once stays on the
-- map even after the sensor's own copy of it has aged out.
CREATE TABLE IF NOT EXISTS dns_observations (
 id BIGSERIAL PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 observed_at TIMESTAMPTZ NOT NULL,
 client_ip TEXT NOT NULL DEFAULT '',
 server_ip TEXT NOT NULL DEFAULT '',
 query_name TEXT NOT NULL,
 query_type INTEGER NOT NULL DEFAULT 0,
 transaction_id INTEGER NOT NULL DEFAULT 0,
 conversation_id TEXT NOT NULL DEFAULT '',
 direction TEXT NOT NULL DEFAULT '',
 response_code INTEGER NOT NULL DEFAULT 0,
 is_response BOOLEAN NOT NULL DEFAULT FALSE,
 answer_count INTEGER NOT NULL DEFAULT 0,
 payload_bytes INTEGER NOT NULL DEFAULT 0,
 answers JSONB NOT NULL DEFAULT '[]'::jsonb,
 cnames JSONB NOT NULL DEFAULT '[]'::jsonb,
 ttl BIGINT NOT NULL DEFAULT 0,
 UNIQUE(sensor_id,observed_at,client_ip,query_name,is_response)
);
ALTER TABLE dns_observations ADD COLUMN IF NOT EXISTS transaction_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dns_observations ADD COLUMN IF NOT EXISTS conversation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE dns_observations ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT '';
ALTER TABLE dns_observations ADD COLUMN IF NOT EXISTS answer_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dns_observations ADD COLUMN IF NOT EXISTS payload_bytes INTEGER NOT NULL DEFAULT 0;
DO $$
DECLARE legacy_unique TEXT;
BEGIN
 SELECT conname INTO legacy_unique
 FROM pg_constraint
 WHERE conrelid='dns_observations'::regclass AND contype='u'
   AND pg_get_constraintdef(oid) LIKE '%sensor_id%observed_at%client_ip%query_name%is_response%'
 LIMIT 1;
 IF legacy_unique IS NOT NULL THEN
  EXECUTE format('ALTER TABLE dns_observations DROP CONSTRAINT %I', legacy_unique);
 END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_observations_event_unique ON dns_observations(sensor_id,observed_at,client_ip,server_ip,transaction_id,query_name,query_type,is_response);
CREATE INDEX IF NOT EXISTS idx_dns_observations_lookup ON dns_observations(sensor_id,observed_at,query_name);
CREATE INDEX IF NOT EXISTS idx_dns_observations_client ON dns_observations(sensor_id,client_ip,observed_at);

CREATE TABLE IF NOT EXISTS smb_observations (
 id BIGSERIAL PRIMARY KEY, sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 observed_at TIMESTAMPTZ NOT NULL, client_ip TEXT NOT NULL DEFAULT '', server_ip TEXT NOT NULL DEFAULT '',
 client_port INTEGER NOT NULL DEFAULT 0, server_port INTEGER NOT NULL DEFAULT 445, dialect TEXT NOT NULL DEFAULT '', command TEXT NOT NULL DEFAULT '',
 message_id NUMERIC(20,0) NOT NULL DEFAULT 0, session_id NUMERIC(20,0) NOT NULL DEFAULT 0, tree_id BIGINT NOT NULL DEFAULT 0,
 file_id_persistent NUMERIC(20,0) NOT NULL DEFAULT 0, file_id_volatile NUMERIC(20,0) NOT NULL DEFAULT 0,
 request_command TEXT NOT NULL DEFAULT '', request_matched BOOLEAN NOT NULL DEFAULT FALSE, stream_gapped BOOLEAN NOT NULL DEFAULT FALSE, stream_resynced BOOLEAN NOT NULL DEFAULT FALSE,
 share_name TEXT NOT NULL DEFAULT '', file_name TEXT NOT NULL DEFAULT '', named_pipe TEXT NOT NULL DEFAULT '', direction TEXT NOT NULL DEFAULT '',
 bytes BIGINT NOT NULL DEFAULT 0, status BIGINT NOT NULL DEFAULT 0, is_response BOOLEAN NOT NULL DEFAULT FALSE,
 is_admin_share BOOLEAN NOT NULL DEFAULT FALSE, is_executable BOOLEAN NOT NULL DEFAULT FALSE, is_script BOOLEAN NOT NULL DEFAULT FALSE, is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
 UNIQUE(sensor_id,observed_at,client_ip,server_ip,message_id,command,is_response)
);
ALTER TABLE smb_observations ADD COLUMN IF NOT EXISTS dialect TEXT NOT NULL DEFAULT '';
ALTER TABLE smb_observations ADD COLUMN IF NOT EXISTS file_id_persistent NUMERIC(20,0) NOT NULL DEFAULT 0;
ALTER TABLE smb_observations ADD COLUMN IF NOT EXISTS file_id_volatile NUMERIC(20,0) NOT NULL DEFAULT 0;
ALTER TABLE smb_observations ADD COLUMN IF NOT EXISTS request_command TEXT NOT NULL DEFAULT '';
ALTER TABLE smb_observations ADD COLUMN IF NOT EXISTS request_matched BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE smb_observations ADD COLUMN IF NOT EXISTS stream_gapped BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE smb_observations ADD COLUMN IF NOT EXISTS stream_resynced BOOLEAN NOT NULL DEFAULT FALSE;
DO $$
DECLARE legacy_unique TEXT;
BEGIN
 SELECT conname INTO legacy_unique
 FROM pg_constraint
 WHERE conrelid='smb_observations'::regclass AND contype='u'
   AND pg_get_constraintdef(oid) LIKE '%sensor_id%observed_at%client_ip%server_ip%message_id%command%is_response%'
 LIMIT 1;
 IF legacy_unique IS NOT NULL THEN
  EXECUTE format('ALTER TABLE smb_observations DROP CONSTRAINT %I', legacy_unique);
 END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_smb_observations_event_unique ON smb_observations(sensor_id,observed_at,client_ip,server_ip,session_id,message_id,command,is_response);
CREATE INDEX IF NOT EXISTS idx_smb_observations_lookup ON smb_observations(sensor_id,observed_at,client_ip,server_ip);
CREATE INDEX IF NOT EXISTS idx_smb_observations_artifact ON smb_observations(sensor_id,share_name,file_name,observed_at);
CREATE TABLE IF NOT EXISTS flow_counters (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 flow_id TEXT NOT NULL,
 packets BIGINT NOT NULL DEFAULT 0,
 bytes BIGINT NOT NULL DEFAULT 0,
 packets_a_to_b BIGINT NOT NULL DEFAULT 0,
 packets_b_to_a BIGINT NOT NULL DEFAULT 0,
 bytes_a_to_b BIGINT NOT NULL DEFAULT 0,
 bytes_b_to_a BIGINT NOT NULL DEFAULT 0,
 last_seen TIMESTAMPTZ,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(sensor_id,flow_id)
);
ALTER TABLE flow_counters ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS flow_observations (
 id BIGSERIAL PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 flow_id TEXT NOT NULL,
 bucket_start TIMESTAMPTZ NOT NULL,
 bucket_end TIMESTAMPTZ NOT NULL,
 src_ip TEXT NOT NULL,
 dst_ip TEXT NOT NULL,
 src_port INTEGER NOT NULL DEFAULT 0,
 dst_port INTEGER NOT NULL DEFAULT 0,
 protocol TEXT NOT NULL DEFAULT '',
 initiator_ip TEXT NOT NULL DEFAULT '',
 responder_ip TEXT NOT NULL DEFAULT '',
 initiator_port INTEGER NOT NULL DEFAULT 0,
 responder_port INTEGER NOT NULL DEFAULT 0,
 packets BIGINT NOT NULL DEFAULT 0,
 bytes BIGINT NOT NULL DEFAULT 0,
 packets_a_to_b BIGINT NOT NULL DEFAULT 0,
 packets_b_to_a BIGINT NOT NULL DEFAULT 0,
 bytes_a_to_b BIGINT NOT NULL DEFAULT 0,
 bytes_b_to_a BIGINT NOT NULL DEFAULT 0,
 vlan_id INTEGER NOT NULL DEFAULT 0,
 is_ot BOOLEAN NOT NULL DEFAULT FALSE,
 UNIQUE(sensor_id,flow_id,bucket_start)
);
CREATE INDEX IF NOT EXISTS idx_flow_observations_contact ON flow_observations(sensor_id,bucket_start,src_ip,dst_ip);
UPDATE flow_counters fc SET last_seen=history.last_seen
FROM (SELECT sensor_id,flow_id,MAX(bucket_end) AS last_seen FROM flow_observations GROUP BY sensor_id,flow_id) history
WHERE fc.sensor_id=history.sensor_id AND fc.flow_id=history.flow_id AND fc.last_seen IS NULL;
CREATE TABLE IF NOT EXISTS asset_security_status (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_ip TEXT NOT NULL,
 asset_identity TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('clean','suspected','infected','contained','recovered')),
 reason TEXT NOT NULL DEFAULT '',
 source TEXT NOT NULL DEFAULT 'manual',
 detected_at TIMESTAMPTZ,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(sensor_id,asset_identity)
);
CREATE INDEX IF NOT EXISTS idx_asset_security_ip ON asset_security_status(sensor_id,asset_ip);
CREATE TABLE IF NOT EXISTS malware_incidents (
 id BIGSERIAL PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 initial_asset_ip TEXT NOT NULL,
 title TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open',
 severity TEXT NOT NULL DEFAULT 'critical',
 lookback_hours INTEGER NOT NULL DEFAULT 24,
 max_hops INTEGER NOT NULL DEFAULT 2,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS asset_exposures (
 incident_id BIGINT NOT NULL REFERENCES malware_incidents(id) ON DELETE CASCADE,
 exposed_asset_ip TEXT NOT NULL,
 parent_asset_ip TEXT NOT NULL DEFAULT '',
 hop_count INTEGER NOT NULL,
 exposure_score INTEGER NOT NULL,
 exposure_severity TEXT NOT NULL,
 reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
 first_contact TIMESTAMPTZ,
 last_contact TIMESTAMPTZ,
 protocols TEXT NOT NULL DEFAULT '',
 bytes BIGINT NOT NULL DEFAULT 0,
 packets BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(incident_id,exposed_asset_ip)
);
DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='asset_exposures' AND column_name='score')
    AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='asset_exposures' AND column_name='exposure_score') THEN
  ALTER TABLE asset_exposures RENAME COLUMN score TO exposure_score;
 END IF;
 IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='asset_exposures' AND column_name='severity')
    AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='asset_exposures' AND column_name='exposure_severity') THEN
  ALTER TABLE asset_exposures RENAME COLUMN severity TO exposure_severity;
 END IF;
END $$;

CREATE TABLE IF NOT EXISTS topology_edges (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 pair_key TEXT NOT NULL,
 src_ip TEXT NOT NULL,
 dst_ip TEXT NOT NULL,
 protocols TEXT NOT NULL DEFAULT '',
 is_ot BOOLEAN NOT NULL DEFAULT FALSE,
 from_honeypot BOOLEAN NOT NULL DEFAULT FALSE,
 vlan_id INTEGER NOT NULL DEFAULT 0,
 packets BIGINT NOT NULL DEFAULT 0,
 bytes BIGINT NOT NULL DEFAULT 0,
 flow_count INTEGER NOT NULL DEFAULT 1,
 first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY (sensor_id, pair_key)
);
-- Companion to topology_edges, same reasoning: a sensor's live topology
-- snapshot only ever contains its *current* assets (subject to the same
-- persist.retention pruning as flows). Without this, an edge safely
-- recorded in topology_edges becomes undrawable the moment either
-- endpoint asset ages out of the live snapshot, since the frontend can
-- only place an edge between two nodes it actually has — exactly the
-- "the line was there, then it vanished" symptom this fixes. See
-- upsertTopologyNodes/ListTopologyNodes in internal/central/topology_edges.go.
CREATE TABLE IF NOT EXISTS topology_nodes (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 ip TEXT NOT NULL,
 mac TEXT NOT NULL DEFAULT '',
 hostname TEXT NOT NULL DEFAULT '',
 vendor TEXT NOT NULL DEFAULT '',
 is_ot BOOLEAN NOT NULL DEFAULT FALSE,
 protocols TEXT NOT NULL DEFAULT '',
 confirmed BOOLEAN NOT NULL DEFAULT TRUE,
 score INTEGER NOT NULL DEFAULT 1,
 vlan_id INTEGER NOT NULL DEFAULT 0,
 packet_count BIGINT NOT NULL DEFAULT 0,
 first_seen TIMESTAMPTZ NOT NULL,
 last_seen TIMESTAMPTZ NOT NULL,
 active BOOLEAN NOT NULL DEFAULT TRUE,
 PRIMARY KEY (sensor_id, ip)
);
-- Stable MAC-backed identity history. topology_nodes remains the current
-- IP-indexed topology ledger needed to attach historical edges, but an IP may be
-- reused by a different device over time. This companion table preserves both
-- identities instead of overwriting the old MAC->IP relationship.
CREATE TABLE IF NOT EXISTS asset_identity_history (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_identity TEXT NOT NULL,
 ip TEXT NOT NULL,
 mac TEXT NOT NULL DEFAULT '',
 hostname TEXT NOT NULL DEFAULT '',
 vendor TEXT NOT NULL DEFAULT '',
 is_ot BOOLEAN NOT NULL DEFAULT FALSE,
 protocols TEXT NOT NULL DEFAULT '',
 confirmed BOOLEAN NOT NULL DEFAULT TRUE,
 score INTEGER NOT NULL DEFAULT 1,
 vlan_id INTEGER NOT NULL DEFAULT 0,
 packet_count BIGINT NOT NULL DEFAULT 0,
 first_seen TIMESTAMPTZ NOT NULL,
 last_seen TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(sensor_id,asset_identity,ip)
);
CREATE INDEX IF NOT EXISTS idx_asset_identity_history_mac ON asset_identity_history(sensor_id,mac,last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_asset_identity_history_ip ON asset_identity_history(sensor_id,ip,last_seen DESC);
-- Durable, one-row-per-alert history, independent of sensor_telemetry.alerts
-- (which is a single JSONB array per sensor, wholesale-overwritten on every
-- sync — no per-alert timestamp to prune by). Upserted from that JSONB on
-- every PutTelemetry, same pattern as topology_edges/topology_nodes. This is
-- what database_retention.alerts_days actually prunes and what the Alerts
-- investigation UI searches/paginates directly. sensor_telemetry.alerts remains
-- only the latest sensor-side delta/snapshot transport.
CREATE TABLE IF NOT EXISTS alert_history (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 alert_key TEXT NOT NULL,
 type TEXT NOT NULL,
 severity TEXT NOT NULL,
 message TEXT NOT NULL,
 evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
 ip TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'new',
 approved_by TEXT NOT NULL DEFAULT '',
 approved_at TIMESTAMPTZ,
 count BIGINT NOT NULL DEFAULT 1,
 first_seen TIMESTAMPTZ NOT NULL,
 last_seen TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (sensor_id, alert_key)
);
CREATE INDEX IF NOT EXISTS idx_alert_history_last_seen ON alert_history(last_seen);
CREATE INDEX IF NOT EXISTS idx_alert_history_status_last_seen ON alert_history(status,last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_alert_history_severity_last_seen ON alert_history(severity,last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_alert_history_sensor_last_seen ON alert_history(sensor_id,last_seen DESC);
ALTER TABLE alert_history ADD COLUMN IF NOT EXISTS count BIGINT NOT NULL DEFAULT 1;
ALTER TABLE alert_history ADD COLUMN IF NOT EXISTS evidence JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Written unconditionally by auditMiddleware for every mutating
-- Management API request, independent of whether SIEM export is
-- configured — siem_outbox (a delivery queue whose rows are deleted once
-- delivered) was never a retained history and only existed at all when
-- SIEM was enabled. This is what the Audit tab reads and what
-- database_retention.audit_days prunes.
CREATE TABLE IF NOT EXISTS audit_log (
 id BIGSERIAL PRIMARY KEY,
 actor TEXT NOT NULL DEFAULT '',
 action TEXT NOT NULL,
 method TEXT NOT NULL,
 path TEXT NOT NULL,
 status INTEGER NOT NULL,
 success BOOLEAN NOT NULL,
 source_ip TEXT NOT NULL DEFAULT '',
 sensor_id TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
-- One row per generated report (see internal/central/reports.go). Kept
-- regardless of whether email delivery is configured or succeeds — the
-- Reports tab reads this table directly, so a report is always viewable
-- even on a fully offline/air-gapped Central with no SMTP configured at
-- all.
CREATE TABLE IF NOT EXISTS report_history (
 id TEXT PRIMARY KEY,
 period_start TIMESTAMPTZ NOT NULL,
 period_end TIMESTAMPTZ NOT NULL,
 html TEXT NOT NULL,
 recipients TEXT NOT NULL DEFAULT '',
 email_sent BOOLEAN NOT NULL DEFAULT FALSE,
 email_error TEXT NOT NULL DEFAULT '',
 email_attempts INTEGER NOT NULL DEFAULT 0,
 last_email_attempt_at TIMESTAMPTZ,
 next_email_attempt_at TIMESTAMPTZ,
 generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_report_history_generated_at ON report_history(generated_at);
-- Manual/imported category+name overrides for the Devices tab — see
-- internal/central/devices.go. Never touched by any sensor sync; this
-- is purely operator input (either one-by-one from the Devices tab, or
-- bulk via CSV import) and always wins over the automatic vendor-based
-- category guess for a given (sensor_id, mac).
CREATE TABLE IF NOT EXISTS asset_context (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_ip TEXT NOT NULL,
 asset_identity TEXT NOT NULL,
 asset_role TEXT NOT NULL DEFAULT '',
 criticality TEXT NOT NULL DEFAULT '',
 zone TEXT NOT NULL DEFAULT '',
 purdue_override REAL CHECK(purdue_override IS NULL OR purdue_override IN (0,1,2,3,3.5,4,5)),
 is_attack_path_entry BOOLEAN NOT NULL DEFAULT FALSE,
 is_attack_path_target BOOLEAN NOT NULL DEFAULT FALSE,
 updated_by TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(sensor_id,asset_identity)
);
CREATE INDEX IF NOT EXISTS idx_asset_context_ip ON asset_context(sensor_id,asset_ip);
CREATE INDEX IF NOT EXISTS idx_flow_observations_itot ON flow_observations(sensor_id,bucket_end,initiator_ip,responder_ip);
CREATE TABLE IF NOT EXISTS imported_tags (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 tag_key TEXT NOT NULL,
 tag JSONB NOT NULL DEFAULT '{}'::jsonb,
 imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 imported_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(sensor_id, tag_key)
);
CREATE TABLE IF NOT EXISTS asset_overrides (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 mac TEXT NOT NULL,
 category TEXT NOT NULL DEFAULT '',
 name TEXT NOT NULL DEFAULT '',
 updated_by TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY (sensor_id, mac)
);
-- VLAN display name + assigned Purdue Model level, managed from the
-- Network Segmentation tab — see internal/central/segmentation.go. This
-- is Central's copy for naming/visualization; the sensor's own
-- detect.segmentation.vlanlevels (its config file) is what the live
-- segmentation_violation detection rule actually runs against — see
-- that tab's own notes on why the two aren't automatically the same
-- thing yet.
CREATE TABLE IF NOT EXISTS vlan_config (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 vlan_id INTEGER NOT NULL CHECK(vlan_id BETWEEN 0 AND 4094),
 name TEXT NOT NULL DEFAULT '',
 purdue_level REAL CHECK(purdue_level IS NULL OR purdue_level IN (0,1,2,3,3.5,4,5)),
 updated_by TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY (sensor_id, vlan_id)
);
-- The one setting vlan_config doesn't cover (it's per-sensor, not
-- per-VLAN): how many Purdue levels apart two VLANs may communicate
-- before segmentation_violation fires. Kept here so pushSegmentationConfig
-- (internal/central/segmentation.go) has everything it needs to send the
-- sensor a complete "segmentation.config" command without also requiring
-- detect.segmentation.maxleveljump in that sensor's local config file.
CREATE TABLE IF NOT EXISTS segmentation_settings (
 sensor_id TEXT PRIMARY KEY REFERENCES sensors(id) ON DELETE CASCADE,
 max_level_jump REAL NOT NULL DEFAULT 1 CHECK(max_level_jump > 0 AND max_level_jump <= 5),
 updated_by TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("ensure central database schema: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,name) VALUES(1,'central bootstrap schema') ON CONFLICT(version) DO NOTHING`); err != nil {
		db.Close()
		return nil, fmt.Errorf("record central schema migration: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,name) VALUES(2,'discovery campaigns and asset recon history') ON CONFLICT(version) DO NOTHING`); err != nil {
		db.Close()
		return nil, fmt.Errorf("record discovery campaign migration: %w", err)
	}
	if _, err := db.Exec(vulnerabilitySchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("bootstrap vulnerability schema: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,name) VALUES(3,'vulnerability finding lifecycle') ON CONFLICT(version) DO NOTHING`); err != nil {
		db.Close()
		return nil, fmt.Errorf("record vulnerability lifecycle migration: %w", err)
	}
	if _, err := db.Exec(threatIntelSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("ensure threat intelligence schema: %w", err)
	}
	if _, err := db.Exec(incidentManagementSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("ensure incident management schema: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,name) VALUES(4,'incident management correlation and asset risk') ON CONFLICT(version) DO NOTHING`); err != nil {
		db.Close()
		return nil, fmt.Errorf("record incident management migration: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,name) VALUES(5,'advanced correlation rules and MITRE mapping') ON CONFLICT(version) DO NOTHING`); err != nil {
		db.Close()
		return nil, fmt.Errorf("record advanced correlation migration: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,name) VALUES(6,'advanced contextual asset risk engine') ON CONFLICT(version) DO NOTHING`); err != nil {
		db.Close()
		return nil, fmt.Errorf("record advanced asset risk migration: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE sensors ADD COLUMN IF NOT EXISTS auth_token_hash TEXT NOT NULL DEFAULT ''; ALTER TABLE sensors ADD COLUMN IF NOT EXISTS auth_token_rotated_at TIMESTAMPTZ; INSERT INTO schema_migrations(version,name) VALUES(7,'per-sensor authentication tokens and live RBAC') ON CONFLICT(version) DO NOTHING`); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply sensor authentication migration: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,name) VALUES(8,'protected authentication defaults across Central resets') ON CONFLICT(version) DO NOTHING`); err != nil {
		db.Close()
		return nil, fmt.Errorf("record protected authentication defaults migration: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE report_history ADD COLUMN IF NOT EXISTS email_attempts INTEGER NOT NULL DEFAULT 0; ALTER TABLE report_history ADD COLUMN IF NOT EXISTS last_email_attempt_at TIMESTAMPTZ; ALTER TABLE report_history ADD COLUMN IF NOT EXISTS next_email_attempt_at TIMESTAMPTZ; CREATE INDEX IF NOT EXISTS idx_report_history_delivery_retry ON report_history(next_email_attempt_at) WHERE email_sent=FALSE AND recipients<>''; INSERT INTO schema_migrations(version,name) VALUES(9,'durable scheduled report delivery retries') ON CONFLICT(version) DO NOTHING`); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply report delivery retry migration: %w", err)
	}
	if _, err := db.Exec(`
ALTER TABLE asset_context ADD COLUMN IF NOT EXISTS asset_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_security_status ADD COLUMN IF NOT EXISTS asset_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_risk_exceptions ADD COLUMN IF NOT EXISTS asset_identity TEXT NOT NULL DEFAULT '';
DELETE FROM vlan_config WHERE vlan_id < 0 OR vlan_id > 4094;
UPDATE vlan_config SET purdue_level=NULL WHERE purdue_level IS NOT NULL AND purdue_level NOT IN (0,1,2,3,3.5,4,5);
UPDATE asset_context SET purdue_override=NULL WHERE purdue_override IS NOT NULL AND purdue_override NOT IN (0,1,2,3,3.5,4,5);
UPDATE segmentation_settings SET max_level_jump=1 WHERE max_level_jump<=0 OR max_level_jump>5;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='vlan_config_vlan_id_valid') THEN ALTER TABLE vlan_config ADD CONSTRAINT vlan_config_vlan_id_valid CHECK(vlan_id BETWEEN 0 AND 4094); END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='vlan_config_purdue_valid') THEN ALTER TABLE vlan_config ADD CONSTRAINT vlan_config_purdue_valid CHECK(purdue_level IS NULL OR purdue_level IN (0,1,2,3,3.5,4,5)); END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='asset_context_purdue_valid') THEN ALTER TABLE asset_context ADD CONSTRAINT asset_context_purdue_valid CHECK(purdue_override IS NULL OR purdue_override IN (0,1,2,3,3.5,4,5)); END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='segmentation_max_jump_valid') THEN ALTER TABLE segmentation_settings ADD CONSTRAINT segmentation_max_jump_valid CHECK(max_level_jump>0 AND max_level_jump<=5); END IF;
END $$;
CREATE TABLE IF NOT EXISTS asset_identity_history (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_identity TEXT NOT NULL,
 ip TEXT NOT NULL,
 mac TEXT NOT NULL DEFAULT '',
 hostname TEXT NOT NULL DEFAULT '',
 vendor TEXT NOT NULL DEFAULT '',
 is_ot BOOLEAN NOT NULL DEFAULT FALSE,
 protocols TEXT NOT NULL DEFAULT '',
 confirmed BOOLEAN NOT NULL DEFAULT TRUE,
 score INTEGER NOT NULL DEFAULT 1,
 vlan_id INTEGER NOT NULL DEFAULT 0,
 packet_count BIGINT NOT NULL DEFAULT 0,
 first_seen TIMESTAMPTZ NOT NULL,
 last_seen TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(sensor_id,asset_identity,ip)
);
CREATE INDEX IF NOT EXISTS idx_asset_identity_history_mac ON asset_identity_history(sensor_id,mac,last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_asset_identity_history_ip ON asset_identity_history(sensor_id,ip,last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_asset_context_identity ON asset_context(sensor_id,asset_identity);
CREATE INDEX IF NOT EXISTS idx_asset_security_identity ON asset_security_status(sensor_id,asset_identity);
CREATE INDEX IF NOT EXISTS idx_asset_risk_exception_identity ON asset_risk_exceptions(sensor_id,asset_identity);
INSERT INTO asset_identity_history(sensor_id,asset_identity,ip,mac,hostname,vendor,is_ot,protocols,confirmed,score,vlan_id,packet_count,first_seen,last_seen)
SELECT sensor_id,CASE WHEN mac<>'' THEN 'mac:'||lower(mac) ELSE 'ip:'||ip END,ip,mac,hostname,vendor,is_ot,protocols,confirmed,score,vlan_id,packet_count,first_seen,last_seen
FROM topology_nodes
ON CONFLICT(sensor_id,asset_identity,ip) DO UPDATE SET
 mac=EXCLUDED.mac,hostname=EXCLUDED.hostname,vendor=EXCLUDED.vendor,
 is_ot=asset_identity_history.is_ot OR EXCLUDED.is_ot,
 protocols=EXCLUDED.protocols,confirmed=EXCLUDED.confirmed,score=EXCLUDED.score,
 vlan_id=EXCLUDED.vlan_id,packet_count=EXCLUDED.packet_count,
 first_seen=LEAST(asset_identity_history.first_seen,EXCLUDED.first_seen),
 last_seen=GREATEST(asset_identity_history.last_seen,EXCLUDED.last_seen);
UPDATE asset_context c SET asset_identity=COALESCE((
 SELECT CASE WHEN n.mac<>'' THEN 'mac:'||lower(n.mac) ELSE 'ip:'||c.asset_ip END
 FROM topology_nodes n WHERE n.sensor_id=c.sensor_id AND n.ip=c.asset_ip
 ORDER BY n.last_seen DESC LIMIT 1
),'ip:'||c.asset_ip) WHERE c.asset_identity='';
UPDATE asset_security_status c SET asset_identity=COALESCE((
 SELECT CASE WHEN n.mac<>'' THEN 'mac:'||lower(n.mac) ELSE 'ip:'||c.asset_ip END
 FROM topology_nodes n WHERE n.sensor_id=c.sensor_id AND n.ip=c.asset_ip
 ORDER BY n.last_seen DESC LIMIT 1
),'ip:'||c.asset_ip) WHERE c.asset_identity='';
UPDATE asset_risk_exceptions c SET asset_identity=COALESCE((
 SELECT CASE WHEN n.mac<>'' THEN 'mac:'||lower(n.mac) ELSE 'ip:'||c.asset_ip END
 FROM topology_nodes n WHERE n.sensor_id=c.sensor_id AND n.ip=c.asset_ip
 ORDER BY n.last_seen DESC LIMIT 1
),'ip:'||c.asset_ip) WHERE c.asset_identity='';
INSERT INTO schema_migrations(version,name) VALUES(10,'stable asset identity and Purdue consistency') ON CONFLICT(version) DO NOTHING;
`); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply stable asset identity migration: %w", err)
	}
	if _, err := db.Exec(`
ALTER TABLE topology_nodes ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;

-- The primary-key conversion is intentionally one-shot. Re-dropping and
-- recreating these keys on every Central startup would take unnecessary table
-- locks even after migration 11 had already completed.
DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=11) THEN
  -- Reconstruct current-inventory membership from the latest full telemetry
  -- snapshot. ALTER COLUMN's DEFAULT TRUE would otherwise mark every historical
  -- topology IP as current immediately after upgrade until each sensor happened
  -- to sync again.
  UPDATE topology_nodes SET active=FALSE;
  UPDATE topology_nodes n SET active=TRUE
  FROM sensor_telemetry st,
       LATERAL jsonb_array_elements(COALESCE(st.topology->'Nodes', st.topology->'nodes', '[]'::jsonb)) AS items(item)
  WHERE n.sensor_id=st.sensor_id AND n.ip=COALESCE(item->>'IP', item->>'ip');

  -- Operator-owned asset state is identity-owned, not IP-owned. An IP can be
  -- reused by another MAC; keeping the old IP primary key would overwrite the
  -- original device's context/status/risk exception as soon as the new device
  -- was edited. Keep one current operator row per stable identity and retain
  -- asset_ip only as the last-known/display address.
  DELETE FROM asset_context a USING (
   SELECT ctid,ROW_NUMBER() OVER(PARTITION BY sensor_id,asset_identity ORDER BY updated_at DESC,asset_ip ASC) rn FROM asset_context
  ) r WHERE a.ctid=r.ctid AND r.rn>1;
  DELETE FROM asset_security_status a USING (
   SELECT ctid,ROW_NUMBER() OVER(PARTITION BY sensor_id,asset_identity ORDER BY updated_at DESC,asset_ip ASC) rn FROM asset_security_status
  ) r WHERE a.ctid=r.ctid AND r.rn>1;
  DELETE FROM asset_risk_exceptions a USING (
   SELECT ctid,ROW_NUMBER() OVER(PARTITION BY sensor_id,asset_identity ORDER BY updated_at DESC,asset_ip ASC) rn FROM asset_risk_exceptions
  ) r WHERE a.ctid=r.ctid AND r.rn>1;

  ALTER TABLE asset_context DROP CONSTRAINT IF EXISTS asset_context_pkey;
  ALTER TABLE asset_context ADD CONSTRAINT asset_context_pkey PRIMARY KEY(sensor_id,asset_identity);
  ALTER TABLE asset_security_status DROP CONSTRAINT IF EXISTS asset_security_status_pkey;
  ALTER TABLE asset_security_status ADD CONSTRAINT asset_security_status_pkey PRIMARY KEY(sensor_id,asset_identity);
  ALTER TABLE asset_risk_exceptions DROP CONSTRAINT IF EXISTS asset_risk_exceptions_pkey;
  ALTER TABLE asset_risk_exceptions ADD CONSTRAINT asset_risk_exceptions_pkey PRIMARY KEY(sensor_id,asset_identity);
  INSERT INTO schema_migrations(version,name) VALUES(11,'active asset reconciliation and identity-owned operator state');
 END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_asset_context_ip ON asset_context(sensor_id,asset_ip);
CREATE INDEX IF NOT EXISTS idx_asset_security_ip ON asset_security_status(sensor_id,asset_ip);
CREATE INDEX IF NOT EXISTS idx_asset_risk_exception_ip ON asset_risk_exceptions(sensor_id,asset_ip);
`); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply active asset identity migration: %w", err)
	}

	if _, err := db.Exec(`
ALTER TABLE asset_recon_profile ADD COLUMN IF NOT EXISTS asset_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_recon_history ADD COLUMN IF NOT EXISTS asset_identity TEXT NOT NULL DEFAULT '';
DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=12) THEN
  -- Bind existing reconnaissance evidence to the device that owned the IP when
  -- the evidence was observed. This prevents a later DHCP/IP reuse from
  -- attaching an old device's OS/firmware/serial profile to the new occupant.
  UPDATE asset_recon_profile p SET asset_identity=COALESCE((
   SELECT h.asset_identity FROM asset_identity_history h
   WHERE h.sensor_id=p.sensor_id AND h.ip=p.ip AND h.first_seen<=p.last_profiled_at
   ORDER BY CASE WHEN p.last_profiled_at BETWEEN h.first_seen AND h.last_seen THEN 0 ELSE 1 END,
            h.last_seen DESC LIMIT 1
  ),(SELECT h.asset_identity FROM asset_identity_history h WHERE h.sensor_id=p.sensor_id AND h.ip=p.ip ORDER BY h.last_seen DESC LIMIT 1),'ip:'||p.ip)
  WHERE p.asset_identity='';
  UPDATE asset_recon_history p SET asset_identity=COALESCE((
   SELECT h.asset_identity FROM asset_identity_history h
   WHERE h.sensor_id=p.sensor_id AND h.ip=p.ip AND h.first_seen<=p.observed_at
   ORDER BY CASE WHEN p.observed_at BETWEEN h.first_seen AND h.last_seen THEN 0 ELSE 1 END,
            h.last_seen DESC LIMIT 1
  ),(SELECT h.asset_identity FROM asset_identity_history h WHERE h.sensor_id=p.sensor_id AND h.ip=p.ip ORDER BY h.last_seen DESC LIMIT 1),'ip:'||p.ip)
  WHERE p.asset_identity='';

  -- A device may have been profiled at more than one DHCP address. Keep the
  -- newest profile as the current profile; history retains every observation.
  DELETE FROM asset_recon_profile p USING (
   SELECT ctid,ROW_NUMBER() OVER(PARTITION BY sensor_id,asset_identity ORDER BY last_profiled_at DESC,ip ASC) rn
   FROM asset_recon_profile
  ) d WHERE p.ctid=d.ctid AND d.rn>1;
  ALTER TABLE asset_recon_profile DROP CONSTRAINT IF EXISTS asset_recon_profile_pkey;
  ALTER TABLE asset_recon_profile ADD CONSTRAINT asset_recon_profile_pkey PRIMARY KEY(sensor_id,asset_identity);
  INSERT INTO schema_migrations(version,name) VALUES(12,'identity-owned reconnaissance profiles');
 END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_asset_recon_profile_ip ON asset_recon_profile(sensor_id,ip);
CREATE INDEX IF NOT EXISTS idx_asset_recon_history_identity ON asset_recon_history(sensor_id,asset_identity,observed_at DESC);
`); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply reconnaissance asset identity migration: %w", err)
	}
	return &Repository{db: db}, nil
}
func (r *Repository) Close() error { return r.db.Close() }

func (r *Repository) ConfigureSIEM(alertsEnabled, auditEnabled bool, source string) {
	r.siemAlertsEnabled = alertsEnabled
	r.siemAuditEnabled = auditEnabled
	r.siemSource = strings.TrimSpace(source)
	if r.siemSource == "" {
		r.siemSource = "otlens-central"
	}
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
VALUES($1,$2,$3,'offline',$4,$5,$6,NOW())
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,site_id=EXCLUDED.site_id,version=EXCLUDED.version,hostname=EXCLUDED.hostname,certificate_fingerprint=EXCLUDED.certificate_fingerprint`, s.ID, s.Name, site, s.Version, s.Hostname, s.CertificateFingerprint)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// SetSensorAuthToken binds a cryptographically random bearer token to one
// sensor. Only its SHA-256 digest is persisted; the plaintext is returned once
// during enrollment and never becomes queryable through the API.
func (r *Repository) SetSensorAuthToken(ctx context.Context, sensorID, tokenHash string) error {
	result, err := r.db.ExecContext(ctx, `UPDATE sensors SET auth_token_hash=$2, auth_token_rotated_at=NOW() WHERE id=$1`, sensorID, tokenHash)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) SensorAuthTokenHash(ctx context.Context, sensorID string) (string, error) {
	var hash string
	err := r.db.QueryRowContext(ctx, `SELECT auth_token_hash FROM sensors WHERE id=$1`, sensorID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return hash, err
}

// RuleName looks up a rule's human-readable Name from a sensor's current
// reported rule list, for audit logging (an ID alone in the Audit log
// isn't very readable). Best-effort: returns ok=false if the sensor or
// rule isn't found — not an error condition, the caller falls back to
// showing the ID.
func (r *Repository) RuleName(ctx context.Context, sensorID, ruleID string) (name string, ok bool) {
	var rulesJSON []byte
	if err := r.db.QueryRowContext(ctx, `SELECT rules FROM sensor_telemetry WHERE sensor_id=$1`, sensorID).Scan(&rulesJSON); err != nil {
		return "", false
	}
	var rules []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if json.Unmarshal(rulesJSON, &rules) != nil {
		return "", false
	}
	for _, rule := range rules {
		if rule.ID == ruleID {
			return rule.Name, rule.Name != ""
		}
	}
	return "", false
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
 capture_backend=$8,capture_interface=$9,capture_snaplen=$10,capture_promiscuous=$11,last_seen=NOW(),last_heartbeat_at=NOW(),
 last_sync_attempt_at=NULLIF($12, '0001-01-01'::timestamptz),last_sync_success_at=NULLIF($13, '0001-01-01'::timestamptz),
 pending_records=$14::bigint,sync_failures=$15::integer,last_sync_error=$16,sync_sequence=$17,
 sync_status=CASE WHEN $15::integer>0 AND $14::bigint>0 THEN 'stalled' WHEN $15::integer>0 THEN 'error' WHEN $14::bigint>0 THEN 'pending' ELSE 'healthy' END
 WHERE id=$1`, h.SensorID, h.Version, h.Hostname, status,
		stringValue(h.Versions, "go"), stringValue(h.Versions, "libpcap"), stringValue(h.Versions, "gopacket"),
		toString(interfaceValue("backend")), toString(interfaceValue("interface")), toInt32(interfaceValue("snaplen")), toBool(interfaceValue("promiscuous")),
		h.Sync.LastAttemptAt, h.Sync.LastSuccessAt, h.Sync.PendingRecords, h.Sync.ConsecutiveFailures, h.Sync.LastError, h.Sync.Sequence)
	if err != nil {
		return err
	}
	healthJSON, _ := json.Marshal(h.Health)
	metricsJSON, _ := json.Marshal(h.Metrics)
	versionsJSON, _ := json.Marshal(h.Versions)
	captureJSON, _ := json.Marshal(h.Capture)
	syncJSON, _ := json.Marshal(h.Sync)
	_, err = r.db.ExecContext(ctx, `INSERT INTO sensor_metrics(sensor_id,recorded_at,uptime_seconds,health,metrics,versions,capture,sync) VALUES($1,NOW(),$2,$3,$4,$5,$6,$7)`, h.SensorID, h.Uptime, healthJSON, metricsJSON, versionsJSON, captureJSON, syncJSON)
	if err == nil {
		_, _ = r.db.ExecContext(ctx, `DELETE FROM sensor_metrics WHERE recorded_at < NOW() - INTERVAL '7 days'`)
	}
	return err
}
func healthFromSample(sample management.SensorMetricSample, lastSeen time.Time) (string, []string) {
	reasons := []string{}
	if time.Since(lastSeen) > 90*time.Second {
		return "offline", []string{"No recent heartbeat"}
	}
	number := func(path ...string) float64 {
		var current interface{} = sample.Metrics
		for _, key := range path {
			m, ok := current.(map[string]interface{})
			if !ok {
				return 0
			}
			current = m[key]
		}
		switch v := current.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		}
		return 0
	}
	drops := number("capture", "drop_rate_percent")
	mem := number("system", "memory_percent")
	queue := number("pipeline", "event_queue_percent")
	if drops >= 5 {
		reasons = append(reasons, fmt.Sprintf("Packet drop rate %.1f%%", drops))
	}
	if mem >= 95 {
		reasons = append(reasons, fmt.Sprintf("Memory usage %.1f%%", mem))
	}
	if queue >= 95 {
		reasons = append(reasons, fmt.Sprintf("Event queue %.1f%% full", queue))
	}
	if sample.Sync.ConsecutiveFailures >= 3 {
		reasons = append(reasons, "Repeated Central synchronization failures")
	}
	if len(reasons) > 0 {
		return "critical", reasons
	}
	if drops >= 1 {
		reasons = append(reasons, fmt.Sprintf("Packet drop rate %.1f%%", drops))
	}
	if mem >= 80 {
		reasons = append(reasons, fmt.Sprintf("Memory usage %.1f%%", mem))
	}
	if queue >= 75 {
		reasons = append(reasons, fmt.Sprintf("Event queue %.1f%% full", queue))
	}
	if sample.Sync.ConsecutiveFailures > 0 {
		reasons = append(reasons, "Central synchronization degraded")
	}
	if len(reasons) > 0 {
		return "warning", reasons
	}
	return "healthy", nil
}

func (r *Repository) SensorMetricHistory(ctx context.Context, sensorID string, since time.Time, limit int) ([]management.SensorMetricSample, error) {
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id,recorded_at,uptime_seconds,health,metrics,versions,capture,sync FROM sensor_metrics WHERE sensor_id=$1 AND recorded_at >= $2 ORDER BY recorded_at ASC LIMIT $3`, sensorID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []management.SensorMetricSample{}
	for rows.Next() {
		var x management.SensorMetricSample
		var health, metrics, versions, capture, sync []byte
		if err := rows.Scan(&x.SensorID, &x.RecordedAt, &x.UptimeSeconds, &health, &metrics, &versions, &capture, &sync); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(health, &x.Health)
		_ = json.Unmarshal(metrics, &x.Metrics)
		_ = json.Unmarshal(versions, &x.Versions)
		_ = json.Unmarshal(capture, &x.Capture)
		_ = json.Unmarshal(sync, &x.Sync)
		x.HealthState, x.HealthReasons = healthFromSample(x, x.RecordedAt)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (r *Repository) LatestSensorMetrics(ctx context.Context) ([]management.SensorMetricSample, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT ON (m.sensor_id) m.sensor_id,m.recorded_at,m.uptime_seconds,m.health,m.metrics,m.versions,m.capture,m.sync,s.last_seen FROM sensor_metrics m JOIN sensors s ON s.id=m.sensor_id ORDER BY m.sensor_id,m.recorded_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []management.SensorMetricSample{}
	for rows.Next() {
		var x management.SensorMetricSample
		var health, metrics, versions, capture, sync []byte
		var lastSeen time.Time
		if err := rows.Scan(&x.SensorID, &x.RecordedAt, &x.UptimeSeconds, &health, &metrics, &versions, &capture, &sync, &lastSeen); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(health, &x.Health)
		_ = json.Unmarshal(metrics, &x.Metrics)
		_ = json.Unmarshal(versions, &x.Versions)
		_ = json.Unmarshal(capture, &x.Capture)
		_ = json.Unmarshal(sync, &x.Sync)
		x.HealthState, x.HealthReasons = healthFromSample(x, lastSeen)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (r *Repository) SchemaVersion(ctx context.Context) int64 {
	var version int64
	if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		return 0
	}
	return version
}

func (r *Repository) ListSensors(ctx context.Context) ([]management.Sensor, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,name,COALESCE(site_id,''),status,version,hostname,last_seen,COALESCE(certificate_fingerprint,''),
COALESCE(go_version,''),COALESCE(libpcap_version,''),COALESCE(gopacket_version,''),COALESCE(capture_backend,''),
COALESCE(capture_interface,''),COALESCE(capture_snaplen,0),COALESCE(capture_promiscuous,FALSE),
last_heartbeat_at,last_sync_attempt_at,last_sync_success_at,last_data_received_at,COALESCE(sync_status,'unknown'),COALESCE(pending_records,0),COALESCE(sync_failures,0),COALESCE(last_sync_error,''),COALESCE(sync_sequence,0) FROM sensors ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.Sensor
	for rows.Next() {
		var s management.Sensor
		if err := rows.Scan(&s.ID, &s.Name, &s.SiteID, &s.Status, &s.Version, &s.Hostname, &s.LastSeen, &s.CertificateFingerprint,
			&s.GoVersion, &s.LibpcapVersion, &s.GopacketVersion, &s.CaptureBackend, &s.CaptureInterface, &s.CaptureSnaplen, &s.CapturePromiscuous, &s.LastHeartbeatAt, &s.LastSyncAttemptAt, &s.LastSyncSuccessAt, &s.LastDataReceivedAt, &s.SyncStatus, &s.PendingRecords, &s.SyncFailures, &s.LastSyncError, &s.SyncSequence); err != nil {
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

// MarkOffline flips status to 'offline' for any sensor whose last_seen
// is older than olderThan — but only ones not already offline, and
// returns exactly those ids. Both matter for auditing this: without the
// status!='offline' guard, a sensor that's been down for days would get
// "marked offline" (and audited) again on every single sweep interval,
// not just the one time it actually went down.
func (r *Repository) MarkOffline(ctx context.Context, olderThan time.Duration) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`UPDATE sensors SET status='offline' WHERE status != 'offline' AND last_seen < NOW() - ($1 * INTERVAL '1 second') RETURNING id`,
		int64(olderThan/time.Second),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// DeleteSensor removes a sensor's row and, via ON DELETE CASCADE on
// every sensor-scoped table's foreign key, everything derived from it:
// telemetry, topology history, alert history, analysis jobs, rule
// assignments, and pending commands. This is NOT a permanent ban on the
// sensor id — if that sensor is still running, the sensor notices that
// authenticated synchronization now returns 401, re-enrolls with the
// configured enrollment token, and register() recreates the row with a fresh
// per-sensor credential. Local SQLite is deliberately independent: its
// persisted telemetry may be uploaded again unless the sensor is reset too.
func (r *Repository) DeleteSensor(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sensors WHERE id=$1`, id)
	return err
}

func learningCompletionConfirmed(raw json.RawMessage) bool {
	var status struct {
		Enabled  bool   `json:"enabled"`
		Mode     string `json:"mode"`
		Behavior struct {
			Enabled bool   `json:"enabled"`
			Mode    string `json:"mode"`
		} `json:"behavior"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &status) != nil {
		return false
	}
	anyEnabled := status.Enabled || status.Behavior.Enabled
	legacyComplete := !status.Enabled || strings.EqualFold(strings.TrimSpace(status.Mode), "monitoring")
	behaviorComplete := !status.Behavior.Enabled || strings.EqualFold(strings.TrimSpace(status.Behavior.Mode), "monitoring")
	return anyEnabled && legacyComplete && behaviorComplete
}

type TelemetrySequenceConflictError struct {
	SensorID         string
	IncomingSequence int64
	CurrentSequence  int64
}

func (e *TelemetrySequenceConflictError) Error() string {
	return fmt.Sprintf("telemetry sequence conflict for %s: incoming=%d current=%d", e.SensorID, e.IncomingSequence, e.CurrentSequence)
}

func (r *Repository) PutTelemetry(ctx context.Context, x management.TelemetrySnapshot) ([]AlertHistoryEntry, error) {
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
		return nil, fmt.Errorf("begin telemetry transaction: %w", err)
	}
	defer tx.Rollback()

	// Serialize ingestion per sensor before looking at sequence state. A stale
	// packet must never run any of the derived-data side effects below (flow
	// deltas, topology ledgers, DNS/SMB/protocol history or alert history).
	// The advisory lock also covers the first-ever insert where there is no row
	// yet for SELECT ... FOR UPDATE to lock.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, x.SensorID); err != nil {
		return nil, fmt.Errorf("lock telemetry sequence: %w", err)
	}
	var currentSequence int64
	var currentChecksum string
	sequenceErr := tx.QueryRowContext(ctx, `SELECT sequence,checksum FROM sensor_telemetry WHERE sensor_id=$1 FOR UPDATE`, x.SensorID).Scan(&currentSequence, &currentChecksum)
	if sequenceErr != nil && !errors.Is(sequenceErr, sql.ErrNoRows) {
		return nil, fmt.Errorf("load telemetry sequence: %w", sequenceErr)
	}
	if sequenceErr == nil {
		if x.Sequence < currentSequence || (x.Sequence == currentSequence && !strings.EqualFold(strings.TrimSpace(x.Checksum), strings.TrimSpace(currentChecksum))) {
			return nil, &TelemetrySequenceConflictError{SensorID: x.SensorID, IncomingSequence: x.Sequence, CurrentSequence: currentSequence}
		}
		if x.Sequence == currentSequence {
			// Exact retry after Central committed but the sensor missed the HTTP
			// response. Acknowledge it without replaying any side effect.
			return nil, nil
		}
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO sensor_telemetry(sensor_id,captured_at,topology,tags,tag_changes,tag_events,alerts,baseline,rules,dns_observations,smb_observations,udp_conversations,udp_telemetry,udp_protocol_exchanges,batch_id,sequence,checksum,updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NOW()) ON CONFLICT(sensor_id) DO UPDATE SET captured_at=EXCLUDED.captured_at,topology=EXCLUDED.topology,tags=EXCLUDED.tags,tag_changes=EXCLUDED.tag_changes,tag_events=EXCLUDED.tag_events,alerts=EXCLUDED.alerts,baseline=EXCLUDED.baseline,rules=EXCLUDED.rules,dns_observations=EXCLUDED.dns_observations,smb_observations=EXCLUDED.smb_observations,udp_conversations=EXCLUDED.udp_conversations,udp_telemetry=EXCLUDED.udp_telemetry,udp_protocol_exchanges=EXCLUDED.udp_protocol_exchanges,batch_id=EXCLUDED.batch_id,sequence=EXCLUDED.sequence,checksum=EXCLUDED.checksum,updated_at=NOW()`, x.SensorID, x.CapturedAt, x.Topology, x.Tags, defaults(x.TagChanges, "[]"), defaults(x.TagEvents, "[]"), defaults(x.Alerts, "[]"), defaults(x.Baseline, "{}"), defaults(x.Rules, "[]"), defaults(x.DNSObservations, "[]"), defaults(x.SMBObservations, "[]"), defaults(x.UDPConversations, "[]"), defaults(x.UDPTelemetry, "{}"), defaults(x.UDPProtocolExchanges, "[]"), x.BatchID, x.Sequence, x.Checksum)
	if err != nil {
		return nil, fmt.Errorf("store telemetry snapshot: %w", err)
	}
	if learningCompletionConfirmed(x.Baseline) {
		if _, err := tx.ExecContext(ctx, `UPDATE sensor_commands SET delivered_at=NOW() WHERE sensor_id=$1 AND command_type='sensor.learning.complete' AND delivered_at IS NULL`, x.SensorID); err != nil {
			return nil, fmt.Errorf("acknowledge learning completion command: %w", err)
		}
	}
	var alerts []map[string]interface{}
	if r.siemAlertsEnabled && len(x.Alerts) > 0 && json.Unmarshal(x.Alerts, &alerts) == nil {
		for _, alert := range alerts {
			id := firstString(alert, "ID", "id")
			if id == "" {
				continue
			}
			// Hash the complete alert snapshot, not just Count/LastSeen/Status.
			// Evidence, severity or message can legitimately change without those
			// three fields changing; the old key silently suppressed such exports.
			alertPayload, marshalErr := json.Marshal(alert)
			if marshalErr != nil {
				return nil, marshalErr
			}
			versionHash := sha256.Sum256(alertPayload)
			eventKey := fmt.Sprintf("alert:%s:%s:%x", x.SensorID, id, versionHash[:])
			eventTime := siemAlertEventTime(alert, x.CapturedAt)
			source := r.siemSource
			if source == "" {
				source = "otlens-central"
			}
			envelope := map[string]interface{}{
				"schema_version": "otlens.siem.v1",
				"event_id":       eventKey,
				"source":         source,
				"kind":           "alert",
				"event_time":     eventTime,
				"sensor_id":      x.SensorID,
				"alert":          alert,
			}
			payload, marshalErr := json.Marshal(envelope)
			if marshalErr != nil {
				return nil, marshalErr
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO siem_outbox(event_key,kind,payload) VALUES($1,'alert',$2) ON CONFLICT(event_key) DO NOTHING`, eventKey, payload); err != nil {
				return nil, fmt.Errorf("queue SIEM alert: %w", err)
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sensors SET last_data_received_at=NOW(),last_sync_success_at=NOW(),sync_status='healthy',pending_records=0,sync_failures=0,last_sync_error='',sync_sequence=GREATEST(sync_sequence,$2) WHERE id=$1`, x.SensorID, x.Sequence); err != nil {
		return nil, fmt.Errorf("update sensor sync state: %w", err)
	}
	// Fold this sync's nodes/edges into the durable per-sensor ledgers
	// (see topology_edges.go) before committing, so it's atomic with the
	// rest of the sync — a failed upsert here rolls back the whole
	// telemetry write rather than silently skipping just the topology
	// history. Nodes must go in before edges are read back out by
	// buildTopologyResponse matters less here (both land in this same
	// transaction), but nodes are upserted first on principle: an edge
	// whose endpoint isn't in the node ledger yet is still fine to have
	// on record, since ListTopologyNodes is a superset fill-in, not a
	// strict foreign key.
	var graph topology.Graph
	if len(x.Topology) > 0 {
		if err := json.Unmarshal(x.Topology, &graph); err != nil {
			return nil, fmt.Errorf("decode topology: %w", err)
		}
		if err := persistFlowObservations(ctx, tx, x.SensorID, x.CapturedAt, graph.Edges); err != nil {
			return nil, fmt.Errorf("persist flow observations: %w", err)
		}
		if err := upsertTopologyNodes(ctx, tx, x.SensorID, graph.Nodes); err != nil {
			return nil, fmt.Errorf("persist topology nodes: %w", err)
		}
		if err := upsertTopologyEdges(ctx, tx, x.SensorID, aggregateEdges(graph.Edges)); err != nil {
			return nil, fmt.Errorf("persist topology edges: %w", err)
		}

		// asset.confirm / asset.delete remain pending across command pulls until
		// this authoritative full asset snapshot proves that the requested state
		// actually exists on the sensor. This prevents a dropped /sync response or
		// a process crash between pull and ApplyCommand from losing the action.
		presentMACs := make([]string, 0, len(graph.Nodes))
		confirmedMACs := make([]string, 0, len(graph.Nodes))
		for _, node := range graph.Nodes {
			mac := strings.ToLower(strings.TrimSpace(node.MAC))
			if mac == "" {
				continue
			}
			presentMACs = append(presentMACs, mac)
			if node.Confirmed {
				confirmedMACs = append(confirmedMACs, mac)
			}
		}
		if len(confirmedMACs) > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE sensor_commands SET delivered_at=NOW() WHERE sensor_id=$1 AND command_type='asset.confirm' AND delivered_at IS NULL AND lower(target)=ANY($2::text[])`, x.SensorID, confirmedMACs); err != nil {
				return nil, fmt.Errorf("acknowledge asset confirm commands: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE sensor_commands SET delivered_at=NOW() WHERE sensor_id=$1 AND command_type='asset.delete' AND delivered_at IS NULL AND NOT(lower(target)=ANY($2::text[]))`, x.SensorID, presentMACs); err != nil {
			return nil, fmt.Errorf("acknowledge asset delete commands: %w", err)
		}
	}
	if err := persistDNSObservations(ctx, tx, x.SensorID, x.DNSObservations); err != nil {
		return nil, fmt.Errorf("persist DNS observations: %w", err)
	}
	if err := persistSMBObservations(ctx, tx, x.SensorID, x.SMBObservations); err != nil {
		return nil, fmt.Errorf("persist SMB observations: %w", err)
	}
	if err := persistProtocolObservations(ctx, tx, x.SensorID, x.ProtocolObservations); err != nil {
		return nil, fmt.Errorf("persist protocol observations: %w", err)
	}
	newAlerts, err := upsertAlertHistory(ctx, tx, x.SensorID, x.Alerts)
	if err != nil {
		return nil, fmt.Errorf("persist alert history: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit telemetry transaction: %w", err)
	}
	return newAlerts, nil
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
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id,captured_at,topology,tags,tag_changes,tag_events,alerts,baseline,rules,dns_observations,smb_observations,udp_conversations,udp_telemetry,udp_protocol_exchanges,batch_id,sequence,checksum FROM sensor_telemetry ORDER BY sensor_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.TelemetrySnapshot
	for rows.Next() {
		var x management.TelemetrySnapshot
		if err := rows.Scan(&x.SensorID, &x.CapturedAt, &x.Topology, &x.Tags, &x.TagChanges, &x.TagEvents, &x.Alerts, &x.Baseline, &x.Rules, &x.DNSObservations, &x.SMBObservations, &x.UDPConversations, &x.UDPTelemetry, &x.UDPProtocolExchanges, &x.BatchID, &x.Sequence, &x.Checksum); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// TelemetryFingerprint returns each sensor's current telemetry sequence
// number without touching any of the (potentially large) JSONB columns.
// Handlers that serve a derived/aggregated view — like /topology — use
// this to cheaply detect "nothing changed since last time" before paying
// for a full topology fetch + JSON decode. Ordered by sensor_id so the
// result is stable and directly hashable.
func (r *Repository) TelemetryFingerprint(ctx context.Context) (map[string]int64, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id, sequence FROM sensor_telemetry ORDER BY sensor_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var id string
		var seq int64
		if err := rows.Scan(&id, &seq); err != nil {
			return nil, err
		}
		out[id] = seq
	}
	return out, rows.Err()
}

// TopologyRow is the minimal per-sensor payload the /topology handler
// needs: just enough to rebuild the aggregated graph, without pulling the
// tags/alerts/baseline/rules columns that other endpoints care about.
type TopologyRow struct {
	SensorID string
	Topology json.RawMessage
}

func (r *Repository) TelemetryTopology(ctx context.Context) ([]TopologyRow, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id, topology FROM sensor_telemetry ORDER BY sensor_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TopologyRow
	for rows.Next() {
		var x TopologyRow
		if err := rows.Scan(&x.SensorID, &x.Topology); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (r *Repository) QueueCommands(ctx context.Context, sensorID, typ string, targets []string) error {
	clean := make([]string, 0, len(targets))
	for _, t := range targets {
		if t != "" {
			clean = append(clean, t)
		}
	}
	if len(clean) == 0 {
		return nil
	}
	// One round trip regardless of how many targets — unnest() expands
	// the array into rows server-side. The naive "one INSERT per target"
	// loop this replaced took whole seconds-to-minutes (visible as "did
	// this even do anything?" in the UI) once someone selected a
	// realistic bulk-action count (thousands of alerts, say), since each
	// row was its own network round trip to Postgres.
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sensor_commands(sensor_id,command_type,target) SELECT $1, $2, unnest($3::text[])`,
		sensorID, typ, clean,
	)
	return err
}
func (r *Repository) HasPendingDataReset(ctx context.Context, sensorID string) (bool, error) {
	var pending bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sensor_commands WHERE sensor_id=$1 AND delivered_at IS NULL AND command_type LIKE 'sensor.%.reset')`, sensorID).Scan(&pending)
	return pending, err
}

func (r *Repository) HasPendingCommand(ctx context.Context, sensorID, commandType string) (bool, error) {
	var pending bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sensor_commands WHERE sensor_id=$1 AND command_type=$2 AND delivered_at IS NULL)`, sensorID, commandType).Scan(&pending)
	return pending, err
}

func (r *Repository) PendingCommandSensors(ctx context.Context, commandType string) (map[string]bool, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT sensor_id FROM sensor_commands WHERE command_type=$1 AND delivered_at IS NULL`, commandType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var sensorID string
		if err := rows.Scan(&sensorID); err != nil {
			return nil, err
		}
		out[sensorID] = true
	}
	return out, rows.Err()
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
		// State-changing commands whose success is visible in telemetry are not
		// acknowledged merely because the sensor downloaded them. They are
		// idempotently replayed until a later telemetry snapshot proves the desired
		// state. This closes the pull/apply/network-crash window for learning and
		// asset confirm/delete operations.
		switch c.Type {
		case "sensor.learning.complete", "asset.confirm", "asset.delete":
		default:
			ids = append(ids, c.ID)
		}
	}
	rows.Close()
	if len(ids) > 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE sensor_commands SET delivered_at=NOW() WHERE id = ANY($1)`, ids); err != nil {
			return nil, err
		}
		for _, command := range out {
			if command.Type != "recon.safe_discovery" {
				continue
			}
			var payload struct {
				JobID string `json:"job_id"`
			}
			if json.Unmarshal([]byte(command.Target), &payload) == nil && payload.JobID != "" {
				if _, err = tx.ExecContext(ctx, `UPDATE reconnaissance_jobs SET status='running',started_at=COALESCE(started_at,NOW()) WHERE id=$1 AND status='queued'`, payload.JobID); err != nil {
					return nil, err
				}
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func siemAlertEventTime(alert map[string]interface{}, fallback time.Time) time.Time {
	for _, key := range []string{"LastSeen", "last_seen", "FirstSeen", "first_seen"} {
		value, ok := alert[key]
		if !ok {
			continue
		}
		switch x := value.(type) {
		case string:
			if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(x)); err == nil {
				return parsed.UTC()
			}
		case time.Time:
			if !x.IsZero() {
				return x.UTC()
			}
		}
	}
	if fallback.IsZero() {
		return time.Now().UTC()
	}
	return fallback.UTC()
}

type SIEMOutboxEvent struct {
	ID       int64
	EventKey string
	Kind     string
	Payload  json.RawMessage
	Attempts int
}

type SIEMQueueStats struct {
	Queued          int64      `json:"queued"`
	Ready           int64      `json:"ready"`
	Failed          int64      `json:"failed"`
	Exhausted       int64      `json:"exhausted"`
	OldestCreatedAt *time.Time `json:"oldest_created_at,omitempty"`
}

// GetSIEMQueueStats makes delivery failures observable instead of silently
// leaving max-attempt-exhausted events in the outbox forever. Exhausted rows
// are retained as a dead-letter queue until an operator resets/reconfigures
// SIEM; they are never reported as delivered.
func (r *Repository) GetSIEMQueueStats(ctx context.Context, maxAttempts int) (SIEMQueueStats, error) {
	var out SIEMQueueStats
	var oldest sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE next_attempt_at <= NOW() AND ($1 <= 0 OR attempts < $1)),
		       COUNT(*) FILTER (WHERE last_error <> ''),
		       COUNT(*) FILTER (WHERE $1 > 0 AND attempts >= $1),
		       MIN(created_at)
		FROM siem_outbox`, maxAttempts).Scan(&out.Queued, &out.Ready, &out.Failed, &out.Exhausted, &oldest)
	if err != nil {
		return SIEMQueueStats{}, err
	}
	if oldest.Valid {
		t := oldest.Time.UTC()
		out.OldestCreatedAt = &t
	}
	return out, nil
}

func (r *Repository) EnqueueSIEM(ctx context.Context, eventKey, kind string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO siem_outbox(event_key,kind,payload) VALUES($1,$2,$3) ON CONFLICT(event_key) DO NOTHING`, eventKey, kind, data)
	return err
}

func (r *Repository) PendingSIEM(ctx context.Context, limit, maxAttempts int, exportAlerts, exportAudit bool) ([]SIEMOutboxEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	enabledKinds := make([]string, 0, 2)
	if exportAlerts {
		enabledKinds = append(enabledKinds, "alert")
	}
	if exportAudit {
		enabledKinds = append(enabledKinds, "audit")
	}
	if len(enabledKinds) == 0 {
		return nil, nil
	}
	query := `SELECT id,event_key,kind,payload,attempts FROM siem_outbox WHERE delivered_at IS NULL AND next_attempt_at <= NOW()`
	args := []interface{}{}
	if len(enabledKinds) == 1 {
		args = append(args, enabledKinds[0])
		query += ` AND kind = $` + fmt.Sprint(len(args))
	} else {
		query += ` AND kind IN ('alert','audit')`
	}
	if maxAttempts > 0 {
		args = append(args, maxAttempts)
		query += ` AND attempts < $` + fmt.Sprint(len(args))
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
		if err := rows.Scan(&e.ID, &e.EventKey, &e.Kind, &e.Payload, &e.Attempts); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *Repository) MarkSIEMDelivered(ctx context.Context, id int64) error {
	// siem_outbox is a delivery queue, not history. Audit history lives in
	// audit_log and alerts in alert_history; retaining delivered queue rows only
	// causes unbounded growth. Delete an acknowledged row immediately.
	_, err := r.db.ExecContext(ctx, `DELETE FROM siem_outbox WHERE id=$1`, id)
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

func (r *Repository) ResetCentral(ctx context.Context, operation, bootstrapUsername, bootstrapPasswordHash string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Data Management resets are deliberately explicit. Authentication,
	// sensors/sites and operator configuration are control-plane state and are
	// never part of a Central data reset.
	switch operation {
	case "telemetry", "database":
		_, err = tx.ExecContext(ctx, `TRUNCATE sensor_telemetry, sensor_metrics, protocol_observations, dns_observations, smb_observations, flow_counters, flow_observations, topology_edges, topology_nodes, asset_identity_history, asset_risk, asset_risk_history RESTART IDENTITY`)
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE sensors SET last_data_received_at=NULL,last_sync_success_at=NULL,pending_records=0,sync_failures=0,last_sync_error='',sync_sequence=0,sync_status='reset'`)
		}
	case "alerts":
		_, err = tx.ExecContext(ctx, `TRUNCATE alert_history, asset_risk, asset_risk_history RESTART IDENTITY`)
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE sensor_telemetry SET alerts='[]'::jsonb,updated_at=NOW()`)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM siem_outbox WHERE kind='alert'`)
		}
	case "incidents":
		// Keep alert history, but clear every incident/investigation object.
		_, err = tx.ExecContext(ctx, `TRUNCATE incident_comments, incident_events, incidents, asset_exposures, malware_incidents RESTART IDENTITY`)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO central_runtime_state(key,value,updated_at) VALUES('incident_correlation_cutoff',NOW()::text,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()`)
		}
	case "siem":
		_, err = tx.ExecContext(ctx, `TRUNCATE siem_outbox RESTART IDENTITY`)
	case "analysis":
		_, err = tx.ExecContext(ctx, `TRUNCATE analysis_jobs RESTART IDENTITY`)
	case "rules":
		_, err = tx.ExecContext(ctx, `TRUNCATE sensor_rule_sets, rule_sets`)
	case "factory":
		// Full Central data reset: wipe observed/derived/history data while
		// preserving users/roles/sessions, sensor/site enrollment and operator
		// configuration such as VLANs, asset context, risk settings, correlation
		// rules, TI sources and vulnerability advisory catalog.
		_, err = tx.ExecContext(ctx, `TRUNCATE
			incident_comments, incident_events, incidents,
			asset_exposures, malware_incidents,
			reconnaissance_results, asset_recon_history, reconnaissance_jobs, asset_recon_profile,
			sensor_telemetry, sensor_metrics,
			protocol_observations, dns_observations, smb_observations,
			flow_counters, flow_observations,
			topology_edges, topology_nodes, asset_identity_history,
			alert_history, asset_risk, asset_risk_history,
			asset_security_status, vulnerability_findings,
			analysis_jobs, siem_outbox, report_history,
			sensor_rule_sets, rule_sets, imported_tags
			RESTART IDENTITY`)
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE sensors SET last_data_received_at=NULL,last_sync_success_at=NULL,pending_records=0,sync_failures=0,last_sync_error='',sync_sequence=0,sync_status='reset'`)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE reconnaissance_campaigns SET last_run_at=NULL`)
		}
		if err == nil {
			// Preserve the just-queued sensor reset commands, but discard stale
			// operational commands from the pre-reset data plane.
			_, err = tx.ExecContext(ctx, `DELETE FROM sensor_commands WHERE command_type NOT LIKE 'sensor.%.reset' OR delivered_at IS NOT NULL`)
		}
		if err == nil {
			// Alert history is empty after a full reset, so no correlation cutoff
			// is needed. Leaving it absent also avoids sensor/Central clock skew
			// suppressing genuinely new post-reset alerts.
			_, err = tx.ExecContext(ctx, `DELETE FROM central_runtime_state`)
		}
	default:
		return fmt.Errorf("unsupported central reset operation %q", operation)
	}
	if err != nil {
		return err
	}

	// Authentication defaults are part of the same transaction. If preservation
	// cannot be verified, rollback the destructive reset.
	if err := ensureAuthBootstrap(ctx, tx, bootstrapUsername, bootstrapPasswordHash); err != nil {
		return fmt.Errorf("preserve authentication defaults: %w", err)
	}
	return tx.Commit()
}

// ResetSensors removes the matching Central-side mirror for selected sensors.
// The caller separately queues the same local reset on each sensor.
func (r *Repository) ResetSensors(ctx context.Context, operation string, sensorIDs []string) error {
	clean := make([]string, 0, len(sensorIDs))
	for _, id := range sensorIDs {
		if id = strings.TrimSpace(id); id != "" {
			clean = append(clean, id)
		}
	}
	if len(clean) == 0 {
		return fmt.Errorf("sensor ids are required")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	exec := func(q string) error {
		_, e := tx.ExecContext(ctx, q, clean)
		return e
	}
	clearTelemetry := func() error {
		queries := []string{
			`DELETE FROM sensor_metrics WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM protocol_observations WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM dns_observations WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM smb_observations WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM flow_counters WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM flow_observations WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM topology_edges WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM topology_nodes WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_identity_history WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_risk WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_risk_history WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM sensor_telemetry WHERE sensor_id=ANY($1::text[])`,
		}
		for _, q := range queries {
			if err := exec(q); err != nil {
				return err
			}
		}
		_, e := tx.ExecContext(ctx, `UPDATE sensors SET last_data_received_at=NULL,last_sync_success_at=NULL,pending_records=0,sync_failures=0,last_sync_error='',sync_sequence=0,sync_status='reset' WHERE id=ANY($1::text[])`, clean)
		return e
	}
	clearAlerts := func() error {
		for _, q := range []string{
			`DELETE FROM alert_history WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_risk WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_risk_history WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM siem_outbox WHERE kind='alert' AND payload->>'sensor_id'=ANY($1::text[])`,
			`UPDATE sensor_telemetry SET alerts='[]'::jsonb,updated_at=NOW() WHERE sensor_id=ANY($1::text[])`,
		} {
			if err := exec(q); err != nil {
				return err
			}
		}
		return nil
	}
	clearIncidents := func() error {
		// incident child rows cascade from both incident tables.
		if err := exec(`DELETE FROM incidents WHERE sensor_id=ANY($1::text[])`); err != nil {
			return err
		}
		return exec(`DELETE FROM malware_incidents WHERE sensor_id=ANY($1::text[])`)
	}

	switch operation {
	case "telemetry":
		err = clearTelemetry()
	case "assets":
		for _, q := range []string{
			`DELETE FROM flow_counters WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM flow_observations WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM topology_edges WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM topology_nodes WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_identity_history WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_risk WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_risk_history WHERE sensor_id=ANY($1::text[])`,
			`UPDATE sensor_telemetry SET topology='{"Nodes":[],"Edges":[],"HoneypotThreshold":10}'::jsonb,udp_conversations='[]'::jsonb,updated_at=NOW() WHERE sensor_id=ANY($1::text[])`,
		} {
			if err = exec(q); err != nil {
				break
			}
		}
	case "alerts":
		err = clearAlerts()
	case "tags":
		for _, q := range []string{
			`DELETE FROM imported_tags WHERE sensor_id=ANY($1::text[])`,
			`UPDATE sensor_telemetry SET tags='[]'::jsonb,tag_changes='[]'::jsonb,tag_events='[]'::jsonb,updated_at=NOW() WHERE sensor_id=ANY($1::text[])`,
		} {
			if err = exec(q); err != nil {
				break
			}
		}
	case "learning":
		err = exec(`UPDATE sensor_telemetry SET baseline='{}'::jsonb,updated_at=NOW() WHERE sensor_id=ANY($1::text[])`)
	case "analysis":
		// Some Central mirror tables predate explicit FromAnalysis provenance.
		// Clear the sensor's derived protocol/flow/topology mirror as a safe
		// superset; live capture repopulates it, while stale PCAP evidence cannot
		// survive an Analysis reset.
		for _, q := range []string{
			`DELETE FROM analysis_jobs WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM protocol_observations WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM dns_observations WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM smb_observations WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM flow_counters WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM flow_observations WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM topology_edges WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM topology_nodes WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_identity_history WHERE sensor_id=ANY($1::text[])`,
		} {
			if err = exec(q); err != nil {
				break
			}
		}
	case "rules":
		err = exec(`DELETE FROM sensor_rule_sets WHERE sensor_id=ANY($1::text[])`)
	case "database":
		if err = clearTelemetry(); err == nil {
			err = clearAlerts()
		}
		if err == nil {
			err = clearIncidents()
		}
	case "factory":
		if err = clearTelemetry(); err == nil {
			err = clearAlerts()
		}
		if err == nil {
			err = clearIncidents()
		}
		for _, q := range []string{
			`DELETE FROM sensor_rule_sets WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM analysis_jobs WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM reconnaissance_jobs WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_recon_profile WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM asset_security_status WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM vulnerability_findings WHERE sensor_id=ANY($1::text[])`,
			`DELETE FROM imported_tags WHERE sensor_id=ANY($1::text[])`,
			`UPDATE reconnaissance_campaigns SET last_run_at=NULL WHERE sensor_id=ANY($1::text[])`,
		} {
			if err == nil {
				err = exec(q)
			}
		}
	default:
		err = fmt.Errorf("unsupported sensor reset operation %q", operation)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) AnalysisPathsForSensors(ctx context.Context, sensorIDs []string) ([]string, error) {
	if len(sensorIDs) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT stored_path FROM analysis_jobs WHERE sensor_id=ANY($1::text[])`, sensorIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		out = append(out, path)
	}
	return out, rows.Err()
}

func (r *Repository) CreateCentralBackup(ctx context.Context, id, name string) (BackupRecord, error) {
	// A core snapshot spans many tables. Read them under one repeatable-read
	// transaction so a concurrent telemetry sync cannot make the export contain
	// sensors from one point in time and alerts/incidents from another.
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return BackupRecord{}, err
	}
	defer tx.Rollback()
	generatedAt := time.Now().UTC()
	payload := map[string]json.RawMessage{}
	manifest, err := json.Marshal(map[string]interface{}{
		"format":         "otlens-central-core-snapshot",
		"schema_version": 2,
		"generated_at":   generatedAt,
		"scope": []string{
			"sites", "safe sensor enrollment metadata", "managed rules and assignments", "latest sensor telemetry",
			"asset identity and operator-owned asset/Purdue policy", "alert history", "managed incidents and incident events/comments", "correlation rules", "report history", "pending SIEM outbox",
		},
		"excluded": []string{
			"user password hashes and sessions", "sensor auth-token hashes", "reconnaissance credentials",
			"high-volume DNS/SMB/protocol/flow observation history", "uploaded PCAP file contents",
		},
		"note": "This JSON is an operational/core snapshot, not a full PostgreSQL dump. Use pg_dump for full database backup/restore.",
	})
	if err != nil {
		return BackupRecord{}, err
	}
	payload["_manifest"] = manifest
	queries := map[string]string{
		"sites": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM sites ORDER BY id) t`,
		// Never export auth_token_hash in a downloadable JSON snapshot. The
		// enrollment identity/status metadata is useful operationally; the bearer
		// verifier is authentication material and belongs only in a real protected
		// PostgreSQL backup.
		"sensors": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (
			SELECT id,name,site_id,status,version,hostname,certificate_fingerprint,auth_token_rotated_at,
			       go_version,libpcap_version,gopacket_version,capture_backend,capture_interface,capture_snaplen,
			       capture_promiscuous,last_heartbeat_at,last_sync_attempt_at,last_sync_success_at,last_data_received_at,
			       sync_status,pending_records,sync_failures,last_sync_error,sync_sequence,last_seen
			FROM sensors ORDER BY id
		) t`,
		"rule_sets":              `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM rule_sets ORDER BY id) t`,
		"sensor_rule_sets":       `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM sensor_rule_sets ORDER BY sensor_id) t`,
		"sensor_telemetry":       `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM sensor_telemetry ORDER BY sensor_id) t`,
		"asset_identity_history": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM asset_identity_history ORDER BY sensor_id,asset_identity,last_seen) t`,
		"asset_context":          `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM asset_context ORDER BY sensor_id,asset_identity,updated_at) t`,
		"asset_overrides":        `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM asset_overrides ORDER BY sensor_id,mac) t`,
		"vlan_config":            `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM vlan_config ORDER BY sensor_id,vlan_id) t`,
		"segmentation_settings":  `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM segmentation_settings ORDER BY sensor_id) t`,
		"asset_security_status":  `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM asset_security_status ORDER BY sensor_id,asset_identity,updated_at) t`,
		"asset_risk_exceptions":  `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM asset_risk_exceptions ORDER BY sensor_id,asset_identity,updated_at) t`,
		"vulnerability_findings": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM vulnerability_findings ORDER BY sensor_id,asset_identity,cve_id) t`,
		"alert_history":          `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM alert_history ORDER BY sensor_id,alert_key) t`,
		"incidents":              `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM incidents ORDER BY id) t`,
		"incident_events":        `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (SELECT * FROM incident_events ORDER BY id) t`,
		"incident_comments": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (
			SELECT * FROM incident_comments ORDER BY id
		) t`,
		"correlation_rules": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (
			SELECT * FROM correlation_rules ORDER BY id
		) t`,
		"report_history": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (
			SELECT * FROM report_history ORDER BY generated_at,id
		) t`,
		"siem_outbox": `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (
			SELECT id,event_key,kind,payload,created_at,next_attempt_at,attempts,last_error
			FROM siem_outbox WHERE delivered_at IS NULL ORDER BY id
		) t`,
	}
	for key, q := range queries {
		var raw []byte
		if err := tx.QueryRowContext(ctx, q).Scan(&raw); err != nil {
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
		name = "central-core-" + generatedAt.Format("20060102-150405")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO system_backups(id,kind,name,payload,size_bytes,sha256,created_at) VALUES($1,'central',$2,$3,$4,$5,$6)`, id, name, data, len(data), sum, generatedAt)
	if err != nil {
		return BackupRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return BackupRecord{}, err
	}
	return BackupRecord{ID: id, Kind: "central", Name: name, SizeBytes: int64(len(data)), SHA256: sum, CreatedAt: generatedAt}, nil
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
	var name, expected string
	if err := r.db.QueryRowContext(ctx, `SELECT payload,name,sha256 FROM system_backups WHERE id=$1`, id).Scan(&b, &name, &expected); err != nil {
		return nil, "", err
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(b))
	if !strings.EqualFold(strings.TrimSpace(expected), actual) {
		return nil, "", fmt.Errorf("backup integrity check failed for %s", id)
	}
	return b, name, nil
}
