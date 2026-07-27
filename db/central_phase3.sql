-- OTLens Central PostgreSQL schema.
--
-- This file is a reference for manual/clean-install use. It is NOT executed
-- by otlens-central at runtime — internal/central/repository.go embeds the
-- authoritative schema (CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN
-- IF NOT EXISTS) and applies it automatically on every startup, so the
-- binary can bootstrap against a brand-new empty database without this file
-- ever being run. Keep the two in sync when either changes; this file
-- should always be a snapshot of what repository.go's schema string creates.
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
CREATE INDEX IF NOT EXISTS sensors_last_seen_idx ON sensors(last_seen);
CREATE INDEX IF NOT EXISTS sensor_telemetry_captured_at_idx ON sensor_telemetry(captured_at);
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS tag_changes JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS tag_events JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS alerts JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS baseline JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS rules JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS batch_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS sequence BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sensor_telemetry ADD COLUMN IF NOT EXISTS checksum TEXT NOT NULL DEFAULT '';
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
 PRIMARY KEY (sensor_id, ip)
);
-- Durable, one-row-per-alert history, independent of sensor_telemetry.alerts
-- (which is a single JSONB array per sensor, wholesale-overwritten on every
-- sync — no per-alert timestamp to prune by). Upserted from that JSONB on
-- every PutTelemetry, same pattern as topology_edges/topology_nodes. This is
-- what database_retention.alerts_days actually prunes; it does not replace
-- the live Alerts tab, which still reads the current sensor_telemetry.alerts
-- snapshot.
CREATE TABLE IF NOT EXISTS alert_history (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 alert_key TEXT NOT NULL,
 type TEXT NOT NULL,
 severity TEXT NOT NULL,
 message TEXT NOT NULL,
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
ALTER TABLE alert_history ADD COLUMN IF NOT EXISTS count BIGINT NOT NULL DEFAULT 1;

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
 generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_report_history_generated_at ON report_history(generated_at);
-- Manual/imported category+name overrides for the Devices tab — see
-- internal/central/devices.go. Never touched by any sensor sync; this
-- is purely operator input (either one-by-one from the Devices tab, or
-- bulk via CSV import) and always wins over the automatic vendor-based
-- category guess for a given (sensor_id, mac).
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
 vlan_id INTEGER NOT NULL,
 name TEXT NOT NULL DEFAULT '',
 purdue_level REAL,
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
 max_level_jump REAL NOT NULL DEFAULT 1,
 updated_by TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
