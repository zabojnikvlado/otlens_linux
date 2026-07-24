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
CREATE INDEX IF NOT EXISTS sensors_last_seen_idx ON sensors(last_seen);

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
CREATE INDEX IF NOT EXISTS sensor_telemetry_captured_at_idx ON sensor_telemetry(captured_at);

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
