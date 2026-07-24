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

ALTER TABLE sensors ADD COLUMN IF NOT EXISTS go_version TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS libpcap_version TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS gopacket_version TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_backend TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_interface TEXT NOT NULL DEFAULT '';
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_snaplen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS capture_promiscuous BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS sensors_last_seen_idx ON sensors(last_seen);

CREATE TABLE IF NOT EXISTS sensor_telemetry (
 sensor_id TEXT PRIMARY KEY REFERENCES sensors(id) ON DELETE CASCADE,
 captured_at TIMESTAMPTZ NOT NULL,
 topology JSONB NOT NULL DEFAULT '{"Nodes":[],"Edges":[],"HoneypotThreshold":10}'::jsonb,
 tags JSONB NOT NULL DEFAULT '[]'::jsonb,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sensor_telemetry_captured_at_idx ON sensor_telemetry(captured_at);

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
