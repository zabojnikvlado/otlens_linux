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
CREATE INDEX IF NOT EXISTS sensors_last_seen_idx ON sensors(last_seen);

CREATE TABLE IF NOT EXISTS sensor_telemetry (
 sensor_id TEXT PRIMARY KEY REFERENCES sensors(id) ON DELETE CASCADE,
 captured_at TIMESTAMPTZ NOT NULL,
 topology JSONB NOT NULL DEFAULT '{"Nodes":[],"Edges":[],"HoneypotThreshold":10}'::jsonb,
 tags JSONB NOT NULL DEFAULT '[]'::jsonb,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sensor_telemetry_captured_at_idx ON sensor_telemetry(captured_at);
