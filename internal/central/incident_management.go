package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const incidentManagementSchema = `
CREATE TABLE IF NOT EXISTS incidents (
 id BIGSERIAL PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_ip TEXT NOT NULL DEFAULT '',
 title TEXT NOT NULL DEFAULT '',
 severity TEXT NOT NULL DEFAULT 'medium',
 score INTEGER NOT NULL DEFAULT 0,
 confidence INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'new',
 owner TEXT NOT NULL DEFAULT '',
 summary TEXT NOT NULL DEFAULT '',
 first_seen TIMESTAMPTZ NOT NULL,
 last_seen TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
DROP INDEX IF EXISTS idx_incidents_open_asset;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlation_rule_id BIGINT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlation_rule_name TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_tactics TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_techniques TEXT NOT NULL DEFAULT '';
DROP INDEX IF EXISTS idx_incidents_open_asset_rule;
CREATE UNIQUE INDEX idx_incidents_open_asset_rule ON incidents(sensor_id,asset_ip,COALESCE(correlation_rule_id,0)) WHERE status IN ('new','investigating','contained');
CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status_score_updated ON incidents(status,score DESC,updated_at DESC);
CREATE TABLE IF NOT EXISTS incident_events (
 id BIGSERIAL PRIMARY KEY,
 incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
 event_type TEXT NOT NULL,
 source_key TEXT NOT NULL DEFAULT '',
 severity TEXT NOT NULL DEFAULT '',
 message TEXT NOT NULL DEFAULT '',
 event_at TIMESTAMPTZ NOT NULL,
 metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(incident_id,event_type,source_key)
);
CREATE TABLE IF NOT EXISTS incident_comments (
 id BIGSERIAL PRIMARY KEY,
 incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
 actor TEXT NOT NULL DEFAULT '',
 body TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS correlation_rules (
 id BIGSERIAL PRIMARY KEY,
 name TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL DEFAULT '',
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 window_minutes INTEGER NOT NULL DEFAULT 60,
 min_events INTEGER NOT NULL DEFAULT 2,
 required_types JSONB NOT NULL DEFAULT '[]'::jsonb,
 sequence_types JSONB NOT NULL DEFAULT '[]'::jsonb,
 severity TEXT NOT NULL DEFAULT 'high',
 score_weight INTEGER NOT NULL DEFAULT 20,
 confidence_weight INTEGER NOT NULL DEFAULT 15,
 mitre_tactics JSONB NOT NULL DEFAULT '[]'::jsonb,
 mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
 builtin BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO correlation_rules(name,description,window_minutes,min_events,required_types,sequence_types,severity,score_weight,confidence_weight,mitre_tactics,mitre_techniques,builtin) VALUES
('Multi-stage activity','Multiple distinct detections against one asset',1440,2,'[]','[]','high',20,15,'["TA0001","TA0008"]','[]',TRUE),
('IOC followed by lateral movement','Threat-intelligence hit followed by SMB or lateral-movement activity',120,2,'["threat_intel"]','["threat_intel","lateral_movement"]','critical',35,25,'["TA0011","TA0008"]','["T1021"]',TRUE),
('Reconnaissance to exploitation','Reconnaissance followed by exploitation or anomalous OT activity',60,2,'["reconnaissance"]','["reconnaissance","ot_value_anomaly"]','high',30,20,'["TA0043","TA0002"]','[]',TRUE),
('Network Behavior Analytics','High-confidence behavior findings promoted by the sensor NBA pipeline',30,1,'["behavior_incident_candidate"]','[]','high',0,0,'["TA0001"]','[]',TRUE)
ON CONFLICT(name) DO NOTHING;
CREATE TABLE IF NOT EXISTS asset_risk (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_ip TEXT NOT NULL,
 score INTEGER NOT NULL DEFAULT 0,
 technical_score INTEGER NOT NULL DEFAULT 0,
 contextual_score INTEGER NOT NULL DEFAULT 0,
 propagated_score INTEGER NOT NULL DEFAULT 0,
 level TEXT NOT NULL DEFAULT 'low',
 trend TEXT NOT NULL DEFAULT 'stable',
 reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
 recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(sensor_id,asset_ip)
);
ALTER TABLE asset_risk ADD COLUMN IF NOT EXISTS technical_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE asset_risk ADD COLUMN IF NOT EXISTS contextual_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE asset_risk ADD COLUMN IF NOT EXISTS propagated_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE asset_risk ADD COLUMN IF NOT EXISTS trend TEXT NOT NULL DEFAULT 'stable';
ALTER TABLE asset_risk ADD COLUMN IF NOT EXISTS recommendations JSONB NOT NULL DEFAULT '[]'::jsonb;
CREATE TABLE IF NOT EXISTS asset_risk_history (
 id BIGSERIAL PRIMARY KEY,
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_ip TEXT NOT NULL,
 score INTEGER NOT NULL,
 level TEXT NOT NULL,
 reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_risk_history_asset ON asset_risk_history(sensor_id,asset_ip,recorded_at DESC);
CREATE TABLE IF NOT EXISTS asset_risk_exceptions (
 sensor_id TEXT NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
 asset_ip TEXT NOT NULL,
 asset_identity TEXT NOT NULL,
 disposition TEXT NOT NULL DEFAULT 'none',
 score_override INTEGER,
 compensating_control TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL DEFAULT '',
 expires_at TIMESTAMPTZ,
 updated_by TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(sensor_id,asset_identity)
);
CREATE INDEX IF NOT EXISTS idx_asset_risk_exception_ip ON asset_risk_exceptions(sensor_id,asset_ip);
CREATE TABLE IF NOT EXISTS asset_risk_settings (
 singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
 alert_weight INTEGER NOT NULL DEFAULT 12,
 vulnerability_weight INTEGER NOT NULL DEFAULT 8,
 exposure_weight INTEGER NOT NULL DEFAULT 15,
 context_weight INTEGER NOT NULL DEFAULT 20,
 propagation_weight INTEGER NOT NULL DEFAULT 12,
 decay_half_life_days INTEGER NOT NULL DEFAULT 14,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO asset_risk_settings(singleton) VALUES(TRUE) ON CONFLICT(singleton) DO NOTHING;
`

type ManagedIncident struct {
	ID              int64     `json:"ID"`
	SensorID        string    `json:"SensorID"`
	IP              string    `json:"IP"`
	Title           string    `json:"Title"`
	Severity        string    `json:"Severity"`
	Score           int       `json:"Score"`
	Confidence      int       `json:"Confidence"`
	Status          string    `json:"Status"`
	Owner           string    `json:"Owner"`
	Summary         string    `json:"Summary"`
	FirstSeen       time.Time `json:"FirstSeen"`
	LastSeen        time.Time `json:"LastSeen"`
	UpdatedAt       time.Time `json:"UpdatedAt"`
	AlertCount      int       `json:"AlertCount"`
	Types           []string  `json:"Types"`
	RuleID          int64     `json:"RuleID"`
	RuleName        string    `json:"RuleName"`
	MITRETactics    []string  `json:"MITRETactics"`
	MITRETechniques []string  `json:"MITRETechniques"`
}

// IncidentDashboardStats is a lightweight workflow summary used by the
// dashboard. "Open" intentionally means analyst-actionable workflow states;
// resolved/closed incidents remain searchable history but do not inflate the
// dashboard queue.
type IncidentDashboardStats struct {
	Total          int `json:"total"`
	Open           int `json:"open"`
	New            int `json:"new"`
	Investigating  int `json:"investigating"`
	Contained      int `json:"contained"`
	Resolved       int `json:"resolved"`
	Closed         int `json:"closed"`
	HighRiskOpen   int `json:"high_risk_open"`
	UnassignedOpen int `json:"unassigned_open"`
}

type IncidentEvent struct {
	ID         int64     `json:"ID"`
	IncidentID int64     `json:"IncidentID"`
	EventType  string    `json:"EventType"`
	SourceKey  string    `json:"SourceKey"`
	Severity   string    `json:"Severity"`
	Message    string    `json:"Message"`
	EventAt    time.Time `json:"EventAt"`
}

type AssetRisk struct {
	SensorID        string    `json:"SensorID"`
	IP              string    `json:"IP"`
	Score           int       `json:"Score"`
	TechnicalScore  int       `json:"TechnicalScore"`
	ContextualScore int       `json:"ContextualScore"`
	PropagatedScore int       `json:"PropagatedScore"`
	Level           string    `json:"Level"`
	Trend           string    `json:"Trend"`
	Reasons         []string  `json:"Reasons"`
	Recommendations []string  `json:"Recommendations"`
	UpdatedAt       time.Time `json:"UpdatedAt"`
}

type AssetRiskException struct {
	SensorID            string     `json:"sensor_id"`
	AssetIdentity       string     `json:"asset_identity,omitempty"`
	AssetIP             string     `json:"asset_ip"`
	Disposition         string     `json:"disposition"`
	ScoreOverride       *int       `json:"score_override,omitempty"`
	CompensatingControl string     `json:"compensating_control"`
	Reason              string     `json:"reason"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	UpdatedBy           string     `json:"updated_by"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type AssetRiskHistoryPoint struct {
	Score      int       `json:"score"`
	Level      string    `json:"level"`
	RecordedAt time.Time `json:"recorded_at"`
}

type CorrelationRule struct {
	ID               int64    `json:"ID"`
	Name             string   `json:"Name"`
	Description      string   `json:"Description"`
	Enabled          bool     `json:"Enabled"`
	WindowMinutes    int      `json:"WindowMinutes"`
	MinEvents        int      `json:"MinEvents"`
	RequiredTypes    []string `json:"RequiredTypes"`
	SequenceTypes    []string `json:"SequenceTypes"`
	Severity         string   `json:"Severity"`
	ScoreWeight      int      `json:"ScoreWeight"`
	ConfidenceWeight int      `json:"ConfidenceWeight"`
	MITRETactics     []string `json:"MITRETactics"`
	MITRETechniques  []string `json:"MITRETechniques"`
	Builtin          bool     `json:"Builtin"`
}

type correlationCandidate struct {
	SensorID, IP string
	Types        []string
	Severity     string
	Count        int
	First, Last  time.Time
}

func containsAll(have []string, required []string) bool {
	m := map[string]bool{}
	for _, v := range have {
		m[strings.ToLower(strings.TrimSpace(v))] = true
	}
	for _, v := range required {
		if !m[strings.ToLower(strings.TrimSpace(v))] {
			return false
		}
	}
	return true
}

func sequenceMatches(types []string, sequence []string) bool {
	if len(sequence) == 0 {
		return true
	}
	pos := 0
	for _, t := range types {
		if strings.EqualFold(t, sequence[pos]) {
			pos++
			if pos == len(sequence) {
				return true
			}
		}
	}
	return false
}

func (r *Repository) ListCorrelationRules(ctx context.Context) ([]CorrelationRule, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,name,description,enabled,window_minutes,min_events,required_types,sequence_types,severity,score_weight,confidence_weight,mitre_tactics,mitre_techniques,builtin FROM correlation_rules ORDER BY builtin DESC,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CorrelationRule{}
	for rows.Next() {
		var x CorrelationRule
		var a, b, c, d []byte
		if err = rows.Scan(&x.ID, &x.Name, &x.Description, &x.Enabled, &x.WindowMinutes, &x.MinEvents, &a, &b, &x.Severity, &x.ScoreWeight, &x.ConfidenceWeight, &c, &d, &x.Builtin); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(a, &x.RequiredTypes)
		_ = json.Unmarshal(b, &x.SequenceTypes)
		_ = json.Unmarshal(c, &x.MITRETactics)
		_ = json.Unmarshal(d, &x.MITRETechniques)
		out = append(out, x)
	}
	return out, rows.Err()
}
func (r *Repository) SaveCorrelationRule(ctx context.Context, x CorrelationRule) (int64, error) {
	if x.WindowMinutes < 1 {
		x.WindowMinutes = 60
	}
	if x.MinEvents < 2 {
		x.MinEvents = 2
	}
	var id int64
	a, _ := json.Marshal(x.RequiredTypes)
	b, _ := json.Marshal(x.SequenceTypes)
	c, _ := json.Marshal(x.MITRETactics)
	d, _ := json.Marshal(x.MITRETechniques)
	err := r.db.QueryRowContext(ctx, `INSERT INTO correlation_rules(name,description,enabled,window_minutes,min_events,required_types,sequence_types,severity,score_weight,confidence_weight,mitre_tactics,mitre_techniques) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(name) DO UPDATE SET description=EXCLUDED.description,enabled=EXCLUDED.enabled,window_minutes=EXCLUDED.window_minutes,min_events=EXCLUDED.min_events,required_types=EXCLUDED.required_types,sequence_types=EXCLUDED.sequence_types,severity=EXCLUDED.severity,score_weight=EXCLUDED.score_weight,confidence_weight=EXCLUDED.confidence_weight,mitre_tactics=EXCLUDED.mitre_tactics,mitre_techniques=EXCLUDED.mitre_techniques,updated_at=NOW() RETURNING id`, x.Name, x.Description, x.Enabled, x.WindowMinutes, x.MinEvents, string(a), string(b), x.Severity, x.ScoreWeight, x.ConfidenceWeight, string(c), string(d)).Scan(&id)
	return id, err
}
func (r *Repository) DeleteCorrelationRule(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM correlation_rules WHERE id=$1 AND builtin=FALSE`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func correlationScore(severity string, alertCount, distinctTypes int) int {
	score := 25 + alertCount*8 + distinctTypes*7
	switch severity {
	case "critical":
		score += 30
	case "high":
		score += 20
	case "medium":
		score += 10
	}
	if score > 100 {
		return 100
	}
	if score < 0 {
		return 0
	}
	return score
}

func riskLevel(score int) string {
	if score >= 75 {
		return "critical"
	}
	if score >= 50 {
		return "high"
	}
	if score >= 25 {
		return "medium"
	}
	return "low"
}
func (r *Repository) SyncCorrelatedIncidents(ctx context.Context) error {
	rules, err := r.ListCorrelationRules(ctx)
	if err != nil {
		return err
	}
	var correlationCutoff time.Time
	_ = r.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT value::timestamptz FROM central_runtime_state WHERE key='incident_correlation_cutoff'),'1970-01-01'::timestamptz)`).Scan(&correlationCutoff)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := syncBehaviorIncidents(ctx, tx, correlationCutoff); err != nil {
		return err
	}
	for _, rule := range rules {
		if !rule.Enabled || rule.Name == "Network Behavior Analytics" {
			// NBA candidates are handled by syncBehaviorIncidents below with their
			// evidence score/confidence. Running the generic correlation pass for the
			// same built-in rule duplicates work and can overwrite NBA-specific scoring.
			continue
		}
		relevantTypes := uniqueStrings(append(append([]string{}, rule.RequiredTypes...), rule.SequenceTypes...))
		rows, qerr := tx.QueryContext(ctx, `SELECT sensor_id,ip,string_agg(type,',' ORDER BY last_seen),string_agg(DISTINCT severity,','),COUNT(*),MIN(first_seen),MAX(last_seen)
			FROM alert_history
			WHERE ip<>'' AND status IN ('new','confirmed')
			  AND last_seen>NOW()-($1*INTERVAL '1 minute') AND last_seen>$3
			  AND (cardinality($4::text[])=0 OR type=ANY($4::text[]))
			GROUP BY sensor_id,ip HAVING COUNT(*) >= $2`, rule.WindowMinutes, rule.MinEvents, correlationCutoff, relevantTypes)
		if qerr != nil {
			return qerr
		}
		candidates := []correlationCandidate{}
		for rows.Next() {
			var c correlationCandidate
			var types, sevs string
			if qerr = rows.Scan(&c.SensorID, &c.IP, &types, &sevs, &c.Count, &c.First, &c.Last); qerr != nil {
				rows.Close()
				return qerr
			}
			c.Types = strings.Split(types, ",")
			c.Severity = highestSeverity(strings.Split(sevs, ","))
			candidates = append(candidates, c)
		}
		rows.Close()
		for _, c := range candidates {
			distinct := []string{}
			seen := map[string]bool{}
			for _, t := range c.Types {
				k := strings.ToLower(t)
				if !seen[k] {
					seen[k] = true
					distinct = append(distinct, t)
				}
			}
			if len(rule.RequiredTypes) == 0 && len(distinct) < 2 {
				continue
			}
			if !containsAll(distinct, rule.RequiredTypes) || !sequenceMatches(c.Types, rule.SequenceTypes) {
				continue
			}
			sev := highestSeverity([]string{c.Severity, rule.Severity})
			score := correlationScore(sev, c.Count, len(distinct)) + rule.ScoreWeight
			if score > 100 {
				score = 100
			}
			confidence := 45 + len(distinct)*10 + rule.ConfidenceWeight
			if len(rule.SequenceTypes) > 0 {
				confidence += 10
			}
			if confidence > 100 {
				confidence = 100
			}
			title := rule.Name + " on " + c.IP
			summary := fmt.Sprintf("Rule %s matched %d events across %d types in %d minutes: %s", rule.Name, c.Count, len(distinct), rule.WindowMinutes, strings.Join(distinct, ", "))
			var id int64
			tactics, _ := json.Marshal(rule.MITRETactics)
			techniques, _ := json.Marshal(rule.MITRETechniques)
			err = tx.QueryRowContext(ctx, `INSERT INTO incidents(sensor_id,asset_ip,title,severity,score,confidence,status,summary,first_seen,last_seen,correlation_rule_id,correlation_rule_name,mitre_tactics,mitre_techniques) VALUES($1,$2,$3,$4,$5,$6,'new',$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(sensor_id,asset_ip,COALESCE(correlation_rule_id,0)) WHERE status IN ('new','investigating','contained') DO UPDATE SET title=EXCLUDED.title,severity=CASE WHEN (CASE LOWER(EXCLUDED.severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) >= (CASE LOWER(incidents.severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) THEN EXCLUDED.severity ELSE incidents.severity END,score=GREATEST(incidents.score,EXCLUDED.score),confidence=GREATEST(incidents.confidence,EXCLUDED.confidence),summary=EXCLUDED.summary,first_seen=LEAST(incidents.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(incidents.last_seen,EXCLUDED.last_seen),mitre_tactics=EXCLUDED.mitre_tactics,mitre_techniques=EXCLUDED.mitre_techniques,updated_at=NOW() RETURNING id`, c.SensorID, c.IP, title, sev, score, confidence, summary, c.First, c.Last, rule.ID, rule.Name, string(tactics), string(techniques)).Scan(&id)
			if err != nil {
				return err
			}
			metadata, _ := json.Marshal(map[string]any{"correlation_rule": rule.Name, "mitre_tactics": rule.MITRETactics, "mitre_techniques": rule.MITRETechniques})
			// Insert all matching alert events in one database statement. The previous
			// implementation issued one SELECT and one INSERT per alert key, which made
			// correlation increasingly expensive as alert volume grew.
			if _, err = tx.ExecContext(ctx, `INSERT INTO incident_events(incident_id,event_type,source_key,severity,message,event_at,metadata)
				SELECT $1,'alert',alert_key,severity,message,last_seen,$2::jsonb
				FROM alert_history
				WHERE sensor_id=$3 AND ip=$4 AND status IN ('new','confirmed')
				  AND last_seen>NOW()-($5*INTERVAL '1 minute') AND last_seen>$6
				  AND (cardinality($7::text[])=0 OR type=ANY($7::text[]))
				ON CONFLICT(incident_id,event_type,source_key) DO UPDATE SET
				  severity=EXCLUDED.severity,
				  message=EXCLUDED.message,
				  event_at=GREATEST(incident_events.event_at,EXCLUDED.event_at),
				  metadata=EXCLUDED.metadata`, id, string(metadata), c.SensorID, c.IP, rule.WindowMinutes, correlationCutoff, relevantTypes); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func syncBehaviorIncidents(ctx context.Context, tx *sql.Tx, cutoff time.Time) error {
	type candidate struct {
		sensorID, ip, alertKey, severity, message string
		count                                     uint64
		firstSeen, lastSeen                       time.Time
		score, confidence                         float64
		evidence                                  []byte
	}
	var ruleID int64
	var windowMinutes int
	if err := tx.QueryRowContext(ctx, `SELECT id,window_minutes FROM correlation_rules WHERE name='Network Behavior Analytics'`).Scan(&ruleID, &windowMinutes); err != nil {
		return err
	}
	if windowMinutes < 1 {
		windowMinutes = 30
	}
	rows, err := tx.QueryContext(ctx, `SELECT sensor_id,ip,alert_key,severity,message,count,first_seen,last_seen,
		COALESCE((evidence->>'risk_score')::double precision,85),
		COALESCE((evidence->>'confidence')::double precision,0.5),evidence
		FROM alert_history WHERE type='behavior_incident_candidate' AND status<>'approved'
		  AND last_seen>NOW()-($1*INTERVAL '1 minute') AND last_seen>$2`, windowMinutes, cutoff)
	if err != nil {
		return err
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.sensorID, &item.ip, &item.alertKey, &item.severity, &item.message, &item.count, &item.firstSeen, &item.lastSeen, &item.score, &item.confidence, &item.evidence); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range candidates {
		scoreValue := int(math.Round(math.Max(0, math.Min(100, item.score))))
		confidenceValue := int(math.Round(math.Max(0, math.Min(1, item.confidence)) * 100))
		var incidentID int64
		err = tx.QueryRowContext(ctx, `INSERT INTO incidents(sensor_id,asset_ip,title,severity,score,confidence,status,summary,first_seen,last_seen,correlation_rule_id,correlation_rule_name,mitre_tactics,mitre_techniques)
			VALUES($1,$2,$3,$4,$5,$6,'new',$7,$8,$9,$10,'Network Behavior Analytics','["TA0001"]','[]')
			ON CONFLICT(sensor_id,asset_ip,COALESCE(correlation_rule_id,0)) WHERE status IN ('new','investigating','contained') DO UPDATE SET
				severity=CASE WHEN (CASE LOWER(EXCLUDED.severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) >= (CASE LOWER(incidents.severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) THEN EXCLUDED.severity ELSE incidents.severity END,score=GREATEST(incidents.score,EXCLUDED.score),confidence=GREATEST(incidents.confidence,EXCLUDED.confidence),
				summary=EXCLUDED.summary,first_seen=LEAST(incidents.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(incidents.last_seen,EXCLUDED.last_seen),updated_at=NOW()
			RETURNING id`, item.sensorID, item.ip, "Network behavior incident on "+item.ip, item.severity, scoreValue, confidenceValue, item.message, item.firstSeen, item.lastSeen, ruleID).Scan(&incidentID)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO incident_events(incident_id,event_type,source_key,severity,message,event_at,metadata)
			VALUES($1,'behavior',$2,$3,$4,$5,$6)
			ON CONFLICT(incident_id,event_type,source_key) DO UPDATE SET
			  severity=EXCLUDED.severity,
			  message=EXCLUDED.message,
			  event_at=GREATEST(incident_events.event_at,EXCLUDED.event_at),
			  metadata=EXCLUDED.metadata`, incidentID, item.alertKey, item.severity, item.message, item.lastSeen, string(item.evidence)); err != nil {
			return err
		}
	}
	return nil
}

func cappedAdd(count, weight, capValue int) int {
	if count <= 0 {
		return 0
	}
	v := count * weight
	if v > capValue {
		return capValue
	}
	return v
}

func (r *Repository) RecalculateAssetRisk(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `WITH current_nodes AS (
SELECT * FROM (SELECT n.*,CASE WHEN mac<>'' THEN 'mac:'||lower(mac) ELSE 'ip:'||ip END asset_identity,ROW_NUMBER() OVER(PARTITION BY sensor_id,CASE WHEN mac<>'' THEN 'mac:'||lower(mac) ELSE 'ip:'||ip END ORDER BY last_seen DESC,ip ASC) rn FROM topology_nodes n WHERE n.active=TRUE) x WHERE rn=1)
SELECT n.sensor_id,n.asset_identity,n.ip,COALESCE(NULLIF(n.vendor,''),'unknown'),COALESCE(NULLIF(n.protocols,''),''),n.last_seen,n.is_ot,COALESCE(c.asset_role,''),COALESCE(c.criticality,''),COALESCE(c.zone,''),c.purdue_override FROM current_nodes n LEFT JOIN asset_context c ON c.sensor_id=n.sensor_id AND c.asset_identity=n.asset_identity`)
	if err != nil {
		return err
	}
	defer rows.Close()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var alertWeight, vulnWeight, exposureWeight, contextWeight, propagationWeight, halfLife int
	_ = tx.QueryRowContext(ctx, `SELECT alert_weight,vulnerability_weight,exposure_weight,context_weight,propagation_weight,decay_half_life_days FROM asset_risk_settings WHERE singleton=TRUE`).Scan(&alertWeight, &vulnWeight, &exposureWeight, &contextWeight, &propagationWeight, &halfLife)
	if alertWeight == 0 {
		alertWeight, vulnWeight, exposureWeight, contextWeight, propagationWeight, halfLife = 12, 8, 15, 20, 12, 14
	}
	for rows.Next() {
		var sensor, identity, ip, vendor, protocols, role, criticality, zone string
		var last time.Time
		var isOT bool
		var purdue sql.NullFloat64
		if err = rows.Scan(&sensor, &identity, &ip, &vendor, &protocols, &last, &isOT, &role, &criticality, &zone, &purdue); err != nil {
			return err
		}
		technical, contextual, propagated := 0, 0, 0
		reasons := []string{}
		recommendations := []string{}
		aliases := []string{ip}
		var historicalAliases []string
		if e := tx.QueryRowContext(ctx, `SELECT COALESCE(ARRAY_AGG(DISTINCT ip ORDER BY ip),ARRAY[]::text[]) FROM asset_identity_history WHERE sensor_id=$1 AND asset_identity=$2`, sensor, identity).Scan(&historicalAliases); e == nil && len(historicalAliases) > 0 {
			aliases = historicalAliases
		}
		var criticalAlerts int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_history WHERE sensor_id=$1 AND status IN ('new','confirmed') AND severity IN ('critical','high') AND last_seen>=NOW()-INTERVAL '5 minutes' AND (ip=ANY($2::text[]) OR evidence->>'source_ip'=ANY($2::text[]) OR evidence->>'destination_ip'=ANY($2::text[]) OR evidence->>'target_ip'=ANY($2::text[]) OR evidence->>'peer_ip'=ANY($2::text[]) OR evidence->>'controller_ip'=ANY($2::text[]) OR evidence->>'origin_ip'=ANY($2::text[]) OR evidence->>'pivot_ip'=ANY($2::text[]) OR evidence->>'latest_target'=ANY($2::text[]))`, sensor, aliases).Scan(&criticalAlerts)
		if criticalAlerts > 0 {
			add := cappedAdd(criticalAlerts, alertWeight, 36)
			technical += add
			reasons = append(reasons, fmt.Sprintf("%d active high/critical alerts", criticalAlerts))
			recommendations = append(recommendations, "Investigate and contain active detections")
		}
		var vulnCritical, vulnHigh, vulnOther int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FILTER (WHERE lower(COALESCE(a.severity,''))='critical'),COUNT(*) FILTER (WHERE lower(COALESCE(a.severity,''))='high'),COUNT(*) FILTER (WHERE lower(COALESCE(a.severity,'')) NOT IN ('critical','high')) FROM vulnerability_findings f LEFT JOIN vulnerability_advisories a ON a.cve_id=f.cve_id WHERE f.sensor_id=$1 AND (f.asset_identity=$2 OR (f.asset_identity='' AND f.asset_ip=$3)) AND f.status IN ('confirmed','accepted_risk','potential')`, sensor, identity, ip).Scan(&vulnCritical, &vulnHigh, &vulnOther)
		if total := vulnCritical + vulnHigh + vulnOther; total > 0 {
			add := cappedAdd(vulnCritical, 14, 28) + cappedAdd(vulnHigh, 9, 18) + cappedAdd(vulnOther, vulnWeight, 12)
			if add > 38 {
				add = 38
			}
			technical += add
			reasons = append(reasons, fmt.Sprintf("%d active vulnerabilities (%d critical, %d high)", total, vulnCritical, vulnHigh))
			recommendations = append(recommendations, "Prioritize exploitable and critical vulnerability remediation")
		}
		p := strings.ToLower(protocols)
		if strings.Contains(p, "telnet") {
			technical += exposureWeight
			reasons = append(reasons, "Telnet observed")
			recommendations = append(recommendations, "Disable Telnet and migrate to an encrypted management protocol")
		}
		if strings.Contains(p, "smb1") || strings.Contains(p, "smbv1") {
			technical += exposureWeight
			reasons = append(reasons, "SMBv1 observed")
			recommendations = append(recommendations, "Disable SMBv1")
		}
		if vendor == "unknown" {
			technical += 6
			reasons = append(reasons, "unknown vendor")
			recommendations = append(recommendations, "Profile the asset and confirm its identity")
		}
		if time.Since(last) > 7*24*time.Hour {
			technical += 6
			reasons = append(reasons, "stale inventory record")
			recommendations = append(recommendations, "Validate whether the asset is retired or unreachable")
		}
		crit := strings.ToLower(criticality)
		switch crit {
		case "critical":
			contextual += contextWeight
		case "high":
			contextual += contextWeight * 3 / 4
		case "medium":
			contextual += contextWeight / 2
		}
		roleLower := strings.ToLower(role)
		if strings.Contains(roleLower, "plc") || strings.Contains(roleLower, "rtu") || strings.Contains(roleLower, "safety") || strings.Contains(roleLower, "domain controller") || strings.Contains(roleLower, "historian") {
			contextual += 10
			reasons = append(reasons, "critical operational role: "+role)
		}
		effectiveOT := isOT
		if strings.TrimSpace(role) != "" || purdue.Valid {
			effectiveOT = roleIsOT(role) || (purdue.Valid && purdue.Float64 <= 3)
		}
		if effectiveOT {
			contextual += 5
		}
		if purdue.Valid && purdue.Float64 <= 1 {
			contextual += 12
			reasons = append(reasons, fmt.Sprintf("Purdue level %.1f asset", purdue.Float64))
			recommendations = append(recommendations, "Verify strict segmentation and least-privilege access")
		}
		z := strings.ToLower(zone)
		if strings.Contains(z, "dmz") {
			contextual += 4
		} else if strings.Contains(z, "level 0") || strings.Contains(z, "level 1") || strings.Contains(z, "safety") {
			contextual += 10
		}
		var external int
		// Exposure follows the stable identity across DHCP aliases. Multicast,
		// unspecified, link-local, loopback and documentation/non-routable ranges
		// are not counted as Internet exposure merely because they are non-RFC1918.
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM flow_observations WHERE sensor_id=$1 AND bucket_end>NOW()-INTERVAL '7 days' AND ((src_ip=ANY($2::text[]) AND NOT (dst_ip::inet <<= ANY(ARRAY['0.0.0.0/8'::cidr,'10.0.0.0/8'::cidr,'100.64.0.0/10'::cidr,'127.0.0.0/8'::cidr,'169.254.0.0/16'::cidr,'172.16.0.0/12'::cidr,'192.0.0.0/24'::cidr,'192.0.2.0/24'::cidr,'192.168.0.0/16'::cidr,'198.18.0.0/15'::cidr,'198.51.100.0/24'::cidr,'203.0.113.0/24'::cidr,'224.0.0.0/4'::cidr,'240.0.0.0/4'::cidr,'::/128'::cidr,'::1/128'::cidr,'fc00::/7'::cidr,'fe80::/10'::cidr,'ff00::/8'::cidr,'2001:db8::/32'::cidr]))) OR (dst_ip=ANY($2::text[]) AND NOT (src_ip::inet <<= ANY(ARRAY['0.0.0.0/8'::cidr,'10.0.0.0/8'::cidr,'100.64.0.0/10'::cidr,'127.0.0.0/8'::cidr,'169.254.0.0/16'::cidr,'172.16.0.0/12'::cidr,'192.0.0.0/24'::cidr,'192.0.2.0/24'::cidr,'192.168.0.0/16'::cidr,'198.18.0.0/15'::cidr,'198.51.100.0/24'::cidr,'203.0.113.0/24'::cidr,'224.0.0.0/4'::cidr,'240.0.0.0/4'::cidr,'::/128'::cidr,'::1/128'::cidr,'fc00::/7'::cidr,'fe80::/10'::cidr,'ff00::/8'::cidr,'2001:db8::/32'::cidr]))))`, sensor, aliases).Scan(&external)
		if external > 0 {
			technical += minInt(exposureWeight, 20)
			reasons = append(reasons, "external network exposure observed")
			recommendations = append(recommendations, "Review external connectivity and restrict inbound/outbound paths")
		}
		var riskyNeighbors int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT CASE WHEN e.src_ip=$2 THEN e.dst_ip ELSE e.src_ip END) FROM topology_edges e JOIN asset_risk ar ON ar.sensor_id=e.sensor_id AND ar.asset_ip=CASE WHEN e.src_ip=$2 THEN e.dst_ip ELSE e.src_ip END WHERE e.sensor_id=$1 AND (e.src_ip=$2 OR e.dst_ip=$2) AND ar.score>=75 AND e.last_seen>NOW()-INTERVAL '7 days'`, sensor, ip).Scan(&riskyNeighbors)
		if riskyNeighbors > 0 {
			propagated = cappedAdd(riskyNeighbors, propagationWeight, 24)
			reasons = append(reasons, fmt.Sprintf("connected to %d critical-risk asset(s)", riskyNeighbors))
			recommendations = append(recommendations, "Review lateral-movement paths and isolate risky neighbors")
		}
		if technical > 60 {
			technical = 60
		}
		if contextual > 25 {
			contextual = 25
		}
		if propagated > 15 {
			propagated = 15
		}
		score := technical + contextual + propagated
		var disposition, control string
		var override sql.NullInt64
		var expires sql.NullTime
		_ = tx.QueryRowContext(ctx, `SELECT disposition,score_override,compensating_control,expires_at FROM asset_risk_exceptions WHERE sensor_id=$1 AND (asset_identity=$2 OR (asset_identity='' AND asset_ip=$3)) AND (expires_at IS NULL OR expires_at>NOW()) ORDER BY updated_at DESC LIMIT 1`, sensor, identity, ip).Scan(&disposition, &override, &control, &expires)
		if override.Valid {
			score = int(override.Int64)
			reasons = append(reasons, "analyst score override applied")
		}
		if disposition == "accepted_risk" {
			score = maxInt(0, score-10)
			reasons = append(reasons, "risk accepted with analyst justification")
		}
		if disposition == "false_positive" {
			score = maxInt(0, score-25)
			reasons = append(reasons, "false-positive disposition")
		}
		if control != "" {
			score = maxInt(0, score-8)
			reasons = append(reasons, "compensating control: "+control)
		}
		if score > 100 {
			score = 100
		}
		level := riskLevel(score)
		var previous int
		_ = tx.QueryRowContext(ctx, `SELECT score FROM asset_risk_history WHERE sensor_id=$1 AND asset_ip=ANY($2::text[]) ORDER BY recorded_at DESC LIMIT 1`, sensor, aliases).Scan(&previous)
		trend := "stable"
		if score >= previous+5 {
			trend = "increasing"
		} else if score <= previous-5 {
			trend = "decreasing"
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO asset_risk(sensor_id,asset_ip,score,technical_score,contextual_score,propagated_score,level,trend,reasons,recommendations,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW()) ON CONFLICT(sensor_id,asset_ip) DO UPDATE SET score=EXCLUDED.score,technical_score=EXCLUDED.technical_score,contextual_score=EXCLUDED.contextual_score,propagated_score=EXCLUDED.propagated_score,level=EXCLUDED.level,trend=EXCLUDED.trend,reasons=EXCLUDED.reasons,recommendations=EXCLUDED.recommendations,updated_at=NOW()`, sensor, ip, score, technical, contextual, propagated, level, trend, pqStringArrayJSON(reasons), pqStringArrayJSON(uniqueStrings(recommendations)))
		if err != nil {
			return err
		}
		if previous != score {
			_, _ = tx.ExecContext(ctx, `INSERT INTO asset_risk_history(sensor_id,asset_ip,score,level,reasons) VALUES($1,$2,$3,$4,$5)`, sensor, ip, score, level, pqStringArrayJSON(reasons))
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	// asset_risk is a current-state table. Historical IP aliases belong in
	// asset_risk_history, not as duplicate current rows after DHCP changes.
	if _, err = tx.ExecContext(ctx, `DELETE FROM asset_risk ar WHERE NOT EXISTS (SELECT 1 FROM (SELECT sensor_id,ip,ROW_NUMBER() OVER(PARTITION BY sensor_id,CASE WHEN mac<>'' THEN 'mac:'||lower(mac) ELSE 'ip:'||ip END ORDER BY last_seen DESC,ip ASC) rn FROM topology_nodes WHERE active=TRUE) n WHERE n.rn=1 AND n.sensor_id=ar.sensor_id AND n.ip=ar.asset_ip)`); err != nil {
		return err
	}
	return tx.Commit()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func uniqueStrings(v []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range v {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func pqStringArrayJSON(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	out := "["
	for i, s := range v {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%q", s)
	}
	return out + "]"
}

func (r *Repository) IncidentDashboard(ctx context.Context, limit int) (IncidentDashboardStats, []ManagedIncident, error) {
	if limit <= 0 {
		limit = 5
	}
	if limit > 20 {
		limit = 20
	}
	var stats IncidentDashboardStats
	err := r.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*)::int,
			COUNT(*) FILTER (WHERE status IN ('new','investigating','contained'))::int,
			COUNT(*) FILTER (WHERE status='new')::int,
			COUNT(*) FILTER (WHERE status='investigating')::int,
			COUNT(*) FILTER (WHERE status='contained')::int,
			COUNT(*) FILTER (WHERE status='resolved')::int,
			COUNT(*) FILTER (WHERE status='closed')::int,
			COUNT(*) FILTER (WHERE status IN ('new','investigating','contained') AND score >= 75)::int,
			COUNT(*) FILTER (WHERE status IN ('new','investigating','contained') AND BTRIM(owner)='')::int
		FROM incidents`).Scan(
		&stats.Total, &stats.Open, &stats.New, &stats.Investigating, &stats.Contained,
		&stats.Resolved, &stats.Closed, &stats.HighRiskOpen, &stats.UnassignedOpen,
	)
	if err != nil {
		return IncidentDashboardStats{}, nil, err
	}
	items, _, err := r.ListManagedIncidentsPage(ctx, "", "", 0, limit, 0)
	if err != nil {
		return IncidentDashboardStats{}, nil, err
	}
	return stats, items, nil
}

func (r *Repository) ListManagedIncidents(ctx context.Context) ([]ManagedIncident, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT i.id,i.sensor_id,i.asset_ip,i.title,i.severity,i.score,i.confidence,i.status,i.owner,i.summary,i.first_seen,i.last_seen,i.updated_at,COALESCE(e.event_count,0),COALESCE(e.severities,''),COALESCE(i.correlation_rule_id,0),i.correlation_rule_name,i.mitre_tactics,i.mitre_techniques
		FROM incidents i
		LEFT JOIN LATERAL (
			SELECT COUNT(*) AS event_count,COALESCE(string_agg(DISTINCT CASE WHEN event_type='alert' THEN severity END,','),'') AS severities
			FROM incident_events WHERE incident_id=i.id
		) e ON TRUE
		ORDER BY CASE i.status WHEN 'new' THEN 0 WHEN 'investigating' THEN 1 WHEN 'contained' THEN 2 WHEN 'resolved' THEN 3 ELSE 4 END,i.score DESC,i.updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ManagedIncident{}
	for rows.Next() {
		var x ManagedIncident
		var types, tactics, techniques string
		if err = rows.Scan(&x.ID, &x.SensorID, &x.IP, &x.Title, &x.Severity, &x.Score, &x.Confidence, &x.Status, &x.Owner, &x.Summary, &x.FirstSeen, &x.LastSeen, &x.UpdatedAt, &x.AlertCount, &types, &x.RuleID, &x.RuleName, &tactics, &techniques); err != nil {
			return nil, err
		}
		if types != "" {
			x.Types = strings.Split(types, ",")
		}
		_ = json.Unmarshal([]byte(tactics), &x.MITRETactics)
		_ = json.Unmarshal([]byte(techniques), &x.MITRETechniques)
		out = append(out, x)
	}
	return out, rows.Err()
}
func (r *Repository) ListManagedIncidentsPage(ctx context.Context, status, query string, minScore, limit, offset int) ([]ManagedIncident, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	query = strings.TrimSpace(query)
	where := `($1='' OR i.status=$1) AND i.score >= $2 AND ($3='' OR i.sensor_id ILIKE '%'||$3||'%' OR i.asset_ip ILIKE '%'||$3||'%' OR i.title ILIKE '%'||$3||'%' OR i.owner ILIKE '%'||$3||'%' OR i.correlation_rule_name ILIKE '%'||$3||'%')`
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents i WHERE `+where, status, minScore, query).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT i.id,i.sensor_id,i.asset_ip,i.title,i.severity,i.score,i.confidence,i.status,i.owner,i.summary,i.first_seen,i.last_seen,i.updated_at,COALESCE(e.event_count,0),COALESCE(e.severities,''),COALESCE(i.correlation_rule_id,0),i.correlation_rule_name,i.mitre_tactics,i.mitre_techniques
		FROM incidents i
		LEFT JOIN LATERAL (
			SELECT COUNT(*) AS event_count,COALESCE(string_agg(DISTINCT CASE WHEN event_type='alert' THEN severity END,','),'') AS severities
			FROM incident_events WHERE incident_id=i.id
		) e ON TRUE
		WHERE `+where+`
		ORDER BY CASE i.status WHEN 'new' THEN 0 WHEN 'investigating' THEN 1 WHEN 'contained' THEN 2 WHEN 'resolved' THEN 3 ELSE 4 END,i.score DESC,i.updated_at DESC
		LIMIT $4 OFFSET $5`, status, minScore, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ManagedIncident{}
	for rows.Next() {
		var x ManagedIncident
		var types, tactics, techniques string
		if err = rows.Scan(&x.ID, &x.SensorID, &x.IP, &x.Title, &x.Severity, &x.Score, &x.Confidence, &x.Status, &x.Owner, &x.Summary, &x.FirstSeen, &x.LastSeen, &x.UpdatedAt, &x.AlertCount, &types, &x.RuleID, &x.RuleName, &tactics, &techniques); err != nil {
			return nil, 0, err
		}
		if types != "" {
			x.Types = strings.Split(types, ",")
		}
		_ = json.Unmarshal([]byte(tactics), &x.MITRETactics)
		_ = json.Unmarshal([]byte(techniques), &x.MITRETechniques)
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *Repository) IncidentEvents(ctx context.Context, id int64) ([]IncidentEvent, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,incident_id,event_type,source_key,severity,message,event_at FROM incident_events WHERE incident_id=$1 ORDER BY event_at DESC`, id)
	if err != nil {
		return nil, err
	}
	out := []IncidentEvent{}
	for rows.Next() {
		var x IncidentEvent
		if err = rows.Scan(&x.ID, &x.IncidentID, &x.EventType, &x.SourceKey, &x.Severity, &x.Message, &x.EventAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(out) > 0 {
		return out, nil
	}

	// Older incidents, or incidents created while alert workflow state changed
	// concurrently with correlation, can have a valid correlation summary but no
	// persisted incident_events rows. Reconstruct the evidence window from
	// alert_history so the analyst workbench never presents a contradictory empty
	// timeline for an incident that explicitly says it matched events.
	var sensorID, assetIP string
	var lastSeen time.Time
	var windowMinutes int
	var requiredJSON, sequenceJSON []byte
	if err := r.db.QueryRowContext(ctx, `SELECT i.sensor_id,i.asset_ip,i.last_seen,COALESCE(r.window_minutes,1440),COALESCE(r.required_types,'[]'::jsonb),COALESCE(r.sequence_types,'[]'::jsonb)
		FROM incidents i LEFT JOIN correlation_rules r ON r.id=i.correlation_rule_id WHERE i.id=$1`, id).Scan(&sensorID, &assetIP, &lastSeen, &windowMinutes, &requiredJSON, &sequenceJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return out, nil
		}
		return nil, err
	}
	if windowMinutes < 1 {
		windowMinutes = 1440
	}
	windowStart := lastSeen.Add(-time.Duration(windowMinutes) * time.Minute)
	allowedTypes := map[string]bool{}
	var requiredTypes, sequenceTypes []string
	_ = json.Unmarshal(requiredJSON, &requiredTypes)
	_ = json.Unmarshal(sequenceJSON, &sequenceTypes)
	for _, alertType := range append(requiredTypes, sequenceTypes...) {
		if normalized := strings.ToLower(strings.TrimSpace(alertType)); normalized != "" {
			allowedTypes[normalized] = true
		}
	}
	fallback, err := r.db.QueryContext(ctx, `SELECT alert_key,type,severity,message,last_seen
		FROM alert_history
		WHERE sensor_id=$1 AND ip=$2
		  AND last_seen >= $3 AND last_seen <= $4
		ORDER BY last_seen DESC
		LIMIT 500`, sensorID, assetIP, windowStart, lastSeen)
	if err != nil {
		return nil, err
	}
	defer fallback.Close()
	for fallback.Next() {
		var sourceKey, alertType, severity, message string
		var eventAt time.Time
		if err := fallback.Scan(&sourceKey, &alertType, &severity, &message, &eventAt); err != nil {
			return nil, err
		}
		if len(allowedTypes) > 0 && !allowedTypes[strings.ToLower(strings.TrimSpace(alertType))] {
			continue
		}
		out = append(out, IncidentEvent{IncidentID: id, EventType: "alert", SourceKey: sourceKey, Severity: severity, Message: message, EventAt: eventAt})
	}
	return out, fallback.Err()
}
func (r *Repository) UpdateIncident(ctx context.Context, id int64, status, owner, summary string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE incidents SET status=$2,owner=$3,summary=$4,updated_at=NOW() WHERE id=$1`, id, status, owner, summary)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
func (r *Repository) AddIncidentComment(ctx context.Context, id int64, actor, body string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO incident_comments(incident_id,actor,body) VALUES($1,$2,$3)`, id, actor, body)
	return err
}
func (r *Repository) IncidentComments(ctx context.Context, id int64) ([]gin.H, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,actor,body,created_at FROM incident_comments WHERE incident_id=$1 ORDER BY created_at DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id int64
		var actor, body string
		var at time.Time
		if err = rows.Scan(&id, &actor, &body, &at); err != nil {
			return nil, err
		}
		out = append(out, gin.H{"ID": id, "Actor": actor, "Body": body, "CreatedAt": at})
	}
	return out, rows.Err()
}
func (r *Repository) ListAssetRisk(ctx context.Context) ([]AssetRisk, error) {
	rows, err := r.db.QueryContext(ctx, `WITH current_nodes AS (SELECT sensor_id,ip FROM (SELECT n.*,ROW_NUMBER() OVER(PARTITION BY sensor_id,CASE WHEN mac<>'' THEN 'mac:'||lower(mac) ELSE 'ip:'||ip END ORDER BY last_seen DESC,ip ASC) rn FROM topology_nodes n WHERE n.active=TRUE) x WHERE rn=1) SELECT ar.sensor_id,ar.asset_ip,ar.score,ar.technical_score,ar.contextual_score,ar.propagated_score,ar.level,ar.trend,ar.reasons,ar.recommendations,ar.updated_at FROM asset_risk ar JOIN current_nodes n ON n.sensor_id=ar.sensor_id AND n.ip=ar.asset_ip ORDER BY ar.score DESC,ar.updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetRisk{}
	for rows.Next() {
		var x AssetRisk
		var raw, recs []byte
		if err = rows.Scan(&x.SensorID, &x.IP, &x.Score, &x.TechnicalScore, &x.ContextualScore, &x.PropagatedScore, &x.Level, &x.Trend, &raw, &recs, &x.UpdatedAt); err != nil {
			return nil, err
		}
		_ = jsonUnmarshalStrings(raw, &x.Reasons)
		_ = jsonUnmarshalStrings(recs, &x.Recommendations)
		out = append(out, x)
	}
	return out, rows.Err()
}
func (r *Repository) AssetRiskHistory(ctx context.Context, sensor, ip string) ([]AssetRiskHistoryPoint, error) {
	aliases, err := r.AssetIPAliases(ctx, sensor, ip)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT score,level,recorded_at FROM asset_risk_history WHERE sensor_id=$1 AND asset_ip=ANY($2::text[]) ORDER BY recorded_at DESC LIMIT 90`, sensor, aliases)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetRiskHistoryPoint{}
	for rows.Next() {
		var x AssetRiskHistoryPoint
		if err = rows.Scan(&x.Score, &x.Level, &x.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (r *Repository) GetAssetRiskException(ctx context.Context, sensor, ip string) (AssetRiskException, error) {
	var x AssetRiskException
	var score sql.NullInt64
	var exp sql.NullTime
	identity, err := r.ResolveAssetIdentity(ctx, sensor, ip)
	if err != nil {
		return x, err
	}
	err = r.db.QueryRowContext(ctx, `SELECT sensor_id,asset_identity,asset_ip,disposition,score_override,compensating_control,reason,expires_at,updated_by,updated_at FROM asset_risk_exceptions WHERE sensor_id=$1 AND (asset_identity=$2 OR (asset_identity='' AND asset_ip=$3)) ORDER BY updated_at DESC LIMIT 1`, sensor, identity, ip).Scan(&x.SensorID, &x.AssetIdentity, &x.AssetIP, &x.Disposition, &score, &x.CompensatingControl, &x.Reason, &exp, &x.UpdatedBy, &x.UpdatedAt)
	if score.Valid {
		v := int(score.Int64)
		x.ScoreOverride = &v
	}
	if exp.Valid {
		x.ExpiresAt = &exp.Time
	}
	if err == nil {
		if current, ok, e := r.CurrentAssetIP(ctx, sensor, identity); e == nil && ok {
			x.AssetIP = current
		}
	}
	return x, err
}
func (r *Repository) SetAssetRiskException(ctx context.Context, x AssetRiskException) error {
	identity, err := r.ResolveAssetIdentity(ctx, x.SensorID, x.AssetIP)
	if err != nil {
		return err
	}
	x.AssetIdentity = identity
	_, err = r.db.ExecContext(ctx, `INSERT INTO asset_risk_exceptions(sensor_id,asset_identity,asset_ip,disposition,score_override,compensating_control,reason,expires_at,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(sensor_id,asset_identity) DO UPDATE SET asset_ip=EXCLUDED.asset_ip,disposition=EXCLUDED.disposition,score_override=EXCLUDED.score_override,compensating_control=EXCLUDED.compensating_control,reason=EXCLUDED.reason,expires_at=EXCLUDED.expires_at,updated_by=EXCLUDED.updated_by,updated_at=NOW()`, x.SensorID, identity, x.AssetIP, x.Disposition, x.ScoreOverride, x.CompensatingControl, x.Reason, x.ExpiresAt, x.UpdatedBy)
	return err
}

func jsonUnmarshalStrings(raw []byte, out *[]string) error {
	if len(raw) == 0 {
		return nil
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	for _, p := range strings.Split(s, ",") {
		*out = append(*out, strings.Trim(strings.TrimSpace(p), "\""))
	}
	return nil
}
