package central

import (
	"context"
	"database/sql"
	"time"
)

// RuleRuntimeMetric is Central's retained, time-scoped view of one detector
// alert type on one sensor. The sensor still owns rule execution/configuration;
// Central owns these analytics because it has durable alert history across
// sensor restarts and can track count deltas without inflating every recent
// finding by its lifetime Count.
type RuleRuntimeMetric struct {
	SensorID            string
	AlertType           string
	ActiveFindings      uint64
	Occurrences24h      uint64
	NewFindings24h      uint64
	RetainedOccurrences uint64
	UniqueFindings      uint64
	LastHit             time.Time
}

func (r *Repository) RuleRuntimeMetrics(ctx context.Context) (map[string]RuleRuntimeMetric, error) {
	rows, err := r.db.QueryContext(ctx, `
WITH retained AS (
	SELECT sensor_id,type,
	       COUNT(*)::bigint AS unique_findings,
	       COALESCE(SUM(count),0)::bigint AS retained_occurrences,
	       COUNT(*) FILTER (
	         WHERE status IN ('new','confirmed')
	           AND last_seen >= NOW()-INTERVAL '5 minutes'
	       )::bigint AS active_findings,
	       MAX(last_seen) AS last_hit
	FROM alert_history
	GROUP BY sensor_id,type
), recent AS (
	SELECT sensor_id,alert_type,
	       COALESCE(SUM(occurrences),0)::bigint AS occurrences_24h,
	       COALESCE(SUM(new_findings),0)::bigint AS new_findings_24h
	FROM rule_occurrence_buckets
	WHERE bucket_start >= NOW()-INTERVAL '24 hours'
	GROUP BY sensor_id,alert_type
)
SELECT COALESCE(retained.sensor_id,recent.sensor_id),
       COALESCE(retained.type,recent.alert_type),
       COALESCE(retained.active_findings,0),
       COALESCE(recent.occurrences_24h,0),
       COALESCE(recent.new_findings_24h,0),
       COALESCE(retained.retained_occurrences,0),
       COALESCE(retained.unique_findings,0),
       retained.last_hit
FROM retained
FULL OUTER JOIN recent
  ON recent.sensor_id=retained.sensor_id AND recent.alert_type=retained.type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]RuleRuntimeMetric)
	for rows.Next() {
		var m RuleRuntimeMetric
		var active, recent, newRecent, retained, unique int64
		var lastHit sql.NullTime
		if err := rows.Scan(&m.SensorID, &m.AlertType, &active, &recent, &newRecent, &retained, &unique, &lastHit); err != nil {
			return nil, err
		}
		if active > 0 {
			m.ActiveFindings = uint64(active)
		}
		if recent > 0 {
			m.Occurrences24h = uint64(recent)
		}
		if newRecent > 0 {
			m.NewFindings24h = uint64(newRecent)
		}
		if retained > 0 {
			m.RetainedOccurrences = uint64(retained)
		}
		if unique > 0 {
			m.UniqueFindings = uint64(unique)
		}
		if lastHit.Valid {
			m.LastHit = lastHit.Time.UTC()
		}
		out[ruleRuntimeMetricKey(m.SensorID, m.AlertType)] = m
	}
	return out, rows.Err()
}

func ruleRuntimeMetricKey(sensorID, alertType string) string {
	return sensorID + "\x00" + alertType
}
