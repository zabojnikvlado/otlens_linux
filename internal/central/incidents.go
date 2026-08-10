package central

import (
	"context"
	"strings"
	"time"
)

// Incident groups alert_history rows that share a sensor+IP and
// happened within the same rolling window — see ListIncidents. This is
// computed fresh from alert_history on every request, not its own
// persisted table: there's nothing here that isn't already derivable
// from what's already stored, and a live grouping can't drift out of
// sync with the underlying alerts the way a separately-maintained
// summary table could.
type Incident struct {
	SensorID   string
	IP         string
	Types      []string
	AlertKeys  []string
	Severity   string // the highest-ranked severity among the grouped alerts
	AlertCount int
	FirstSeen  time.Time
	LastSeen   time.Time
}

// ListIncidents groups alert_history by (sensor_id, ip) where at least
// minDistinctTypes different alert *types* were seen within the last
// window — the idea being that one type repeating (e.g. the same
// external_communication alert bumping its Count) isn't a multi-stage
// incident, but an ARP spoof followed by a new communication pattern
// followed by lateral movement, all against the same IP within a short
// window, very plausibly is a single unfolding event worth looking at
// together rather than as three unrelated rows in the Alerts tab. New
// (unreviewed) and confirmed alerts participate; approved alerts are an
// operator verdict that the pattern is expected/benign and are excluded.
//
// Uses string_agg (comma-joined text) rather than array_agg/text[] —
// scanning a native Postgres array back out through database/sql's
// generic interface (as opposed to pgx's own, which this codebase
// doesn't use directly) isn't something else in this codebase already
// relies on, so this avoids depending on unverified driver behavior for
// something a plain string split handles just as well.
func (r *Repository) ListIncidents(ctx context.Context, window time.Duration, minDistinctTypes int) ([]Incident, error) {
	if window <= 0 {
		window = 24 * time.Hour
	}
	if minDistinctTypes < 2 {
		minDistinctTypes = 2
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT sensor_id, ip,
		       string_agg(DISTINCT type, ',' ORDER BY type),
		       string_agg(alert_key, ',' ORDER BY last_seen DESC),
		       string_agg(DISTINCT severity, ','),
		       COUNT(*), MIN(first_seen), MAX(last_seen)
		FROM alert_history
		WHERE last_seen > NOW() - ($1 * INTERVAL '1 second') AND ip != '' AND status IN ('new','confirmed')
		GROUP BY sensor_id, ip
		HAVING COUNT(DISTINCT type) >= $2
		ORDER BY MAX(last_seen) DESC`,
		int64(window/time.Second), minDistinctTypes,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Incident, 0)
	for rows.Next() {
		var inc Incident
		var types, keys, severities string
		if err := rows.Scan(&inc.SensorID, &inc.IP, &types, &keys, &severities, &inc.AlertCount, &inc.FirstSeen, &inc.LastSeen); err != nil {
			return nil, err
		}
		inc.Types = strings.Split(types, ",")
		inc.AlertKeys = strings.Split(keys, ",")
		inc.Severity = highestSeverity(strings.Split(severities, ","))
		out = append(out, inc)
	}
	return out, rows.Err()
}

// highestSeverity picks the worst of the given severity strings by the
// same low/medium/high/critical ranking notify.go uses. Unrecognized
// strings are ignored rather than treated as either extreme.
func highestSeverity(severities []string) string {
	best, bestRank := "low", -1
	for _, s := range severities {
		if rank, ok := severityRank[s]; ok && rank > bestRank {
			best, bestRank = s, rank
		}
	}
	return best
}
