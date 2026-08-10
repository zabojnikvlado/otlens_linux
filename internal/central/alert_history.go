package central

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// telemetryAlert mirrors the JSON shape of detect.Alert as reported by a
// sensor — kept as a local, minimal copy rather than importing
// internal/detect, since Central only needs a handful of fields out of
// it and doesn't otherwise depend on the sensor's detection engine
// package.
type telemetryAlert struct {
	ID        string                 `json:"ID"`
	Type      string                 `json:"Type"`
	Severity  string                 `json:"Severity"`
	Message   string                 `json:"Message"`
	IP        string                 `json:"IP"`
	FirstSeen time.Time              `json:"FirstSeen"`
	LastSeen  time.Time              `json:"LastSeen"`
	Count     uint64                 `json:"Count"`
	Status    string                 `json:"Status"`
	Evidence  map[string]interface{} `json:"Evidence,omitempty"`
}

// upsertAlertHistory folds this sync's reported alerts into the durable,
// per-alert alert_history table. As of the sensor-side dirty-tracking
// change (see detect.Engine.GetDirtyAlerts), what arrives here on a
// given sync is normally just the alerts that are new or changed since
// the sensor's last successful sync — not its entire alert set — which
// is exactly why this has to be an upsert-by-key, not a
// replace-the-whole-table operation: a partial report must only ever
// add to/update this table, never make it look like anything not
// mentioned in this batch has gone away. status is taken from the
// sensor's report but never downgrades a status Central already
// recorded via MarkAlertsReviewed — an operator's "confirmed"/
// "approved" verdict shouldn't flip back to "new" just because the
// sensor's own copy hasn't caught up yet on this particular sync.
//
// Returns the entries that were genuinely new this call (xmax=0 is
// Postgres's standard idiom for "this row was just inserted, not
// updated" — a system column set to 0 only by INSERT, non-zero once any
// UPDATE has touched the row) — see notify.go, which uses this to
// dispatch a notification only for something that just started
// happening, not on every routine re-report of an already-known alert.
func upsertAlertHistory(ctx context.Context, x execer, sensorID string, alertsJSON []byte) ([]AlertHistoryEntry, error) {
	if len(alertsJSON) == 0 {
		return nil, nil
	}
	var alerts []telemetryAlert
	if err := json.Unmarshal(alertsJSON, &alerts); err != nil {
		return nil, nil // malformed/empty — nothing to record, not a sync failure
	}
	var newlyCreated []AlertHistoryEntry
	for _, a := range alerts {
		if a.ID == "" {
			continue
		}
		firstSeen := a.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = time.Now()
		}
		lastSeen := a.LastSeen
		if lastSeen.IsZero() {
			lastSeen = firstSeen
		}
		status := a.Status
		if status == "" {
			status = "new"
		}
		count := a.Count
		if count == 0 {
			count = 1
		}
		rows, err := x.QueryContext(ctx, `
			INSERT INTO alert_history(sensor_id,alert_key,type,severity,message,ip,status,count,first_seen,last_seen,evidence)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT(sensor_id,alert_key) DO UPDATE SET
				type = EXCLUDED.type,
				severity = EXCLUDED.severity,
				message = EXCLUDED.message,
				ip = EXCLUDED.ip,
				status = CASE WHEN alert_history.status IN ('confirmed','approved') THEN alert_history.status ELSE EXCLUDED.status END,
				count = GREATEST(alert_history.count, EXCLUDED.count),
				first_seen = LEAST(alert_history.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(alert_history.last_seen, EXCLUDED.last_seen),
				evidence = EXCLUDED.evidence
			RETURNING (xmax = 0) AS inserted
		`, sensorID, a.ID, a.Type, a.Severity, a.Message, a.IP, status, count, firstSeen, lastSeen, jsonObject(a.Evidence))
		if err != nil {
			return newlyCreated, err
		}
		var wasInserted bool
		if rows.Next() {
			_ = rows.Scan(&wasInserted)
		}
		rows.Close()
		if wasInserted {
			newlyCreated = append(newlyCreated, AlertHistoryEntry{
				SensorID: sensorID, AlertKey: a.ID, Type: a.Type, Severity: a.Severity,
				Message: a.Message, IP: a.IP, Status: status, Count: count,
				FirstSeen: firstSeen, LastSeen: lastSeen,
				Evidence: a.Evidence,
			})
		}
	}
	return newlyCreated, nil
}

// MarkAlertsReviewed records an operator's confirm/approve verdict
// immediately, at the moment Central queues the command to the sensor —
// see alertActions. The sensor's own eventual telemetry report of the
// same status change (once it processes the queued command) is a no-op
// against this thanks to upsertAlertHistory's status-downgrade guard.
func (r *Repository) MarkAlertsReviewed(ctx context.Context, sensorID string, alertKeys []string, status, actor string) error {
	if len(alertKeys) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE alert_history SET status=$3, approved_by=$4, approved_at=NOW()
		WHERE sensor_id=$1 AND alert_key = ANY($2)`,
		sensorID, alertKeys, status, actor,
	)
	return err
}

// AlertHistoryEntry is one row of alert_history — this is now the
// authoritative source for the Alerts tab (GET /v1/alerts), not
// sensor_telemetry.alerts, since that field can be a partial delta on
// any given sync and no longer represents "everything currently open."
type AlertHistoryEntry struct {
	SensorID   string
	AlertKey   string
	Type       string
	Severity   string
	Message    string
	IP         string
	Status     string
	ApprovedBy string
	ApprovedAt *time.Time
	Count      uint64
	FirstSeen  time.Time
	LastSeen   time.Time
	Evidence   map[string]interface{}
}

// AlertHistoryStats contains authoritative alert counters across the whole
// retained alert_history table. The Alerts UI intentionally loads only the
// most recent rows for responsiveness, so headline counters must not be
// derived from that truncated list.
type AlertHistoryStats struct {
	Total        int64 `json:"total"`
	Open         int64 `json:"open"`
	Confirmed    int64 `json:"confirmed"`
	Approved     int64 `json:"approved"`
	OpenCritical int64 `json:"open_critical"`
	OpenHigh     int64 `json:"open_high"`
	OpenMedium   int64 `json:"open_medium"`
	OpenLow      int64 `json:"open_low"`
	OpenInfo     int64 `json:"open_info"`
}

// GetAlertHistoryStats returns counts for every retained alert, independent of
// the 2,000-row presentation window used by ListAlertHistory.
func (r *Repository) GetAlertHistoryStats(ctx context.Context) (AlertHistoryStats, error) {
	var out AlertHistoryStats
	err := r.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status='new'),
			COUNT(*) FILTER (WHERE status='confirmed'),
			COUNT(*) FILTER (WHERE status='approved'),
			COUNT(*) FILTER (WHERE status='new' AND LOWER(severity)='critical'),
			COUNT(*) FILTER (WHERE status='new' AND LOWER(severity)='high'),
			COUNT(*) FILTER (WHERE status='new' AND LOWER(severity)='medium'),
			COUNT(*) FILTER (WHERE status='new' AND LOWER(severity)='low'),
			COUNT(*) FILTER (WHERE status='new' AND LOWER(severity)='info')
		FROM alert_history`).Scan(
		&out.Total,
		&out.Open,
		&out.Confirmed,
		&out.Approved,
		&out.OpenCritical,
		&out.OpenHigh,
		&out.OpenMedium,
		&out.OpenLow,
		&out.OpenInfo,
	)
	return out, err
}

// AlertHistoryQuery describes a server-side Alerts-tab query. It deliberately
// keeps paging/filtering in PostgreSQL so operators can inspect every retained
// alert without making the browser download the entire alert_history table.
type AlertHistoryQuery struct {
	Search   string
	SensorID string
	Status   string
	Severity string
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
	Oldest   bool
}

// AlertHistoryPage is the paged response returned by GET /v1/alerts/search.
type AlertHistoryPage struct {
	Items  []AlertHistoryEntry `json:"items"`
	Total  int64               `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
}

// SearchAlertHistory searches the complete retained alert_history table.
// Unlike ListAlertHistory, this is intended for interactive investigation and
// therefore supports paging through every matching row.
func (r *Repository) SearchAlertHistory(ctx context.Context, q AlertHistoryQuery) (AlertHistoryPage, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 500 {
		q.Limit = 500
	}
	if q.Offset < 0 {
		q.Offset = 0
	}

	where := make([]string, 0, 8)
	args := make([]interface{}, 0, 10)
	add := func(value interface{}) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}

	if value := strings.TrimSpace(q.SensorID); value != "" {
		where = append(where, "sensor_id="+add(value))
	}
	if value := strings.ToLower(strings.TrimSpace(q.Status)); value != "" {
		where = append(where, "status="+add(value))
	}
	if value := strings.ToLower(strings.TrimSpace(q.Severity)); value != "" {
		where = append(where, "severity="+add(value))
	}
	if q.From != nil {
		where = append(where, "last_seen >= "+add(*q.From))
	}
	if q.To != nil {
		where = append(where, "last_seen < "+add(*q.To))
	}
	if value := strings.TrimSpace(q.Search); value != "" {
		pattern := "%" + value + "%"
		arg := add(pattern)
		where = append(where, "(sensor_id ILIKE "+arg+" OR alert_key ILIKE "+arg+" OR type ILIKE "+arg+" OR severity ILIKE "+arg+" OR message ILIKE "+arg+" OR ip ILIKE "+arg+")")
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_history"+whereSQL, args...).Scan(&total); err != nil {
		return AlertHistoryPage{}, err
	}

	order := "DESC"
	if q.Oldest {
		order = "ASC"
	}
	queryArgs := append([]interface{}{}, args...)
	limitArg := fmt.Sprintf("$%d", len(queryArgs)+1)
	queryArgs = append(queryArgs, q.Limit)
	offsetArg := fmt.Sprintf("$%d", len(queryArgs)+1)
	queryArgs = append(queryArgs, q.Offset)

	rows, err := r.db.QueryContext(ctx, `
		SELECT sensor_id,alert_key,type,severity,message,ip,status,approved_by,approved_at,count,first_seen,last_seen,evidence
		FROM alert_history`+whereSQL+`
		ORDER BY last_seen `+order+`, sensor_id ASC, alert_key ASC
		LIMIT `+limitArg+` OFFSET `+offsetArg, queryArgs...)
	if err != nil {
		return AlertHistoryPage{}, err
	}
	defer rows.Close()

	items := make([]AlertHistoryEntry, 0, q.Limit)
	for rows.Next() {
		var e AlertHistoryEntry
		var evidence []byte
		if err := rows.Scan(&e.SensorID, &e.AlertKey, &e.Type, &e.Severity, &e.Message, &e.IP, &e.Status, &e.ApprovedBy, &e.ApprovedAt, &e.Count, &e.FirstSeen, &e.LastSeen, &evidence); err != nil {
			return AlertHistoryPage{}, err
		}
		_ = json.Unmarshal(evidence, &e.Evidence)
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return AlertHistoryPage{}, err
	}

	return AlertHistoryPage{Items: items, Total: total, Limit: q.Limit, Offset: q.Offset}, nil
}

// ListAlertHistory returns a lightweight newest-first snapshot used by
// dashboard/correlation-adjacent views. The operational Alerts tab uses
// SearchAlertHistory so it can page through every retained row without a
// 2,000-alert visibility ceiling.
func (r *Repository) ListAlertHistory(ctx context.Context, limit int) ([]AlertHistoryEntry, error) {
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT sensor_id,alert_key,type,severity,message,ip,status,approved_by,approved_at,count,first_seen,last_seen,evidence
		FROM alert_history ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AlertHistoryEntry, 0)
	for rows.Next() {
		var e AlertHistoryEntry
		var evidence []byte
		if err := rows.Scan(&e.SensorID, &e.AlertKey, &e.Type, &e.Severity, &e.Message, &e.IP, &e.Status, &e.ApprovedBy, &e.ApprovedAt, &e.Count, &e.FirstSeen, &e.LastSeen, &evidence); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidence, &e.Evidence)
		out = append(out, e)
	}
	return out, rows.Err()
}

func jsonObject(value interface{}) string {
	data, _ := json.Marshal(value)
	if len(data) == 0 || string(data) == "null" {
		return "{}"
	}
	return string(data)
}
