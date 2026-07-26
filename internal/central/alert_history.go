package central

import (
	"context"
	"encoding/json"
	"time"
)

// telemetryAlert mirrors the JSON shape of detect.Alert as reported by a
// sensor — kept as a local, minimal copy rather than importing
// internal/detect, since Central only needs a handful of fields out of
// it and doesn't otherwise depend on the sensor's detection engine
// package.
type telemetryAlert struct {
	ID        string    `json:"ID"`
	Type      string    `json:"Type"`
	Severity  string    `json:"Severity"`
	Message   string    `json:"Message"`
	IP        string    `json:"IP"`
	FirstSeen time.Time `json:"FirstSeen"`
	LastSeen  time.Time `json:"LastSeen"`
	Count     uint64    `json:"Count"`
	Status    string    `json:"Status"`
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
func upsertAlertHistory(ctx context.Context, x execer, sensorID string, alertsJSON []byte) error {
	if len(alertsJSON) == 0 {
		return nil
	}
	var alerts []telemetryAlert
	if err := json.Unmarshal(alertsJSON, &alerts); err != nil {
		return nil // malformed/empty — nothing to record, not a sync failure
	}
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
		if _, err := x.ExecContext(ctx, `
			INSERT INTO alert_history(sensor_id,alert_key,type,severity,message,ip,status,count,first_seen,last_seen)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT(sensor_id,alert_key) DO UPDATE SET
				type = EXCLUDED.type,
				severity = EXCLUDED.severity,
				message = EXCLUDED.message,
				ip = EXCLUDED.ip,
				status = CASE WHEN alert_history.status IN ('confirmed','approved') THEN alert_history.status ELSE EXCLUDED.status END,
				count = GREATEST(alert_history.count, EXCLUDED.count),
				first_seen = LEAST(alert_history.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(alert_history.last_seen, EXCLUDED.last_seen)
		`, sensorID, a.ID, a.Type, a.Severity, a.Message, a.IP, status, count, firstSeen, lastSeen); err != nil {
			return err
		}
	}
	return nil
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
}

// ListAlertHistory returns the most recently active alerts, newest
// first. limit is generous (default/max 2000) since this backs the main
// Alerts tab rather than a paged report — but deliberately still capped,
// since a sensor that's accumulated tens of thousands of distinct
// findings shouldn't turn a routine page load into a multi-megabyte
// response every poll.
func (r *Repository) ListAlertHistory(ctx context.Context, limit int) ([]AlertHistoryEntry, error) {
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT sensor_id,alert_key,type,severity,message,ip,status,approved_by,approved_at,count,first_seen,last_seen
		FROM alert_history ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AlertHistoryEntry, 0)
	for rows.Next() {
		var e AlertHistoryEntry
		if err := rows.Scan(&e.SensorID, &e.AlertKey, &e.Type, &e.Severity, &e.Message, &e.IP, &e.Status, &e.ApprovedBy, &e.ApprovedAt, &e.Count, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
