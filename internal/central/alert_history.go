package central

import (
	"context"
	"encoding/json"
	"time"
)

// telemetryAlert mirrors the JSON shape of detect.Alert as reported in
// sensor_telemetry.alerts — kept as a local, minimal copy rather than
// importing internal/detect, since Central only needs a handful of
// fields out of it and doesn't otherwise depend on the sensor's
// detection engine package.
type telemetryAlert struct {
	ID        string    `json:"ID"`
	Type      string    `json:"Type"`
	Severity  string    `json:"Severity"`
	Message   string    `json:"Message"`
	IP        string    `json:"IP"`
	FirstSeen time.Time `json:"FirstSeen"`
	LastSeen  time.Time `json:"LastSeen"`
	Status    string    `json:"Status"`
}

// upsertAlertHistory folds this sync's reported alerts into the durable
// alert_history table — same reasoning as topology_edges/topology_nodes:
// sensor_telemetry.alerts is a single JSONB array per sensor, wholesale
// overwritten on every sync, so it has no per-alert timestamp for
// database_retention to prune by on its own. Runs inside PutTelemetry's
// existing transaction. status is taken from the sensor's report but
// never downgrades a status Central already recorded via
// MarkAlertsReviewed — an operator's "confirmed"/"approved" verdict
// shouldn't flip back to "new" just because the sensor's own copy
// hasn't caught up yet on this particular sync.
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
		if _, err := x.ExecContext(ctx, `
			INSERT INTO alert_history(sensor_id,alert_key,type,severity,message,ip,status,first_seen,last_seen)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT(sensor_id,alert_key) DO UPDATE SET
				type = EXCLUDED.type,
				severity = EXCLUDED.severity,
				message = EXCLUDED.message,
				ip = EXCLUDED.ip,
				status = CASE WHEN alert_history.status IN ('confirmed','approved') THEN alert_history.status ELSE EXCLUDED.status END,
				first_seen = LEAST(alert_history.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(alert_history.last_seen, EXCLUDED.last_seen)
		`, sensorID, a.ID, a.Type, a.Severity, a.Message, a.IP, status, firstSeen, lastSeen); err != nil {
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

// AlertHistoryEntry is one row of alert_history, for the Audit/backup
// surfaces that read it directly (as opposed to the live Alerts tab,
// which reads sensor_telemetry.alerts).
type AlertHistoryEntry struct {
	SensorID    string
	AlertKey    string
	Type        string
	Severity    string
	Message     string
	IP          string
	Status      string
	ApprovedBy  string
	ApprovedAt  *time.Time
	FirstSeen   time.Time
	LastSeen    time.Time
}

func (r *Repository) ListAlertHistory(ctx context.Context, limit int) ([]AlertHistoryEntry, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT sensor_id,alert_key,type,severity,message,ip,status,approved_by,approved_at,first_seen,last_seen
		FROM alert_history ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AlertHistoryEntry, 0)
	for rows.Next() {
		var e AlertHistoryEntry
		if err := rows.Scan(&e.SensorID, &e.AlertKey, &e.Type, &e.Severity, &e.Message, &e.IP, &e.Status, &e.ApprovedBy, &e.ApprovedAt, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
