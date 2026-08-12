package central

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const alertActivityWindow = 5 * time.Minute

func alertIsActive(status string, lastSeen, now time.Time) bool {
	return strings.ToLower(status) != "approved" && !lastSeen.IsZero() && now.Sub(lastSeen) <= alertActivityWindow
}

// telemetryAlert mirrors the JSON shape of detect.Alert as reported by a
// sensor — kept as a local, minimal copy rather than importing
// internal/detect, since Central only needs a handful of fields out of
// it and doesn't otherwise depend on the sensor's detection engine
// package.
type telemetryAlert struct {
	ID            string                 `json:"ID"`
	Type          string                 `json:"Type"`
	Severity      string                 `json:"Severity"`
	Message       string                 `json:"Message"`
	IP            string                 `json:"IP"`
	AssetIdentity string                 `json:"AssetIdentity,omitempty"`
	FirstSeen     time.Time              `json:"FirstSeen"`
	LastSeen      time.Time              `json:"LastSeen"`
	Count         uint64                 `json:"Count"`
	Status        string                 `json:"Status"`
	Evidence      map[string]interface{} `json:"Evidence,omitempty"`
}

// upsertAlertHistory folds this sync's reported alerts into the durable,
// per-alert alert_history table. As of the sensor-side dirty-tracking
// change (see detect.Engine.GetDirtyAlerts), what arrives here on a
// given sync is normally just the alerts that are new or changed since
// the sensor's last successful sync — not its entire alert set — which
// is exactly why this has to be an upsert-by-key, not a
// replace-the-whole-table operation: a partial report must only ever
// add to/update this table, never make it look like anything not
// mentioned in this batch has gone away. Status is taken from the sensor's
// report. An approved verdict is permanent. A confirmed verdict is protected from a stale sensor echo, but a genuinely
// new episode may reopen it: the sensor changes status back to new only while
// also incrementing the episode Count, which lets Central distinguish a real
// recurrence from an old pre-command payload.
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
		return nil, err
	}
	var newlyCreated []AlertHistoryEntry
	for _, a := range alerts {
		if a.ID == "" {
			continue
		}
		lastSeen := a.LastSeen
		if lastSeen.IsZero() {
			// A detection without an event timestamp cannot be safely ordered
			// against retained history. Do not manufacture a fresh active alert.
			continue
		}
		firstSeen := a.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = lastSeen
		}
		status := a.Status
		if status == "" {
			status = "new"
		}
		count := a.Count
		if count == 0 {
			count = 1
		}
		identity := strings.TrimSpace(a.AssetIdentity)
		if identity == "" && a.Evidence != nil {
			if v, ok := a.Evidence["asset_identity"].(string); ok {
				identity = strings.TrimSpace(v)
			}
		}
		if identity == "" && a.IP != "" {
			_ = x.QueryRowContext(ctx, `SELECT asset_identity FROM asset_ip_binding_history WHERE sensor_id=$1 AND ip=$2 AND valid_from<=$3 AND (valid_to IS NULL OR valid_to>=$3) ORDER BY CASE provenance WHEN 'arp' THEN 0 ELSE 1 END,last_observed DESC LIMIT 1`, sensorID, a.IP, lastSeen).Scan(&identity)
		}
		if identity == "" && a.IP != "" {
			identity = canonicalAssetIdentity("", a.IP)
		}
		var wasInserted bool
		err := x.QueryRowContext(ctx, `
			INSERT INTO alert_history(sensor_id,alert_key,type,severity,message,ip,asset_identity,status,count,first_seen,last_seen,evidence)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT(sensor_id,alert_key) DO UPDATE SET
				type = CASE WHEN EXCLUDED.last_seen >= alert_history.last_seen THEN EXCLUDED.type ELSE alert_history.type END,
				severity = CASE WHEN EXCLUDED.last_seen >= alert_history.last_seen THEN EXCLUDED.severity ELSE alert_history.severity END,
				message = CASE WHEN EXCLUDED.last_seen >= alert_history.last_seen THEN EXCLUDED.message ELSE alert_history.message END,
				ip = CASE WHEN EXCLUDED.last_seen >= alert_history.last_seen THEN EXCLUDED.ip ELSE alert_history.ip END,
				asset_identity = CASE WHEN EXCLUDED.last_seen >= alert_history.last_seen AND EXCLUDED.asset_identity<>'' THEN EXCLUDED.asset_identity ELSE alert_history.asset_identity END,
				status = CASE
					WHEN EXCLUDED.last_seen < alert_history.last_seen THEN alert_history.status
					WHEN alert_history.status='approved' THEN alert_history.status
					WHEN alert_history.status='confirmed' AND EXCLUDED.status='new' AND EXCLUDED.count<=alert_history.count THEN alert_history.status
					ELSE EXCLUDED.status
				END,
				count = GREATEST(alert_history.count, EXCLUDED.count),
				first_seen = LEAST(alert_history.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(alert_history.last_seen, EXCLUDED.last_seen),
				evidence = CASE WHEN EXCLUDED.last_seen >= alert_history.last_seen THEN EXCLUDED.evidence ELSE alert_history.evidence END
			RETURNING (xmax = 0) AS inserted
		`, sensorID, a.ID, a.Type, a.Severity, a.Message, a.IP, identity, status, count, firstSeen, lastSeen, jsonObject(a.Evidence)).Scan(&wasInserted)
		if err != nil {
			return newlyCreated, err
		}
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
	Active     bool `json:"Active"`
}

// AlertHistoryStats contains authoritative alert counters across the whole
// retained alert_history table. The Alerts UI intentionally loads only the
// most recent rows for responsiveness, so headline counters must not be
// derived from that truncated list.
type AlertHistoryStats struct {
	Total        int64 `json:"total"`
	Open         int64 `json:"open"` // compatibility: currently active, non-approved alerts
	Active       int64 `json:"active"`
	Resolved     int64 `json:"resolved"`
	Unreviewed   int64 `json:"unreviewed"`
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
			COUNT(*) FILTER (WHERE status<>'approved' AND last_seen >= NOW()-INTERVAL '5 minutes'),
			COUNT(*) FILTER (WHERE status<>'approved' AND last_seen >= NOW()-INTERVAL '5 minutes'),
			COUNT(*) FILTER (WHERE status='approved' OR last_seen < NOW()-INTERVAL '5 minutes'),
			COUNT(*) FILTER (WHERE status='new'),
			COUNT(*) FILTER (WHERE status='confirmed'),
			COUNT(*) FILTER (WHERE status='approved'),
			COUNT(*) FILTER (WHERE status<>'approved' AND last_seen >= NOW()-INTERVAL '5 minutes' AND LOWER(severity)='critical'),
			COUNT(*) FILTER (WHERE status<>'approved' AND last_seen >= NOW()-INTERVAL '5 minutes' AND LOWER(severity)='high'),
			COUNT(*) FILTER (WHERE status<>'approved' AND last_seen >= NOW()-INTERVAL '5 minutes' AND LOWER(severity)='medium'),
			COUNT(*) FILTER (WHERE status<>'approved' AND last_seen >= NOW()-INTERVAL '5 minutes' AND LOWER(severity)='low'),
			COUNT(*) FILTER (WHERE status<>'approved' AND last_seen >= NOW()-INTERVAL '5 minutes' AND LOWER(severity)='info')
		FROM alert_history`).Scan(
		&out.Total, &out.Open, &out.Active, &out.Resolved, &out.Unreviewed,
		&out.Confirmed, &out.Approved,
		&out.OpenCritical, &out.OpenHigh, &out.OpenMedium, &out.OpenLow, &out.OpenInfo,
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
	Activity string
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
	if value := strings.ToLower(strings.TrimSpace(q.Activity)); value != "" {
		switch value {
		case "active":
			where = append(where, "status<>'approved' AND last_seen >= NOW()-INTERVAL '5 minutes'")
		case "resolved":
			where = append(where, "(status='approved' OR last_seen < NOW()-INTERVAL '5 minutes')")
		}
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
		e.Active = alertIsActive(e.Status, e.LastSeen, time.Now())
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
		e.Active = alertIsActive(e.Status, e.LastSeen, time.Now())
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListBehaviorAlertHistory reads behavior findings directly instead of taking
// a slice of the newest alerts of every type. This prevents unrelated alert
// volume from pushing still-retained behavior findings out of the NBA view.
func (r *Repository) ListBehaviorAlertHistory(ctx context.Context, limit int, activeOnly bool) ([]AlertHistoryEntry, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	activeSQL := ""
	if activeOnly {
		activeSQL = " AND status<>'approved' AND last_seen >= NOW()-INTERVAL '5 minutes'"
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT sensor_id,alert_key,type,severity,message,ip,status,approved_by,approved_at,count,first_seen,last_seen,evidence
		FROM alert_history WHERE type LIKE 'behavior\_%' ESCAPE '\'`+activeSQL+` ORDER BY last_seen DESC LIMIT $1`, limit)
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
		e.Active = alertIsActive(e.Status, e.LastSeen, time.Now())
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *Repository) BehaviorAlertHistoryByKey(ctx context.Context, sensorID, alertKey string) (AlertHistoryEntry, error) {
	var e AlertHistoryEntry
	var evidence []byte
	err := r.db.QueryRowContext(ctx, `SELECT sensor_id,alert_key,type,severity,message,ip,status,approved_by,approved_at,count,first_seen,last_seen,evidence
		FROM alert_history WHERE sensor_id=$1 AND alert_key=$2 AND type LIKE 'behavior\_%' ESCAPE '\'`, sensorID, alertKey).Scan(
		&e.SensorID, &e.AlertKey, &e.Type, &e.Severity, &e.Message, &e.IP, &e.Status, &e.ApprovedBy, &e.ApprovedAt, &e.Count, &e.FirstSeen, &e.LastSeen, &evidence)
	if err != nil {
		return e, err
	}
	_ = json.Unmarshal(evidence, &e.Evidence)
	e.Active = alertIsActive(e.Status, e.LastSeen, time.Now())
	return e, nil
}

func jsonObject(value interface{}) string {
	data, _ := json.Marshal(value)
	if len(data) == 0 || string(data) == "null" {
		return "{}"
	}
	return string(data)
}

// ListAssetAlertHistory returns retained alerts that reference the current
// stable identity of an asset. It resolves every IP alias owned by the
// identity and matches only structured alert fields/evidence keys so Asset
// 360 does not depend on the browser's truncated global alert list or on
// substring matching (for example 10.1.1.1 accidentally matching
// 10.1.1.10).
func (r *Repository) ListAssetAlertHistory(ctx context.Context, sensorID, assetIP string, limit int) ([]AlertHistoryEntry, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	identity, err := r.ResolveAssetIdentity(ctx, sensorID, assetIP)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT sensor_id,alert_key,type,severity,message,ip,status,approved_by,approved_at,count,first_seen,last_seen,evidence
		FROM alert_history a
		WHERE sensor_id=$1 AND (
			a.asset_identity=$2 OR
			(a.asset_identity='' AND EXISTS (
				SELECT 1 FROM asset_ip_binding_history b
				WHERE b.sensor_id=a.sensor_id AND b.asset_identity=$2
				  AND b.valid_from<=a.last_seen AND (b.valid_to IS NULL OR b.valid_to>=a.first_seen)
				  AND b.ip IN (a.ip,COALESCE(a.evidence->>'source_ip',''),COALESCE(a.evidence->>'destination_ip',''),COALESCE(a.evidence->>'target_ip',''),COALESCE(a.evidence->>'peer_ip',''),COALESCE(a.evidence->>'controller_ip',''),COALESCE(a.evidence->>'origin_ip',''),COALESCE(a.evidence->>'pivot_ip',''),COALESCE(a.evidence->>'latest_target',''))
			))
		)
		ORDER BY last_seen DESC, alert_key ASC LIMIT $3`, sensorID, identity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AlertHistoryEntry, 0)
	now := time.Now()
	for rows.Next() {
		var e AlertHistoryEntry
		var evidence []byte
		if err := rows.Scan(&e.SensorID, &e.AlertKey, &e.Type, &e.Severity, &e.Message, &e.IP, &e.Status, &e.ApprovedBy, &e.ApprovedAt, &e.Count, &e.FirstSeen, &e.LastSeen, &evidence); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidence, &e.Evidence)
		e.Active = alertIsActive(e.Status, e.LastSeen, now)
		out = append(out, e)
	}
	return out, rows.Err()
}
