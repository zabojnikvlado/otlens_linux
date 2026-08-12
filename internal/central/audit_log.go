package central

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AuditEntry struct {
	ID        int64
	Actor     string
	Action    string
	Method    string
	Path      string
	Status    int
	Success   bool
	SourceIP  string
	SensorID  string
	CreatedAt time.Time
}

type AuditFilter struct {
	Limit    int
	Offset   int
	Actor    string
	Action   string
	SensorID string
	Success  *bool
}

func (r *Repository) InsertAuditLog(ctx context.Context, e AuditEntry) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO audit_log(actor,action,method,path,status,success,source_ip,sensor_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id,created_at`,
		e.Actor, e.Action, e.Method, e.Path, e.Status, e.Success, e.SourceIP, e.SensorID,
	).Scan(&e.ID, &e.CreatedAt); err != nil {
		return err
	}
	if r.siemAuditEnabled {
		source := strings.TrimSpace(r.siemSource)
		if source == "" {
			source = "otlens-central"
		}
		eventKey := fmt.Sprintf("audit:%d", e.ID)
		payload := map[string]interface{}{
			"schema_version": "otlens.siem.v1",
			"event_id":       eventKey,
			"source":         source,
			"kind":           "audit",
			"event_time":     e.CreatedAt.UTC(),
			"audit": map[string]interface{}{
				"id":        e.ID,
				"actor":     e.Actor,
				"action":    e.Action,
				"method":    e.Method,
				"path":      e.Path,
				"status":    e.Status,
				"success":   e.Success,
				"source_ip": e.SourceIP,
				"sensor_id": e.SensorID,
			},
		}
		encoded, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO siem_outbox(event_key,kind,payload) VALUES($1,'audit',$2) ON CONFLICT(event_key) DO NOTHING`, eventKey, encoded); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) ListAuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	return r.ListAuditLogFiltered(ctx, AuditFilter{Limit: limit})
}

func (r *Repository) ListAuditLogFiltered(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 250
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := []string{"1=1"}
	args := []interface{}{}
	add := func(clause string, value interface{}) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if strings.TrimSpace(f.Actor) != "" {
		add("actor ILIKE '%%' || $%d || '%%'", strings.TrimSpace(f.Actor))
	}
	if strings.TrimSpace(f.Action) != "" {
		args = append(args, strings.TrimSpace(f.Action))
		n := len(args)
		where = append(where, fmt.Sprintf("(action ILIKE '%%' || $%d || '%%' OR path ILIKE '%%' || $%d || '%%')", n, n))
	}
	if strings.TrimSpace(f.SensorID) != "" {
		add("sensor_id ILIKE '%%' || $%d || '%%'", strings.TrimSpace(f.SensorID))
	}
	if f.Success != nil {
		add("success=$%d", *f.Success)
	}
	args = append(args, f.Limit, f.Offset)
	q := fmt.Sprintf(`SELECT id,actor,action,method,path,status,success,source_ip,sensor_id,created_at FROM audit_log WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, strings.Join(where, " AND "), len(args)-1, len(args))
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditEntry, 0)
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Method, &e.Path, &e.Status, &e.Success, &e.SourceIP, &e.SensorID, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
