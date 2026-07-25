package central

import (
	"context"
	"time"
)

// AuditEntry is one row of audit_log — see that table's doc comment in
// the embedded schema for why it's independent of siem_outbox.
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

func (r *Repository) InsertAuditLog(ctx context.Context, e AuditEntry) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_log(actor,action,method,path,status,success,source_ip,sensor_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		e.Actor, e.Action, e.Method, e.Path, e.Status, e.Success, e.SourceIP, e.SensorID,
	)
	return err
}

// ListAuditLog returns the most recent audit entries, newest first —
// this is what the Audit tab shows.
func (r *Repository) ListAuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id,actor,action,method,path,status,success,source_ip,sensor_id,created_at
		FROM audit_log ORDER BY created_at DESC LIMIT $1`, limit)
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
