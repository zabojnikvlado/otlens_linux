package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/zabojnikvlado/otlens_linux/internal/smb"
	"time"
)

func persistSMBObservations(ctx context.Context, tx *sql.Tx, sensorID string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var rows []smb.Observation
	if err := json.Unmarshal(raw, &rows); err != nil {
		return err
	}
	for _, o := range rows {
		at := o.Timestamp
		if at.IsZero() {
			at = time.Now().UTC()
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO smb_observations(sensor_id,observed_at,client_ip,server_ip,client_port,server_port,command,message_id,session_id,tree_id,share_name,file_name,named_pipe,direction,bytes,status,is_response,is_admin_share,is_executable,is_script,is_encrypted) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT(sensor_id,observed_at,client_ip,server_ip,message_id,command,is_response) DO NOTHING`, sensorID, at, o.ClientIP, o.ServerIP, o.ClientPort, o.ServerPort, o.Command, o.MessageID, o.SessionID, o.TreeID, o.ShareName, o.FileName, o.NamedPipe, o.Direction, o.Bytes, o.Status, o.IsResponse, o.IsAdminShare, o.IsExecutable, o.IsScript, o.IsEncrypted)
		if err != nil {
			return err
		}
	}
	return nil
}

type SMBObservationRow struct {
	ID       int64  `json:"id"`
	SensorID string `json:"sensor_id"`
	smb.Observation
}

func (r *Repository) ListSMBObservations(ctx context.Context, sensorID, clientIP, serverIP, artifact string, limit int) ([]SMBObservationRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,sensor_id,observed_at,client_ip,server_ip,client_port,server_port,command,message_id,session_id,tree_id,share_name,file_name,named_pipe,direction,bytes,status,is_response,is_admin_share,is_executable,is_script,is_encrypted FROM smb_observations WHERE ($1='' OR sensor_id=$1) AND ($2='' OR client_ip=$2) AND ($3='' OR server_ip=$3) AND ($4='' OR share_name ILIKE '%'||$4||'%' OR file_name ILIKE '%'||$4||'%' OR named_pipe ILIKE '%'||$4||'%') ORDER BY observed_at DESC LIMIT $5`, sensorID, clientIP, serverIP, artifact, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SMBObservationRow
	for rows.Next() {
		var x SMBObservationRow
		if err := rows.Scan(&x.ID, &x.SensorID, &x.Timestamp, &x.ClientIP, &x.ServerIP, &x.ClientPort, &x.ServerPort, &x.Command, &x.MessageID, &x.SessionID, &x.TreeID, &x.ShareName, &x.FileName, &x.NamedPipe, &x.Direction, &x.Bytes, &x.Status, &x.IsResponse, &x.IsAdminShare, &x.IsExecutable, &x.IsScript, &x.IsEncrypted); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
