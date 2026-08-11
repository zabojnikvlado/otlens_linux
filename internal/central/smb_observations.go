package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/zabojnikvlado/otlens_linux/internal/smb"
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
			continue
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO smb_observations(sensor_id,observed_at,client_ip,server_ip,client_port,server_port,dialect,command,message_id,session_id,tree_id,file_id_persistent,file_id_volatile,request_command,request_matched,stream_gapped,stream_resynced,share_name,file_name,named_pipe,direction,bytes,status,is_response,is_admin_share,is_executable,is_script,is_encrypted) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28) ON CONFLICT DO NOTHING`, sensorID, at, o.ClientIP, o.ServerIP, o.ClientPort, o.ServerPort, o.Dialect, o.Command, o.MessageID, o.SessionID, o.TreeID, o.FileIDPersistent, o.FileIDVolatile, o.RequestCommand, o.RequestMatched, o.StreamGapped, o.StreamResynced, o.ShareName, o.FileName, o.NamedPipe, o.Direction, o.Bytes, o.Status, o.IsResponse, o.IsAdminShare, o.IsExecutable, o.IsScript, o.IsEncrypted)
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

func (r *Repository) ListSMBObservations(ctx context.Context, sensorID, clientIP, serverIP, artifact, search string, limit int) ([]SMBObservationRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,sensor_id,observed_at,client_ip,server_ip,client_port,server_port,dialect,command,message_id,session_id,tree_id,file_id_persistent,file_id_volatile,request_command,request_matched,stream_gapped,stream_resynced,share_name,file_name,named_pipe,direction,bytes,status,is_response,is_admin_share,is_executable,is_script,is_encrypted
FROM smb_observations
WHERE ($1='' OR sensor_id=$1)
  AND ($2='' OR client_ip=$2)
  AND ($3='' OR server_ip=$3)
  AND ($4='' OR share_name ILIKE '%'||$4||'%' OR file_name ILIKE '%'||$4||'%' OR named_pipe ILIKE '%'||$4||'%')
  AND ($5='' OR client_ip ILIKE '%'||$5||'%' OR server_ip ILIKE '%'||$5||'%' OR command ILIKE '%'||$5||'%' OR share_name ILIKE '%'||$5||'%' OR file_name ILIKE '%'||$5||'%' OR named_pipe ILIKE '%'||$5||'%' OR status ILIKE '%'||$5||'%')
ORDER BY observed_at DESC LIMIT $6`, sensorID, clientIP, serverIP, artifact, search, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SMBObservationRow
	for rows.Next() {
		var x SMBObservationRow
		if err := rows.Scan(&x.ID, &x.SensorID, &x.Timestamp, &x.ClientIP, &x.ServerIP, &x.ClientPort, &x.ServerPort, &x.Dialect, &x.Command, &x.MessageID, &x.SessionID, &x.TreeID, &x.FileIDPersistent, &x.FileIDVolatile, &x.RequestCommand, &x.RequestMatched, &x.StreamGapped, &x.StreamResynced, &x.ShareName, &x.FileName, &x.NamedPipe, &x.Direction, &x.Bytes, &x.Status, &x.IsResponse, &x.IsAdminShare, &x.IsExecutable, &x.IsScript, &x.IsEncrypted); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
