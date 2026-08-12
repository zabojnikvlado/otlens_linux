package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

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

	// A sensor can retain thousands of SMB observations. Persist them in bounded
	// multi-row statements rather than one SQL round trip per observation.
	const writeBatch = 1000
	valid := make([]smb.Observation, 0, len(rows))
	for _, o := range rows {
		if o.Timestamp.IsZero() {
			continue
		}
		valid = append(valid, o)
	}
	for start := 0; start < len(valid); start += writeBatch {
		end := start + writeBatch
		if end > len(valid) {
			end = len(valid)
		}
		args := make([]interface{}, 0, (end-start)*28)
		values := make([]string, 0, end-start)
		for _, o := range valid[start:end] {
			values = append(values, appendSQLTuple(&args,
				sensorID, o.Timestamp, o.ClientIP, o.ServerIP, o.ClientPort, o.ServerPort, o.Dialect, o.Command,
				o.MessageID, o.SessionID, o.TreeID, o.FileIDPersistent, o.FileIDVolatile, o.RequestCommand,
				o.RequestMatched, o.StreamGapped, o.StreamResynced, o.ShareName, o.FileName, o.NamedPipe,
				o.Direction, o.Bytes, o.Status, o.IsResponse, o.IsAdminShare, o.IsExecutable, o.IsScript, o.IsEncrypted,
			))
		}
		if len(values) == 0 {
			continue
		}
		q := `INSERT INTO smb_observations(sensor_id,observed_at,client_ip,server_ip,client_port,server_port,dialect,command,message_id,session_id,tree_id,file_id_persistent,file_id_volatile,request_command,request_matched,stream_gapped,stream_resynced,share_name,file_name,named_pipe,direction,bytes,status,is_response,is_admin_share,is_executable,is_script,is_encrypted) VALUES ` + strings.Join(values, ",") + ` ON CONFLICT DO NOTHING`
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
	}
	return nil
}

type SMBObservationRow struct {
	ID             int64     `json:"id"`
	SensorID       string    `json:"sensor_id"`
	EvidenceSource string    `json:"evidence_source,omitempty"`
	FlowID         string    `json:"flow_id,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitempty"`
	LastSeen       time.Time `json:"last_seen,omitempty"`
	Packets        uint64    `json:"packets,omitempty"`
	smb.Observation
}

// SMBDashboardStats is a lightweight dashboard aggregate. It deliberately
// avoids loading hundreds or thousands of full SMB evidence rows just to
// render one KPI card.
type SMBDashboardStats struct {
	RiskActivity int64     `json:"risk_activity"`
	DecodedRows  int64     `json:"decoded_rows"`
	LastObserved time.Time `json:"last_observed,omitempty"`
}

func (r *Repository) SMBDashboardStats(ctx context.Context) (SMBDashboardStats, error) {
	var out SMBDashboardStats
	var last sql.NullTime
	err := r.db.QueryRowContext(ctx, `
SELECT
 COUNT(*) FILTER (WHERE is_admin_share OR is_executable OR is_script OR named_pipe<>'') AS risk_activity,
 COUNT(*) AS decoded_rows,
 MAX(observed_at) AS last_observed
FROM smb_observations
WHERE observed_at >= NOW() - INTERVAL '24 hours'`).Scan(&out.RiskActivity, &out.DecodedRows, &last)
	if err != nil {
		return out, err
	}
	if last.Valid {
		out.LastObserved = last.Time
	}
	return out, nil
}

func parseSMBUint(raw string, bits int, field string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(raw, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", field, raw, err)
	}
	return v, nil
}

func (r *Repository) ListSMBObservations(ctx context.Context, sensorID, clientIP, serverIP, artifact, search string, limit int) ([]SMBObservationRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	where := []string{"1=1"}
	args := make([]interface{}, 0, 6)
	add := func(expr string, value interface{}) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(expr, len(args)))
	}
	if sensorID != "" {
		add("sensor_id=$%d", sensorID)
	}
	if clientIP != "" {
		add("client_ip=$%d", clientIP)
	}
	if serverIP != "" {
		add("server_ip=$%d", serverIP)
	}
	if artifact != "" {
		args = append(args, artifact)
		n := len(args)
		where = append(where, fmt.Sprintf("(share_name ILIKE '%%'||$%d||'%%' OR file_name ILIKE '%%'||$%d||'%%' OR named_pipe ILIKE '%%'||$%d||'%%')", n, n, n))
	}
	if search != "" {
		args = append(args, search)
		n := len(args)
		where = append(where, fmt.Sprintf("(client_ip ILIKE '%%'||$%d||'%%' OR server_ip ILIKE '%%'||$%d||'%%' OR command ILIKE '%%'||$%d||'%%' OR share_name ILIKE '%%'||$%d||'%%' OR file_name ILIKE '%%'||$%d||'%%' OR named_pipe ILIKE '%%'||$%d||'%%' OR status::text ILIKE '%%'||$%d||'%%')", n, n, n, n, n, n, n))
	}
	args = append(args, limit)
	limitArg := len(args)
	// NUMERIC(20,0) is used for SMB's unsigned 64-bit identifiers. Different
	// database/sql drivers expose PostgreSQL NUMERIC differently (string,
	// []byte or driver-specific numeric values), and scanning it directly into
	// uint64 is therefore not portable. Cast all unsigned SMB fields to text (or
	// signed bigint where the schema guarantees the range) and convert explicitly.
	query := `SELECT id,sensor_id,observed_at,client_ip,server_ip,
client_port::bigint,server_port::bigint,dialect,command,message_id::text,session_id::text,tree_id::bigint,
file_id_persistent::text,file_id_volatile::text,request_command,request_matched,stream_gapped,stream_resynced,
share_name,file_name,named_pipe,direction,bytes::bigint,status::bigint,is_response,is_admin_share,is_executable,is_script,is_encrypted
FROM smb_observations
WHERE ` + strings.Join(where, " AND ") + fmt.Sprintf(" ORDER BY observed_at DESC LIMIT $%d", limitArg)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SMBObservationRow, 0, limit)
	for rows.Next() {
		var x SMBObservationRow
		var clientPort, serverPort, treeID, byteCount, status int64
		var messageIDRaw, sessionIDRaw, filePersistentRaw, fileVolatileRaw string
		if err := rows.Scan(&x.ID, &x.SensorID, &x.Timestamp, &x.ClientIP, &x.ServerIP,
			&clientPort, &serverPort, &x.Dialect, &x.Command, &messageIDRaw, &sessionIDRaw, &treeID,
			&filePersistentRaw, &fileVolatileRaw, &x.RequestCommand, &x.RequestMatched, &x.StreamGapped, &x.StreamResynced,
			&x.ShareName, &x.FileName, &x.NamedPipe, &x.Direction, &byteCount, &status, &x.IsResponse,
			&x.IsAdminShare, &x.IsExecutable, &x.IsScript, &x.IsEncrypted); err != nil {
			return nil, err
		}
		if clientPort < 0 || clientPort > 65535 || serverPort < 0 || serverPort > 65535 ||
			treeID < 0 || treeID > int64(^uint32(0)) || status < 0 || status > int64(^uint32(0)) || byteCount < 0 {
			// A single malformed retained row must not make the whole SMB Explorer
			// unavailable. Skip it and continue with the remaining evidence.
			continue
		}
		messageID, e1 := parseSMBUint(messageIDRaw, 64, "message_id")
		sessionID, e2 := parseSMBUint(sessionIDRaw, 64, "session_id")
		filePersistent, e3 := parseSMBUint(filePersistentRaw, 64, "file_id_persistent")
		fileVolatile, e4 := parseSMBUint(fileVolatileRaw, 64, "file_id_volatile")
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			continue
		}
		x.ClientPort = uint16(clientPort)
		x.ServerPort = uint16(serverPort)
		x.TreeID = uint32(treeID)
		x.Status = uint32(status)
		x.Bytes = uint64(byteCount)
		x.MessageID = messageID
		x.SessionID = sessionID
		x.FileIDPersistent = filePersistent
		x.FileIDVolatile = fileVolatile
		x.EvidenceSource = "decoded"
		x.FirstSeen = x.Timestamp
		x.LastSeen = x.Timestamp
		out = append(out, x)
	}
	return out, rows.Err()
}

// ListSMBTransportEvidence returns TCP/445 relationships from the flow ledger.
// It intentionally does not claim that SMB payload was decoded. This is the
// visibility fallback for encrypted SMB3 sessions, mid-stream captures and
// packet-loss cases where transport evidence exists but the SMB record parser
// cannot safely reconstruct an application message.
func (r *Repository) ListSMBTransportEvidence(ctx context.Context, sensorID, clientIP, serverIP, search string, limit int) ([]SMBObservationRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	where := []string{"protocol='TCP'", "(responder_port=445 OR initiator_port=445 OR dst_port=445 OR src_port=445)"}
	args := make([]interface{}, 0, 6)
	if sensorID != "" {
		args = append(args, sensorID)
		where = append(where, fmt.Sprintf("sensor_id=$%d", len(args)))
	}
	clientExpr := `CASE WHEN responder_port=445 THEN COALESCE(NULLIF(initiator_ip,''),src_ip) WHEN initiator_port=445 THEN COALESCE(NULLIF(responder_ip,''),dst_ip) WHEN dst_port=445 THEN src_ip ELSE dst_ip END`
	serverExpr := `CASE WHEN responder_port=445 THEN COALESCE(NULLIF(responder_ip,''),dst_ip) WHEN initiator_port=445 THEN COALESCE(NULLIF(initiator_ip,''),src_ip) WHEN dst_port=445 THEN dst_ip ELSE src_ip END`
	clientPortExpr := `CASE WHEN responder_port=445 THEN COALESCE(NULLIF(initiator_port,0),src_port) WHEN initiator_port=445 THEN COALESCE(NULLIF(responder_port,0),dst_port) WHEN dst_port=445 THEN src_port ELSE dst_port END`
	if clientIP != "" {
		args = append(args, clientIP)
		where = append(where, fmt.Sprintf("%s=$%d", clientExpr, len(args)))
	}
	if serverIP != "" {
		args = append(args, serverIP)
		where = append(where, fmt.Sprintf("%s=$%d", serverExpr, len(args)))
	}
	if search != "" {
		args = append(args, search)
		n := len(args)
		where = append(where, fmt.Sprintf("(%s ILIKE '%%'||$%d||'%%' OR %s ILIKE '%%'||$%d||'%%' OR flow_id ILIKE '%%'||$%d||'%%')", clientExpr, n, serverExpr, n, n))
	}

	// The old fallback grouped the entire retained TCP/445 flow ledger before
	// applying LIMIT. On installations with millions of one-minute flow buckets
	// that can turn one SMB page load into a long-running aggregate. Read a
	// bounded newest-first candidate window through the partial SMB index and
	// merge buckets per flow in Go instead. Transport evidence is a visibility
	// fallback; exact long-term byte totals belong to Traffic Analytics.
	candidateLimit := limit * 8
	if candidateLimit < limit {
		candidateLimit = limit
	}
	if candidateLimit > 25000 {
		candidateLimit = 25000
	}
	args = append(args, candidateLimit)
	limitArg := len(args)
	query := fmt.Sprintf(`SELECT sensor_id,flow_id,%s AS client_ip,%s AS server_ip,%s AS client_port,
bucket_start,bucket_end,packets::bigint,bytes::bigint
FROM flow_observations
WHERE %s
ORDER BY bucket_end DESC
LIMIT $%d`, clientExpr, serverExpr, clientPortExpr, strings.Join(where, " AND "), limitArg)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type aggregate struct{ row SMBObservationRow }
	byFlow := make(map[string]*aggregate, limit)
	order := make([]string, 0, limit)
	for rows.Next() {
		var sensor, flowID, cip, sip string
		var clientPort, packets, byteCount int64
		var first, last time.Time
		if err := rows.Scan(&sensor, &flowID, &cip, &sip, &clientPort, &first, &last, &packets, &byteCount); err != nil {
			return nil, err
		}
		if clientPort < 0 || clientPort > 65535 || packets < 0 || byteCount < 0 {
			continue
		}
		key := sensor + "\x00" + flowID + "\x00" + cip + "\x00" + sip
		a := byFlow[key]
		if a == nil {
			if len(order) >= limit {
				continue
			}
			x := SMBObservationRow{SensorID: sensor, EvidenceSource: "transport", FlowID: flowID, FirstSeen: first, LastSeen: last, Packets: uint64(packets)}
			x.Timestamp = last
			x.ClientIP = cip
			x.ServerIP = sip
			x.ClientPort = uint16(clientPort)
			x.ServerPort = 445
			x.Command = "transport_session"
			x.Direction = "client_to_server"
			x.Bytes = uint64(byteCount)
			a = &aggregate{row: x}
			byFlow[key] = a
			order = append(order, key)
			continue
		}
		if first.Before(a.row.FirstSeen) {
			a.row.FirstSeen = first
		}
		if last.After(a.row.LastSeen) {
			a.row.LastSeen = last
			a.row.Timestamp = last
		}
		a.row.Packets += uint64(packets)
		a.row.Bytes += uint64(byteCount)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]SMBObservationRow, 0, len(order))
	for _, key := range order {
		out = append(out, byFlow[key].row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

func (r *Repository) ListSMBEvidence(ctx context.Context, sensorID, clientIP, serverIP, artifact, search string, limit int, includeTransport bool) ([]SMBObservationRow, error) {
	decoded, err := r.ListSMBObservations(ctx, sensorID, clientIP, serverIP, artifact, search, limit)
	if err != nil {
		return nil, err
	}
	if !includeTransport || artifact != "" {
		return decoded, nil
	}
	transport, err := r.ListSMBTransportEvidence(ctx, sensorID, clientIP, serverIP, search, limit)
	if err != nil {
		// Transport evidence is an optional fallback for encrypted/mid-stream SMB.
		// A slow or malformed historical flow row must not hide otherwise healthy
		// decoded SMB observations from the Explorer.
		return decoded, nil
	}

	// Suppress a transport-only row when the same client/server pair already has
	// decoded SMB evidence during that flow lifetime. The fallback should fill
	// blind spots, not duplicate healthy parser output.
	covered := make(map[string][]time.Time, len(decoded))
	for _, d := range decoded {
		k := d.SensorID + "\x00" + d.ClientIP + "\x00" + d.ServerIP
		covered[k] = append(covered[k], d.Timestamp)
	}
	combined := make([]SMBObservationRow, 0, len(decoded)+len(transport))
	combined = append(combined, decoded...)
	for _, t := range transport {
		k := t.SensorID + "\x00" + t.ClientIP + "\x00" + t.ServerIP
		matched := false
		for _, at := range covered[k] {
			if !at.Before(t.FirstSeen.Add(-time.Minute)) && !at.After(t.LastSeen.Add(time.Minute)) {
				matched = true
				break
			}
		}
		if !matched {
			combined = append(combined, t)
		}
	}
	sort.Slice(combined, func(i, j int) bool { return combined[i].Timestamp.After(combined[j].Timestamp) })
	if len(combined) > limit {
		combined = combined[:limit]
	}
	return combined, nil
}
