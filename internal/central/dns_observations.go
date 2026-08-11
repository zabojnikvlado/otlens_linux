package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	passivedns "github.com/zabojnikvlado/otlens_linux/internal/dns"
)

func persistDNSObservations(ctx context.Context, tx *sql.Tx, sensorID string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var observations []passivedns.Observation
	if err := json.Unmarshal(raw, &observations); err != nil {
		return err
	}
	for _, o := range observations {
		if strings.TrimSpace(o.QueryName) == "" {
			continue
		}
		at := o.Timestamp
		if at.IsZero() {
			// Never invent a fresh timestamp for an old/malformed observation.
			// Sensors resend their bounded observation buffer on each sync, so
			// using NOW() here would manufacture a new DNS event every cycle.
			continue
		}
		answers, _ := json.Marshal(o.Answers)
		cnames, _ := json.Marshal(o.CNAMEs)
		_, err := tx.ExecContext(ctx, `INSERT INTO dns_observations(sensor_id,observed_at,client_ip,server_ip,query_name,query_type,transaction_id,conversation_id,direction,response_code,is_response,answer_count,payload_bytes,answers,cnames,ttl) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT DO NOTHING`, sensorID, at, o.ClientIP, o.ServerIP, strings.ToLower(o.QueryName), o.QueryType, o.TransactionID, o.ConversationID, o.Direction, o.ResponseCode, o.IsResponse, o.AnswerCount, o.PayloadBytes, answers, cnames, o.TTL)
		if err != nil {
			return err
		}
	}
	return nil
}

type DNSObservationRow struct {
	ID             int64           `json:"id"`
	SensorID       string          `json:"sensor_id"`
	ObservedAt     time.Time       `json:"observed_at"`
	ClientIP       string          `json:"client_ip"`
	ServerIP       string          `json:"server_ip"`
	QueryName      string          `json:"query_name"`
	QueryType      int             `json:"query_type"`
	TransactionID  int             `json:"transaction_id"`
	ConversationID string          `json:"conversation_id"`
	Direction      string          `json:"direction"`
	ResponseCode   int             `json:"response_code"`
	IsResponse     bool            `json:"is_response"`
	AnswerCount    int             `json:"answer_count"`
	PayloadBytes   int             `json:"payload_bytes"`
	Answers        json.RawMessage `json:"answers"`
	CNAMEs         json.RawMessage `json:"cnames"`
	TTL            int64           `json:"ttl"`
}

func (r *Repository) ListDNSObservations(ctx context.Context, sensorID, queryName, clientIP, search string, limit int) ([]DNSObservationRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,sensor_id,observed_at,client_ip,server_ip,query_name,query_type,transaction_id,conversation_id,direction,response_code,is_response,answer_count,payload_bytes,answers,cnames,ttl
FROM dns_observations
WHERE ($1='' OR sensor_id=$1)
  AND ($2='' OR query_name ILIKE '%'||$2||'%')
  AND ($3='' OR client_ip=$3)
  AND ($4='' OR query_name ILIKE '%'||$4||'%' OR client_ip ILIKE '%'||$4||'%' OR server_ip ILIKE '%'||$4||'%' OR answers::text ILIKE '%'||$4||'%')
ORDER BY observed_at DESC LIMIT $5`, sensorID, queryName, clientIP, search, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSObservationRow{}
	for rows.Next() {
		var x DNSObservationRow
		if err := rows.Scan(&x.ID, &x.SensorID, &x.ObservedAt, &x.ClientIP, &x.ServerIP, &x.QueryName, &x.QueryType, &x.TransactionID, &x.ConversationID, &x.Direction, &x.ResponseCode, &x.IsResponse, &x.AnswerCount, &x.PayloadBytes, &x.Answers, &x.CNAMEs, &x.TTL); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
