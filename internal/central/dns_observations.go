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

	// Telemetry carries a bounded observation buffer (normally up to 5,000 DNS
	// rows). Executing one INSERT per observation turned one sensor sync into
	// thousands of PostgreSQL round trips and could easily exceed the sensor's
	// telemetry timeout even though heartbeat/sync were healthy. Fold each batch
	// with a single multi-row INSERT instead. The event-unique index keeps resend
	// of the sensor's bounded buffer idempotent.
	const writeBatch = 1000
	type row struct {
		o       passivedns.Observation
		answers []byte
		cnames  []byte
	}
	valid := make([]row, 0, len(observations))
	for _, o := range observations {
		if strings.TrimSpace(o.QueryName) == "" || o.Timestamp.IsZero() {
			continue
		}
		answers, _ := json.Marshal(o.Answers)
		cnames, _ := json.Marshal(o.CNAMEs)
		valid = append(valid, row{o: o, answers: answers, cnames: cnames})
	}
	for start := 0; start < len(valid); start += writeBatch {
		end := start + writeBatch
		if end > len(valid) {
			end = len(valid)
		}
		args := make([]interface{}, 0, (end-start)*16)
		values := make([]string, 0, end-start)
		for _, item := range valid[start:end] {
			o := item.o
			values = append(values, appendSQLTuple(&args,
				sensorID, o.Timestamp, o.ClientIP, o.ServerIP, strings.ToLower(o.QueryName), o.QueryType,
				o.TransactionID, o.ConversationID, o.Direction, o.ResponseCode, o.IsResponse, o.AnswerCount,
				o.PayloadBytes, item.answers, item.cnames, o.TTL,
			))
		}
		if len(values) == 0 {
			continue
		}
		q := `INSERT INTO dns_observations(sensor_id,observed_at,client_ip,server_ip,query_name,query_type,transaction_id,conversation_id,direction,response_code,is_response,answer_count,payload_bytes,answers,cnames,ttl) VALUES ` + strings.Join(values, ",") + ` ON CONFLICT DO NOTHING`
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
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
