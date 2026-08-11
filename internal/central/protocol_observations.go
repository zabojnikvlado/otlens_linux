package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/protocolobs"
)

func persistProtocolObservations(ctx context.Context, tx *sql.Tx, sensorID string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var observations []protocolobs.Observation
	if err := json.Unmarshal(raw, &observations); err != nil {
		return err
	}
	for _, o := range observations {
		if strings.TrimSpace(o.Protocol) == "" {
			continue
		}
		at := o.Timestamp
		if at.IsZero() {
			continue
		}
		attrs, _ := json.Marshal(o.Attributes)
		_, err := tx.ExecContext(ctx, `INSERT INTO protocol_observations(sensor_id,observed_at,protocol,transport,src_ip,dst_ip,src_port,dst_port,operation,host,resource,username,status,summary,encrypted,from_analysis,conversation_id,flow_id,direction,rtt_millis,attributes)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
ON CONFLICT DO NOTHING`, sensorID, at, strings.ToLower(o.Protocol), o.Transport, o.SrcIP, o.DstIP, o.SrcPort, o.DstPort, o.Operation, o.Host, o.Resource, o.Username, o.Status, o.Summary, o.Encrypted, o.FromAnalysis, o.ConversationID, o.FlowID, o.Direction, o.RTTMillis, attrs)
		if err != nil {
			return err
		}
	}
	return nil
}

type ProtocolObservationRow struct {
	ID             int64           `json:"id"`
	SensorID       string          `json:"sensor_id"`
	ObservedAt     time.Time       `json:"observed_at"`
	Protocol       string          `json:"protocol"`
	Transport      string          `json:"transport"`
	SrcIP          string          `json:"src_ip"`
	DstIP          string          `json:"dst_ip"`
	SrcPort        int             `json:"src_port"`
	DstPort        int             `json:"dst_port"`
	Operation      string          `json:"operation"`
	Host           string          `json:"host"`
	Resource       string          `json:"resource"`
	Username       string          `json:"username"`
	Status         string          `json:"status"`
	Summary        string          `json:"summary"`
	Encrypted      bool            `json:"encrypted"`
	FromAnalysis   bool            `json:"from_analysis"`
	ConversationID string          `json:"conversation_id"`
	FlowID         string          `json:"flow_id"`
	Direction      string          `json:"direction"`
	RTTMillis      float64         `json:"rtt_millis"`
	Attributes     json.RawMessage `json:"attributes"`
}

func (r *Repository) ListProtocolObservations(ctx context.Context, sensorID, protocol, ip string, limit int) ([]ProtocolObservationRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,sensor_id,observed_at,protocol,transport,src_ip,dst_ip,src_port,dst_port,operation,host,resource,username,status,summary,encrypted,from_analysis,conversation_id,flow_id,direction,rtt_millis,attributes FROM protocol_observations WHERE ($1='' OR sensor_id=$1) AND ($2='' OR protocol=$2) AND ($3='' OR src_ip=$3 OR dst_ip=$3) ORDER BY observed_at DESC LIMIT $4`, sensorID, strings.ToLower(protocol), ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProtocolObservationRow{}
	for rows.Next() {
		var x ProtocolObservationRow
		if err := rows.Scan(&x.ID, &x.SensorID, &x.ObservedAt, &x.Protocol, &x.Transport, &x.SrcIP, &x.DstIP, &x.SrcPort, &x.DstPort, &x.Operation, &x.Host, &x.Resource, &x.Username, &x.Status, &x.Summary, &x.Encrypted, &x.FromAnalysis, &x.ConversationID, &x.FlowID, &x.Direction, &x.RTTMillis, &x.Attributes); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
