package central

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/topology"
)

type AssetSecurityStatus struct {
	SensorID      string     `json:"sensor_id"`
	AssetIdentity string     `json:"asset_identity,omitempty"`
	AssetIP       string     `json:"asset_ip"`
	Status        string     `json:"status"`
	Reason        string     `json:"reason"`
	Source        string     `json:"source"`
	DetectedAt    *time.Time `json:"detected_at,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
	UpdatedBy     string     `json:"updated_by"`
}
type MalwareIncident struct {
	ID             int64           `json:"id"`
	SensorID       string          `json:"sensor_id"`
	InitialAssetIP string          `json:"initial_asset_ip"`
	Title          string          `json:"title"`
	Status         string          `json:"status"`
	Severity       string          `json:"severity"`
	LookbackHours  int             `json:"lookback_hours"`
	MaxHops        int             `json:"max_hops"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	Exposures      []AssetExposure `json:"exposures,omitempty"`
}
type AssetExposure struct {
	AssetIP          string    `json:"asset_ip"`
	ParentAssetIP    string    `json:"parent_asset_ip"`
	HopCount         int       `json:"hop_count"`
	ExposureScore    int       `json:"exposure_score"`
	ExposureSeverity string    `json:"exposure_severity"`
	Reasons          []string  `json:"reasons"`
	FirstContact     time.Time `json:"first_contact"`
	LastContact      time.Time `json:"last_contact"`
	Protocols        []string  `json:"protocols"`
	Bytes            uint64    `json:"bytes"`
	Packets          uint64    `json:"packets"`
}
type flowContact struct {
	A, B, Protocol   string
	SrcPort, DstPort uint16
	First, Last      time.Time
	Bytes, Packets   uint64
	IsOT             bool
}

func persistFlowObservations(ctx context.Context, x execer, sensorID string, capturedAt time.Time, edges []topology.Edge) error {
	valid := make([]topology.Edge, 0, len(edges))
	flowIDs := make([]string, 0, len(edges))
	seenIDs := make(map[string]struct{}, len(edges))
	for _, e := range edges {
		if e.ID == "" || e.SrcIP == "" || e.DstIP == "" {
			continue
		}
		valid = append(valid, e)
		if _, exists := seenIDs[e.ID]; !exists {
			seenIDs[e.ID] = struct{}{}
			flowIDs = append(flowIDs, e.ID)
		}
	}
	if len(valid) == 0 {
		return nil
	}

	type counter struct {
		packets, bytes           uint64
		packetsAToB, packetsBToA uint64
		bytesAToB, bytesBToA     uint64
		lastSeen                 time.Time
	}
	previous := make(map[string]counter, len(flowIDs))

	// Load counters in batches instead of issuing one SELECT per flow. The old
	// implementation did 2-3 SQL round trips for every received edge; a restored
	// SQLite backlog of a few thousand flows could therefore exceed the sensor's
	// HTTP timeout even on an otherwise healthy/authenticated connection.
	const lookupBatch = 1000
	for start := 0; start < len(flowIDs); start += lookupBatch {
		end := start + lookupBatch
		if end > len(flowIDs) {
			end = len(flowIDs)
		}
		args := []interface{}{sensorID}
		ids := make([]string, 0, end-start)
		for _, id := range flowIDs[start:end] {
			args = append(args, id)
			ids = append(ids, fmt.Sprintf("$%d", len(args)))
		}
		rows, err := x.QueryContext(ctx, `SELECT flow_id,packets,bytes,packets_a_to_b,packets_b_to_a,bytes_a_to_b,bytes_b_to_a,COALESCE(last_seen,'1970-01-01'::timestamptz) FROM flow_counters WHERE sensor_id=$1 AND flow_id IN (`+strings.Join(ids, ",")+`)`, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			var c counter
			if err := rows.Scan(&id, &c.packets, &c.bytes, &c.packetsAToB, &c.packetsBToA, &c.bytesAToB, &c.bytesBToA, &c.lastSeen); err != nil {
				rows.Close()
				return err
			}
			previous[id] = c
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}

	type observation struct {
		edge                     topology.Edge
		eventAt                  time.Time
		packets, bytes           uint64
		packetsAToB, packetsBToA uint64
		bytesAToB, bytesBToA     uint64
	}
	observations := make([]observation, 0, len(valid))
	accepted := make([]topology.Edge, 0, len(valid))
	for _, e := range valid {
		eventAt := e.LastSeen
		if eventAt.IsZero() {
			eventAt = capturedAt
		}
		old, found := previous[e.ID]
		if found && !old.lastSeen.IsZero() && !old.lastSeen.Equal(time.Unix(0, 0).UTC()) {
			if eventAt.Before(old.lastSeen) {
				// Restored dirty flow older than what Central already folded in.
				// Do not lower counters or manufacture a counter-reset delta.
				continue
			}
			if eventAt.Equal(old.lastSeen) && (e.Packets < old.packets || e.Bytes < old.bytes || e.PacketsAToB < old.packetsAToB || e.PacketsBToA < old.packetsBToA || e.BytesAToB < old.bytesAToB || e.BytesBToA < old.bytesBToA) {
				continue
			}
		}
		accepted = append(accepted, e)
		dp, db := e.Packets, e.Bytes
		dpa, dpb := e.PacketsAToB, e.PacketsBToA
		dba, dbb := e.BytesAToB, e.BytesBToA
		if found {
			if dp >= old.packets {
				dp -= old.packets
			}
			if db >= old.bytes {
				db -= old.bytes
			}
			if dpa >= old.packetsAToB {
				dpa -= old.packetsAToB
			}
			if dpb >= old.packetsBToA {
				dpb -= old.packetsBToA
			}
			if dba >= old.bytesAToB {
				dba -= old.bytesAToB
			}
			if dbb >= old.bytesBToA {
				dbb -= old.bytesBToA
			}
		}
		if dp > 0 || db > 0 {
			observations = append(observations, observation{
				edge: e, eventAt: eventAt, packets: dp, bytes: db,
				packetsAToB: dpa, packetsBToA: dpb,
				bytesAToB: dba, bytesBToA: dbb,
			})
		}
	}

	valid = accepted
	if len(valid) == 0 {
		return nil
	}

	// Keep each statement well below PostgreSQL's bind-parameter ceiling.
	const writeBatch = 500
	for start := 0; start < len(observations); start += writeBatch {
		end := start + writeBatch
		if end > len(observations) {
			end = len(observations)
		}
		args := make([]interface{}, 0, (end-start)*21)
		values := make([]string, 0, end-start)
		flowObservationTypes := []string{
			"text", "text", "timestamptz", "timestamptz", "text", "text",
			"integer", "integer", "text", "text", "text", "integer", "integer",
			"bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "integer", "boolean",
		}
		for _, o := range observations[start:end] {
			e := o.edge
			values = append(values, appendSQLTypedTuple(&args, flowObservationTypes,
				sensorID, e.ID, o.eventAt.UTC().Truncate(time.Minute), o.eventAt, e.SrcIP, e.DstIP, e.SrcPort, e.DstPort, e.Protocol,
				e.InitiatorIP, e.ResponderIP, e.InitiatorPort, e.ResponderPort,
				o.packets, o.bytes, o.packetsAToB, o.packetsBToA, o.bytesAToB, o.bytesBToA, e.VLANID, e.IsOT,
			))
		}

		// Resolve identity at the event timestamp inside the same set-based INSERT.
		// This avoids both an N+1 application lookup and a broad UPDATE over every
		// flow minute between the oldest/newest observation in the sync. When an IP
		// has overlapping owners, preserve ip:<IP> instead of choosing a random MAC.
		query := `INSERT INTO flow_observations(
 sensor_id,flow_id,bucket_start,bucket_end,src_ip,dst_ip,src_identity,dst_identity,src_port,dst_port,protocol,initiator_ip,responder_ip,initiator_port,responder_port,packets,bytes,packets_a_to_b,packets_b_to_a,bytes_a_to_b,bytes_b_to_a,vlan_id,is_ot)
SELECT v.sensor_id::text,v.flow_id::text,v.bucket_start::timestamptz,v.bucket_end::timestamptz,v.src_ip::text,v.dst_ip::text,
 COALESCE((SELECT CASE WHEN COUNT(DISTINCT b.asset_identity)=1 THEN MIN(b.asset_identity) ELSE 'ip:'||v.src_ip::text END FROM asset_ip_binding_history b WHERE b.sensor_id=v.sensor_id::text AND b.ip=v.src_ip::text AND b.valid_from<=v.bucket_end::timestamptz AND (b.valid_to IS NULL OR b.valid_to>=v.bucket_start::timestamptz)),'ip:'||v.src_ip::text),
 COALESCE((SELECT CASE WHEN COUNT(DISTINCT b.asset_identity)=1 THEN MIN(b.asset_identity) ELSE 'ip:'||v.dst_ip::text END FROM asset_ip_binding_history b WHERE b.sensor_id=v.sensor_id::text AND b.ip=v.dst_ip::text AND b.valid_from<=v.bucket_end::timestamptz AND (b.valid_to IS NULL OR b.valid_to>=v.bucket_start::timestamptz)),'ip:'||v.dst_ip::text),
 v.src_port::integer,v.dst_port::integer,v.protocol::text,v.initiator_ip::text,v.responder_ip::text,v.initiator_port::integer,v.responder_port::integer,v.packets::bigint,v.bytes::bigint,v.packets_a_to_b::bigint,v.packets_b_to_a::bigint,v.bytes_a_to_b::bigint,v.bytes_b_to_a::bigint,v.vlan_id::integer,v.is_ot::boolean
FROM (VALUES ` + strings.Join(values, ",") + `) AS v(sensor_id,flow_id,bucket_start,bucket_end,src_ip,dst_ip,src_port,dst_port,protocol,initiator_ip,responder_ip,initiator_port,responder_port,packets,bytes,packets_a_to_b,packets_b_to_a,bytes_a_to_b,bytes_b_to_a,vlan_id,is_ot)
ON CONFLICT(sensor_id,flow_id,bucket_start) DO UPDATE SET src_identity=EXCLUDED.src_identity,dst_identity=EXCLUDED.dst_identity,packets=flow_observations.packets+EXCLUDED.packets,bytes=flow_observations.bytes+EXCLUDED.bytes,packets_a_to_b=flow_observations.packets_a_to_b+EXCLUDED.packets_a_to_b,packets_b_to_a=flow_observations.packets_b_to_a+EXCLUDED.packets_b_to_a,bytes_a_to_b=flow_observations.bytes_a_to_b+EXCLUDED.bytes_a_to_b,bytes_b_to_a=flow_observations.bytes_b_to_a+EXCLUDED.bytes_b_to_a,bucket_end=GREATEST(flow_observations.bucket_end,EXCLUDED.bucket_end)`
		if _, err := x.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}

	for start := 0; start < len(valid); start += writeBatch {
		end := start + writeBatch
		if end > len(valid) {
			end = len(valid)
		}
		args := make([]interface{}, 0, (end-start)*9)
		values := make([]string, 0, end-start)
		for _, e := range valid[start:end] {
			eventAt := e.LastSeen
			if eventAt.IsZero() {
				eventAt = capturedAt
			}
			values = append(values, appendSQLTuple(&args, sensorID, e.ID, e.Packets, e.Bytes, e.PacketsAToB, e.PacketsBToA, e.BytesAToB, e.BytesBToA, eventAt))
		}
		query := `INSERT INTO flow_counters(sensor_id,flow_id,packets,bytes,packets_a_to_b,packets_b_to_a,bytes_a_to_b,bytes_b_to_a,last_seen) VALUES ` + strings.Join(values, ",") + ` ON CONFLICT(sensor_id,flow_id) DO UPDATE SET packets=EXCLUDED.packets,bytes=EXCLUDED.bytes,packets_a_to_b=EXCLUDED.packets_a_to_b,packets_b_to_a=EXCLUDED.packets_b_to_a,bytes_a_to_b=EXCLUDED.bytes_a_to_b,bytes_b_to_a=EXCLUDED.bytes_b_to_a,last_seen=EXCLUDED.last_seen,updated_at=NOW() WHERE flow_counters.last_seen IS NULL OR EXCLUDED.last_seen >= flow_counters.last_seen`
		if _, err := x.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) SetAssetSecurityStatus(ctx context.Context, v AssetSecurityStatus) error {
	identity, err := r.ResolveAssetIdentity(ctx, v.SensorID, v.AssetIP)
	if err != nil {
		return err
	}
	v.AssetIdentity = identity
	_, err = r.db.ExecContext(ctx, `INSERT INTO asset_security_status(sensor_id,asset_identity,asset_ip,status,reason,source,detected_at,updated_at,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,NOW(),$8) ON CONFLICT(sensor_id,asset_identity) DO UPDATE SET asset_ip=EXCLUDED.asset_ip,status=EXCLUDED.status,reason=EXCLUDED.reason,source=EXCLUDED.source,detected_at=EXCLUDED.detected_at,updated_at=NOW(),updated_by=EXCLUDED.updated_by`, v.SensorID, identity, v.AssetIP, v.Status, v.Reason, v.Source, v.DetectedAt, v.UpdatedBy)
	return err
}
func (r *Repository) ListAssetSecurityStatuses(ctx context.Context, sensorID string) ([]AssetSecurityStatus, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id,asset_identity,asset_ip,status,reason,source,detected_at,updated_at,updated_by FROM asset_security_status WHERE ($1='' OR sensor_id=$1) ORDER BY updated_at DESC`, sensorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetSecurityStatus{}
	seen := map[string]bool{}
	for rows.Next() {
		var v AssetSecurityStatus
		if err := rows.Scan(&v.SensorID, &v.AssetIdentity, &v.AssetIP, &v.Status, &v.Reason, &v.Source, &v.DetectedAt, &v.UpdatedAt, &v.UpdatedBy); err != nil {
			return nil, err
		}
		if v.AssetIdentity == "" {
			v.AssetIdentity = canonicalAssetIdentity("", v.AssetIP)
		}
		key := v.SensorID + "\x00" + v.AssetIdentity
		if seen[key] {
			continue
		}
		if ip, ok, err := r.CurrentAssetIP(ctx, v.SensorID, v.AssetIdentity); err != nil {
			return nil, err
		} else if !ok {
			continue // orphaned historical status must not attach to a future IP reuser
		} else {
			v.AssetIP = ip
		}
		seen[key] = true
		out = append(out, v)
	}
	return out, rows.Err()
}

func exposureSeverity(exposureScore int) string {
	if exposureScore >= 80 {
		return "critical"
	}
	if exposureScore >= 60 {
		return "high"
	}
	if exposureScore >= 30 {
		return "medium"
	}
	return "low"
}
func contactExposureScore(c flowContact, hop int) (int, []string) {
	exposureScore := 20
	reasons := []string{"direct communication with traced asset"}
	p := strings.ToUpper(c.Protocol)
	if p == "TCP" && (c.SrcPort == 445 || c.DstPort == 445 || c.SrcPort == 3389 || c.DstPort == 3389 || c.SrcPort == 22 || c.DstPort == 22 || c.SrcPort == 5985 || c.DstPort == 5985) {
		exposureScore += 25
		reasons = append(reasons, "administrative or file-transfer protocol")
	}
	if c.Bytes >= 100*1024*1024 {
		exposureScore += 15
		reasons = append(reasons, "large data transfer")
	}
	if c.Packets >= 100 {
		exposureScore += 10
		reasons = append(reasons, "repeated communication")
	}
	if c.IsOT {
		exposureScore += 30
		reasons = append(reasons, "OT protocol exposure")
	}
	exposureScore -= 15 * (hop - 1)
	if exposureScore < 0 {
		exposureScore = 0
	}
	if exposureScore > 100 {
		exposureScore = 100
	}
	return exposureScore, reasons
}
func (r *Repository) CreateContactTrace(ctx context.Context, sensorID, ip string, lookback, maxHops int) (MalwareIncident, error) {
	if lookback <= 0 {
		lookback = 24
	}
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > 3 {
		maxHops = 3
	}
	now := time.Now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return MalwareIncident{}, err
	}
	defer tx.Rollback()
	var id int64
	title := "Malware infection – " + ip
	err = tx.QueryRowContext(ctx, `INSERT INTO malware_incidents(sensor_id,initial_asset_ip,title,lookback_hours,max_hops) VALUES($1,$2,$3,$4,$5) RETURNING id`, sensorID, ip, title, lookback, maxHops).Scan(&id)
	if err != nil {
		return MalwareIncident{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT src_ip,dst_ip,protocol,src_port,dst_port,MIN(bucket_start),MAX(bucket_end),SUM(bytes),SUM(packets),BOOL_OR(is_ot) FROM flow_observations WHERE sensor_id=$1 AND bucket_end >= $2 GROUP BY src_ip,dst_ip,protocol,src_port,dst_port`, sensorID, now.Add(-time.Duration(lookback)*time.Hour))
	if err != nil {
		return MalwareIncident{}, err
	}
	var contacts []flowContact
	for rows.Next() {
		var c flowContact
		if err := rows.Scan(&c.A, &c.B, &c.Protocol, &c.SrcPort, &c.DstPort, &c.First, &c.Last, &c.Bytes, &c.Packets, &c.IsOT); err != nil {
			rows.Close()
			return MalwareIncident{}, err
		}
		contacts = append(contacts, c)
	}
	rows.Close()
	frontier := []string{ip}
	visited := map[string]bool{ip: true}
	var ex []AssetExposure
	for hop := 1; hop <= maxHops; hop++ {
		var next []string
		for _, cur := range frontier {
			for _, c := range contacts {
				other := ""
				if c.A == cur {
					other = c.B
				} else if c.B == cur {
					other = c.A
				}
				if other == "" || visited[other] {
					continue
				}
				visited[other] = true
				exposureScore, reasons := contactExposureScore(c, hop)
				e := AssetExposure{AssetIP: other, ParentAssetIP: cur, HopCount: hop, ExposureScore: exposureScore, ExposureSeverity: exposureSeverity(exposureScore), Reasons: reasons, FirstContact: c.First, LastContact: c.Last, Protocols: []string{c.Protocol}, Bytes: c.Bytes, Packets: c.Packets}
				raw, _ := json.Marshal(reasons)
				_, err = tx.ExecContext(ctx, `INSERT INTO asset_exposures(incident_id,exposed_asset_ip,parent_asset_ip,hop_count,exposure_score,exposure_severity,reasons,first_contact,last_contact,protocols,bytes,packets) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, id, e.AssetIP, e.ParentAssetIP, e.HopCount, e.ExposureScore, e.ExposureSeverity, raw, e.FirstContact, e.LastContact, strings.Join(e.Protocols, ","), e.Bytes, e.Packets)
				if err != nil {
					return MalwareIncident{}, err
				}
				ex = append(ex, e)
				next = append(next, other)
			}
		}
		frontier = next
	}
	if err := tx.Commit(); err != nil {
		return MalwareIncident{}, err
	}
	sort.Slice(ex, func(i, j int) bool { return ex[i].ExposureScore > ex[j].ExposureScore })
	return MalwareIncident{ID: id, SensorID: sensorID, InitialAssetIP: ip, Title: title, Status: "open", Severity: "critical", LookbackHours: lookback, MaxHops: maxHops, CreatedAt: now, UpdatedAt: now, Exposures: ex}, nil
}
func (r *Repository) GetMalwareIncident(ctx context.Context, id int64) (MalwareIncident, error) {
	var v MalwareIncident
	err := r.db.QueryRowContext(ctx, `SELECT id,sensor_id,initial_asset_ip,title,status,severity,lookback_hours,max_hops,created_at,updated_at FROM malware_incidents WHERE id=$1`, id).Scan(&v.ID, &v.SensorID, &v.InitialAssetIP, &v.Title, &v.Status, &v.Severity, &v.LookbackHours, &v.MaxHops, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return v, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT exposed_asset_ip,parent_asset_ip,hop_count,exposure_score,exposure_severity,reasons,first_contact,last_contact,protocols,bytes,packets FROM asset_exposures WHERE incident_id=$1 ORDER BY exposure_score DESC`, id)
	if err != nil {
		return v, err
	}
	defer rows.Close()
	for rows.Next() {
		var e AssetExposure
		var raw []byte
		var protocols string
		if err := rows.Scan(&e.AssetIP, &e.ParentAssetIP, &e.HopCount, &e.ExposureScore, &e.ExposureSeverity, &raw, &e.FirstContact, &e.LastContact, &protocols, &e.Bytes, &e.Packets); err != nil {
			return v, err
		}
		json.Unmarshal(raw, &e.Reasons)
		if protocols != "" {
			e.Protocols = strings.Split(protocols, ",")
		}
		v.Exposures = append(v.Exposures, e)
	}
	return v, rows.Err()
}
func (v MalwareIncident) Graph() map[string]interface{} {
	nodes := []map[string]interface{}{{"id": v.InitialAssetIP, "security_status": "infected", "is_initial_asset": true, "exposure_score": nil}}
	edges := []map[string]interface{}{}
	for _, e := range v.Exposures {
		nodes = append(nodes, map[string]interface{}{"id": e.AssetIP, "security_status": "unknown", "exposure_status": "exposed", "is_initial_asset": false, "exposure_score": e.ExposureScore, "exposure_severity": e.ExposureSeverity, "hop_count": e.HopCount})
		edges = append(edges, map[string]interface{}{"source": e.ParentAssetIP, "target": e.AssetIP, "exposure_score": e.ExposureScore, "exposure_severity": e.ExposureSeverity, "first_contact": e.FirstContact, "last_contact": e.LastContact, "protocols": e.Protocols})
	}
	return map[string]interface{}{"incident": v, "nodes": nodes, "edges": edges}
}
func validateSecurityStatus(v string) error {
	switch v {
	case "clean", "suspected", "infected", "contained", "recovered":
		return nil
	}
	return fmt.Errorf("invalid status")
}
