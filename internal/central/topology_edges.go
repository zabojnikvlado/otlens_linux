package central

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/topology"
)

// topologyEdgeRecord is one row of topology_edges — Central's own durable
// ledger of every asset pair a sensor has ever reported, independent of
// whatever the sensor's own (pruned) live flow table currently holds.
type topologyEdgeRecord struct {
	SrcIP        string
	DstIP        string
	Protocol     string // comma-joined, same shape as the live aggregatedEdge's Protocol field
	IsOT         bool
	FromHoneypot bool
	VLANID       uint16
	Packets      uint64
	Bytes        uint64
	FlowCount    int
	FirstSeen    time.Time
	LastSeen     time.Time
}

// PairKey is the same canonical (order-independent) key this row is
// stored under — used to build a stable per-edge ID for the frontend.
func (e topologyEdgeRecord) PairKey() string {
	lo, hi := canonicalPair(e.SrcIP, e.DstIP)
	return lo + "|" + hi
}

// execer is satisfied by both *sql.DB and *sql.Tx, so upsertTopologyEdges
// can run inside PutTelemetry's existing transaction (atomic with the
// rest of that sync) without needing its own connection.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// upsertTopologyEdges folds a sensor's just-received, already-aggregated
// edges into the durable ledger. is_ot/from_honeypot only ever get OR'd
// in (a pair that was ever OT or ever honeypot-involved stays flagged
// that way in this historical record); protocols/vlan/packets/bytes/
// flow_count take the latest report, since those describe current
// traffic shape rather than a fact worth remembering forever;
// first_seen/last_seen expand to cover the full span this pair has ever
// been observed across.
func upsertTopologyEdges(ctx context.Context, x execer, sensorID string, edges []aggregatedEdge) error {
	for _, e := range edges {
		pairKey := (topologyEdgeRecord{SrcIP: e.SrcIP, DstIP: e.DstIP}).PairKey()
		firstSeen := e.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = time.Now()
		}
		lastSeen := e.LastSeen
		if lastSeen.IsZero() {
			lastSeen = firstSeen
		}
		_, err := x.ExecContext(ctx, `
			INSERT INTO topology_edges(sensor_id,pair_key,src_ip,dst_ip,protocols,is_ot,from_honeypot,vlan_id,packets,bytes,flow_count,first_seen,last_seen)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT(sensor_id,pair_key) DO UPDATE SET
				src_ip = CASE WHEN EXCLUDED.from_honeypot AND NOT topology_edges.from_honeypot THEN EXCLUDED.src_ip ELSE topology_edges.src_ip END,
				dst_ip = CASE WHEN EXCLUDED.from_honeypot AND NOT topology_edges.from_honeypot THEN EXCLUDED.dst_ip ELSE topology_edges.dst_ip END,
				protocols = EXCLUDED.protocols,
				is_ot = topology_edges.is_ot OR EXCLUDED.is_ot,
				from_honeypot = topology_edges.from_honeypot OR EXCLUDED.from_honeypot,
				vlan_id = EXCLUDED.vlan_id,
				packets = EXCLUDED.packets,
				bytes = EXCLUDED.bytes,
				flow_count = EXCLUDED.flow_count,
				first_seen = LEAST(topology_edges.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(topology_edges.last_seen, EXCLUDED.last_seen)`,
			sensorID, pairKey, e.SrcIP, e.DstIP, e.Protocol, e.IsOT, e.FromHoneypot, e.VLANID, e.Packets, e.Bytes, e.FlowCount, firstSeen, lastSeen,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListTopologyEdges returns every pair ever recorded for a sensor —
// this is what the /topology handler draws from instead of the sensor's
// current (pruned) live snapshot, so a connection drawn once stays on
// the map even after the sensor itself has aged the underlying flow out.
func (r *Repository) ListTopologyEdges(ctx context.Context, sensorID string) ([]topologyEdgeRecord, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT src_ip,dst_ip,protocols,is_ot,from_honeypot,vlan_id,packets,bytes,flow_count,first_seen,last_seen FROM topology_edges WHERE sensor_id=$1`, sensorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]topologyEdgeRecord, 0)
	for rows.Next() {
		var e topologyEdgeRecord
		if err := rows.Scan(&e.SrcIP, &e.DstIP, &e.Protocol, &e.IsOT, &e.FromHoneypot, &e.VLANID, &e.Packets, &e.Bytes, &e.FlowCount, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// topologyNodeRecord is one row of topology_nodes — see that table's
// doc comment in the embedded schema.
type topologyNodeRecord struct {
	IP          string
	MAC         string
	Hostname    string
	Vendor      string
	IsOT        bool
	Protocols   string // comma-joined
	Confirmed   bool
	Score       int
	VLANID      uint16
	PacketCount uint64
	FirstSeen   time.Time
	LastSeen    time.Time
}

// upsertTopologyNodes folds this sync's live node list into the durable
// per-sensor node ledger, in the same transaction as upsertTopologyEdges
// so the two never drift out of sync with each other. is_ot is OR'd in
// permanently (a device that was ever seen speaking OT stays flagged
// that way here, same reasoning as topology_edges); everything else
// (hostname/vendor/score/vlan/confirmed/packet_count) takes the latest
// report, since those describe current state rather than a fact worth
// remembering forever regardless of what the sensor reports next.
func upsertTopologyNodes(ctx context.Context, x execer, sensorID string, nodes []topology.Node) error {
	for _, n := range nodes {
		if n.IP == "" {
			continue
		}
		protocols := strings.Join(n.Protocols, ",")
		firstSeen := n.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = time.Now()
		}
		lastSeen := n.LastSeen
		if lastSeen.IsZero() {
			lastSeen = firstSeen
		}
		_, err := x.ExecContext(ctx, `
			INSERT INTO topology_nodes(sensor_id,ip,mac,hostname,vendor,is_ot,protocols,confirmed,score,vlan_id,packet_count,first_seen,last_seen)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT(sensor_id,ip) DO UPDATE SET
				mac = EXCLUDED.mac,
				hostname = EXCLUDED.hostname,
				vendor = EXCLUDED.vendor,
				is_ot = topology_nodes.is_ot OR EXCLUDED.is_ot,
				protocols = EXCLUDED.protocols,
				confirmed = EXCLUDED.confirmed,
				score = EXCLUDED.score,
				vlan_id = EXCLUDED.vlan_id,
				packet_count = EXCLUDED.packet_count,
				first_seen = LEAST(topology_nodes.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(topology_nodes.last_seen, EXCLUDED.last_seen)`,
			sensorID, n.IP, n.MAC, n.Hostname, n.Vendor, n.IsOT, protocols, n.Confirmed, n.Score, n.VLANID, n.PacketCount, firstSeen, lastSeen,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListTopologyNodes returns every asset ever recorded for a sensor,
// keyed by IP — see buildTopologyResponse for how this fills in for
// assets the live snapshot doesn't currently have, so their edges in
// topology_edges stay drawable.
func (r *Repository) ListTopologyNodes(ctx context.Context, sensorID string) ([]topologyNodeRecord, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT ip,mac,hostname,vendor,is_ot,protocols,confirmed,score,vlan_id,packet_count,first_seen,last_seen FROM topology_nodes WHERE sensor_id=$1`, sensorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]topologyNodeRecord, 0)
	for rows.Next() {
		var n topologyNodeRecord
		var protocols string
		if err := rows.Scan(&n.IP, &n.MAC, &n.Hostname, &n.Vendor, &n.IsOT, &protocols, &n.Confirmed, &n.Score, &n.VLANID, &n.PacketCount, &n.FirstSeen, &n.LastSeen); err != nil {
			return nil, err
		}
		if protocols != "" {
			n.Protocols = protocols
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func splitProtocols(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	sort.Strings(parts)
	return parts
}
