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
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
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
	type preparedEdge struct {
		edge      aggregatedEdge
		pairKey   string
		firstSeen time.Time
		lastSeen  time.Time
	}
	prepared := make([]preparedEdge, 0, len(edges))
	type nodeSpan struct{ first, last time.Time }
	stubNodes := make(map[string]nodeSpan, len(edges)*2)
	seenPairs := make(map[string]struct{}, len(edges))

	for _, e := range edges {
		if e.SrcIP == "" || e.DstIP == "" {
			continue
		}
		pairKey := (topologyEdgeRecord{SrcIP: e.SrcIP, DstIP: e.DstIP}).PairKey()
		if _, duplicate := seenPairs[pairKey]; duplicate {
			// aggregateEdges normally guarantees one row per pair. Avoid a
			// PostgreSQL "cannot affect row a second time" error if a future
			// caller passes duplicates to this lower-level helper directly.
			continue
		}
		seenPairs[pairKey] = struct{}{}
		firstSeen := e.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = time.Now()
		}
		lastSeen := e.LastSeen
		if lastSeen.IsZero() {
			lastSeen = firstSeen
		}
		prepared = append(prepared, preparedEdge{edge: e, pairKey: pairKey, firstSeen: firstSeen, lastSeen: lastSeen})
		for _, ip := range [2]string{e.SrcIP, e.DstIP} {
			span, exists := stubNodes[ip]
			if !exists {
				stubNodes[ip] = nodeSpan{first: firstSeen, last: lastSeen}
				continue
			}
			if firstSeen.Before(span.first) {
				span.first = firstSeen
			}
			if lastSeen.After(span.last) {
				span.last = lastSeen
			}
			stubNodes[ip] = span
		}
	}
	if len(prepared) == 0 {
		return nil
	}

	// Insert all missing endpoint stubs in batches. The previous implementation
	// issued two INSERTs per edge, which multiplied a restored backlog into
	// thousands of database round trips in one telemetry transaction.
	const batchSize = 500
	ips := make([]string, 0, len(stubNodes))
	for ip := range stubNodes {
		ips = append(ips, ip)
	}
	for start := 0; start < len(ips); start += batchSize {
		end := start + batchSize
		if end > len(ips) {
			end = len(ips)
		}
		args := make([]interface{}, 0, (end-start)*4)
		values := make([]string, 0, end-start)
		for _, ip := range ips[start:end] {
			span := stubNodes[ip]
			values = append(values, appendSQLTuple(&args, sensorID, ip, span.first, span.last))
		}
		query := `INSERT INTO topology_nodes(sensor_id,ip,first_seen,last_seen) VALUES ` + strings.Join(values, ",") + ` ON CONFLICT(sensor_id,ip) DO NOTHING`
		if _, err := x.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}

	for start := 0; start < len(prepared); start += batchSize {
		end := start + batchSize
		if end > len(prepared) {
			end = len(prepared)
		}
		args := make([]interface{}, 0, (end-start)*13)
		values := make([]string, 0, end-start)
		for _, item := range prepared[start:end] {
			e := item.edge
			values = append(values, appendSQLTuple(&args,
				sensorID, item.pairKey, e.SrcIP, e.DstIP, e.Protocol, e.IsOT, e.FromHoneypot,
				e.VLANID, e.Packets, e.Bytes, e.FlowCount, item.firstSeen, item.lastSeen,
			))
		}
		query := `INSERT INTO topology_edges(sensor_id,pair_key,src_ip,dst_ip,protocols,is_ot,from_honeypot,vlan_id,packets,bytes,flow_count,first_seen,last_seen) VALUES ` + strings.Join(values, ",") + `
ON CONFLICT(sensor_id,pair_key) DO UPDATE SET
	src_ip = CASE WHEN EXCLUDED.last_seen >= topology_edges.last_seen AND EXCLUDED.from_honeypot AND NOT topology_edges.from_honeypot THEN EXCLUDED.src_ip ELSE topology_edges.src_ip END,
	dst_ip = CASE WHEN EXCLUDED.last_seen >= topology_edges.last_seen AND EXCLUDED.from_honeypot AND NOT topology_edges.from_honeypot THEN EXCLUDED.dst_ip ELSE topology_edges.dst_ip END,
	protocols = CASE WHEN EXCLUDED.last_seen >= topology_edges.last_seen THEN EXCLUDED.protocols ELSE topology_edges.protocols END,
	is_ot = topology_edges.is_ot OR EXCLUDED.is_ot,
	from_honeypot = topology_edges.from_honeypot OR EXCLUDED.from_honeypot,
	vlan_id = CASE WHEN EXCLUDED.last_seen >= topology_edges.last_seen THEN EXCLUDED.vlan_id ELSE topology_edges.vlan_id END,
	packets = CASE WHEN EXCLUDED.last_seen >= topology_edges.last_seen THEN EXCLUDED.packets ELSE topology_edges.packets END,
	bytes = CASE WHEN EXCLUDED.last_seen >= topology_edges.last_seen THEN EXCLUDED.bytes ELSE topology_edges.bytes END,
	flow_count = CASE WHEN EXCLUDED.last_seen >= topology_edges.last_seen THEN EXCLUDED.flow_count ELSE topology_edges.flow_count END,
	first_seen = LEAST(topology_edges.first_seen, EXCLUDED.first_seen),
	last_seen = GREATEST(topology_edges.last_seen, EXCLUDED.last_seen)`
		if _, err := x.ExecContext(ctx, query, args...); err != nil {
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
// BackfillOrphanedEdgeNodes creates minimal topology_nodes stubs for any
// IP that already appears in topology_edges but has no matching node —
// the one-time catch-up for upsertTopologyEdges' ongoing guarantee,
// which only covers edges written *after* that guarantee existed. Safe
// to call on every startup: ON CONFLICT DO NOTHING makes repeat runs a
// no-op once caught up.
func (r *Repository) BackfillOrphanedEdgeNodes(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO topology_nodes (sensor_id, ip, first_seen, last_seen)
		SELECT sensor_id, ip, NOW(), NOW() FROM (
			SELECT sensor_id, src_ip AS ip FROM topology_edges
			UNION
			SELECT sensor_id, dst_ip AS ip FROM topology_edges
		) AS edge_ips
		ON CONFLICT (sensor_id, ip) DO NOTHING`,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

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
				mac = CASE WHEN EXCLUDED.last_seen >= topology_nodes.last_seen OR topology_nodes.mac='' THEN EXCLUDED.mac ELSE topology_nodes.mac END,
				hostname = CASE WHEN EXCLUDED.last_seen >= topology_nodes.last_seen OR topology_nodes.hostname='' THEN EXCLUDED.hostname ELSE topology_nodes.hostname END,
				vendor = CASE WHEN EXCLUDED.last_seen >= topology_nodes.last_seen OR topology_nodes.vendor='' THEN EXCLUDED.vendor ELSE topology_nodes.vendor END,
				is_ot = topology_nodes.is_ot OR EXCLUDED.is_ot,
				protocols = CASE WHEN EXCLUDED.last_seen >= topology_nodes.last_seen THEN EXCLUDED.protocols ELSE topology_nodes.protocols END,
				confirmed = CASE WHEN EXCLUDED.last_seen >= topology_nodes.last_seen THEN EXCLUDED.confirmed ELSE topology_nodes.confirmed END,
				score = CASE WHEN EXCLUDED.last_seen >= topology_nodes.last_seen THEN EXCLUDED.score ELSE topology_nodes.score END,
				vlan_id = CASE WHEN EXCLUDED.last_seen >= topology_nodes.last_seen THEN EXCLUDED.vlan_id ELSE topology_nodes.vlan_id END,
				packet_count = CASE WHEN EXCLUDED.last_seen >= topology_nodes.last_seen THEN EXCLUDED.packet_count ELSE topology_nodes.packet_count END,
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

// IPHistoryEntry is one IP an asset has been observed with, and when.
type IPHistoryEntry struct {
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
}

// ListIPHistory returns every IP a given asset (identified by its MAC)
// has ever been recorded with on a sensor, oldest first — straight from
// topology_nodes, which already tracks exactly this. Useful for a
// device that's changed IP over time (DHCP renewal, static
// reassignment, etc.) — the Assets tab only ever shows whichever IP is
// *currently* reported; this is the timeline behind it.
func (r *Repository) ListIPHistory(ctx context.Context, sensorID, mac string) ([]IPHistoryEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT ip, first_seen, last_seen FROM topology_nodes
		WHERE sensor_id=$1 AND mac=$2 ORDER BY first_seen ASC`,
		sensorID, mac,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IPHistoryEntry, 0)
	for rows.Next() {
		var e IPHistoryEntry
		if err := rows.Scan(&e.IP, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
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

// AssetIdentityMeta summarizes the durable identity history for one current asset.
// MAC-backed identities are stable across DHCP changes; IP-only identities are
// intentionally lower-confidence because an address may later be reused.
type AssetIdentityMeta struct {
	CanonicalID        string
	FirstSeen          time.Time
	LastSeen           time.Time
	IPCount            int
	SourceCount        int
	IdentityConfidence string
	Aliases            []string
}

// AssetIdentityMetadata returns identity/lifecycle metadata keyed by sensorID\x00IP.
func (r *Repository) AssetIdentityMetadata(ctx context.Context) (map[string]AssetIdentityMeta, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH grouped AS (
			SELECT sensor_id,
			       CASE WHEN mac <> '' THEN 'mac:' || lower(mac) ELSE 'ip:' || ip END AS canonical_id,
			       NULLIF(mac,'') AS mac_key,
			       MIN(first_seen) AS first_seen,
			       MAX(last_seen) AS last_seen,
			       COUNT(DISTINCT ip)::int AS ip_count,
			       COUNT(*)::int AS source_count,
			       ARRAY_AGG(DISTINCT ip ORDER BY ip) AS aliases
			FROM topology_nodes
			GROUP BY sensor_id, CASE WHEN mac <> '' THEN 'mac:' || lower(mac) ELSE 'ip:' || ip END, NULLIF(mac,'')
		)
		SELECT n.sensor_id,n.ip,g.canonical_id,g.first_seen,g.last_seen,g.ip_count,g.source_count,g.aliases,
		       CASE
		         WHEN n.mac <> '' THEN 'high'
		         WHEN n.hostname <> '' OR n.vendor <> '' THEN 'medium'
		         ELSE 'low'
		       END AS confidence
		FROM topology_nodes n
		JOIN grouped g ON g.sensor_id=n.sensor_id
		 AND g.canonical_id=CASE WHEN n.mac <> '' THEN 'mac:' || lower(n.mac) ELSE 'ip:' || n.ip END`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AssetIdentityMeta{}
	for rows.Next() {
		var sensorID, ip string
		var m AssetIdentityMeta
		if err := rows.Scan(&sensorID, &ip, &m.CanonicalID, &m.FirstSeen, &m.LastSeen, &m.IPCount, &m.SourceCount, &m.Aliases, &m.IdentityConfidence); err != nil {
			return nil, err
		}
		out[sensorID+"\x00"+ip] = m
	}
	return out, rows.Err()
}
