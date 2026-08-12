package central

import (
	"context"
	"database/sql"
	"fmt"
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
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
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
		args := make([]interface{}, 0, (end-start)*5)
		values := make([]string, 0, end-start)
		for _, ip := range ips[start:end] {
			span := stubNodes[ip]
			values = append(values, appendSQLTuple(&args, sensorID, ip, span.first, span.last, false))
		}
		// Flow-only endpoints are historical topology helpers, not discovered
		// current assets. Marking them active made Purdue/risk/current inventory
		// treat an endpoint that only appeared in a flow as a managed device.
		query := `INSERT INTO topology_nodes(sensor_id,ip,first_seen,last_seen,active) VALUES ` + strings.Join(values, ",") + ` ON CONFLICT(sensor_id,ip) DO NOTHING`
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
		INSERT INTO topology_nodes (sensor_id, ip, first_seen, last_seen, active)
		SELECT sensor_id, ip, NOW(), NOW(), FALSE FROM (
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

func canonicalAssetIdentity(mac, ip string) string {
	if normalized, err := normalizeAssetMAC(mac); err == nil {
		return "mac:" + normalized
	}
	return "ip:" + strings.TrimSpace(ip)
}

func (n topologyNodeRecord) Identity() string {
	return canonicalAssetIdentity(n.MAC, n.IP)
}

// upsertTopologyNodes reconciles this sync's complete live node list with the
// durable per-sensor ledger. topology_nodes keeps historical IP rows so old
// topology edges remain drawable, but active=true means the identity is present
// in the sensor's *current* inventory. A full topology snapshot is authoritative:
// anything omitted from it becomes inactive until observed again.
//
// An IP can also be reused by a different MAC. In that case current-state fields
// must start from the new occupant rather than inheriting sticky is_ot/first_seen
// metadata from the previous device. asset_identity_history below preserves both
// physical identities separately, so resetting the IP-indexed current row loses
// no identity history.
func upsertTopologyNodes(ctx context.Context, x execer, sensorID string, nodes []topology.Node) error {
	if _, err := x.ExecContext(ctx, `UPDATE topology_nodes SET active=FALSE,identity_conflict=FALSE,conflict_macs='' WHERE sensor_id=$1`, sensorID); err != nil {
		return err
	}
	snapshotAt := time.Now().UTC()
	type candidate struct {
		node topology.Node
		ip   string
	}
	byIP := make(map[string][]candidate)
	for _, n := range nodes {
		ips := append([]string(nil), n.IPs...)
		if len(ips) == 0 && n.IP != "" {
			ips = []string{n.IP}
		}
		seen := map[string]bool{}
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			byIP[ip] = append(byIP[ip], candidate{node: n, ip: ip})
		}
	}
	for ip, cs := range byIP {
		// Stable candidate order: ARP/L2-confirmed first, newest observation next,
		// canonical MAC last. The order is only for deterministic display fields;
		// a true multi-MAC conflict is never resolved to that display candidate.
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].node.IPVerifiedByARP != cs[j].node.IPVerifiedByARP {
				return cs[i].node.IPVerifiedByARP
			}
			if !cs[i].node.LastSeen.Equal(cs[j].node.LastSeen) {
				return cs[i].node.LastSeen.After(cs[j].node.LastSeen)
			}
			return strings.ToLower(cs[i].node.MAC) < strings.ToLower(cs[j].node.MAC)
		})
		uniqueMAC := map[string]bool{}
		macs := []string{}
		for _, c := range cs {
			m := strings.ToLower(strings.TrimSpace(c.node.MAC))
			if m != "" && !uniqueMAC[m] {
				uniqueMAC[m] = true
				macs = append(macs, m)
			}
		}
		conflict := len(macs) > 1
		display := cs[0].node
		protocols := strings.Join(display.Protocols, ",")
		firstSeen := display.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = snapshotAt
		}
		lastSeen := display.LastSeen
		if lastSeen.IsZero() {
			lastSeen = firstSeen
		}
		displayMAC := display.MAC
		if conflict {
			displayMAC = ""
		}
		_, err := x.ExecContext(ctx, `
			INSERT INTO topology_nodes(sensor_id,ip,mac,hostname,vendor,is_ot,protocols,confirmed,score,vlan_id,packet_count,first_seen,last_seen,active,identity_conflict,conflict_macs)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,TRUE,$14,$15)
			ON CONFLICT(sensor_id,ip) DO UPDATE SET mac=EXCLUDED.mac,hostname=EXCLUDED.hostname,vendor=EXCLUDED.vendor,is_ot=EXCLUDED.is_ot,
			protocols=EXCLUDED.protocols,confirmed=EXCLUDED.confirmed,score=EXCLUDED.score,vlan_id=EXCLUDED.vlan_id,packet_count=EXCLUDED.packet_count,
			first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,active=TRUE,identity_conflict=EXCLUDED.identity_conflict,conflict_macs=EXCLUDED.conflict_macs`,
			sensorID, ip, displayMAC, display.Hostname, display.Vendor, display.IsOT, protocols, display.Confirmed, display.Score, display.VLANID, display.PacketCount, firstSeen, lastSeen, conflict, strings.Join(macs, ","))
		if err != nil {
			return err
		}

		for _, c := range cs {
			n := c.node
			identity := canonicalAssetIdentity(n.MAC, ip)
			protocols := strings.Join(n.Protocols, ",")
			fs := n.LastSeen // binding start must not inherit the NIC's lifetime FirstSeen
			if fs.IsZero() {
				fs = snapshotAt
			}
			ls := n.LastSeen
			if ls.IsZero() {
				ls = fs
			}
			if _, err := x.ExecContext(ctx, `
				INSERT INTO asset_identity_history(sensor_id,asset_identity,ip,mac,hostname,vendor,is_ot,protocols,confirmed,score,vlan_id,packet_count,first_seen,last_seen)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
				ON CONFLICT(sensor_id,asset_identity,ip) DO UPDATE SET mac=EXCLUDED.mac,hostname=CASE WHEN EXCLUDED.last_seen>=asset_identity_history.last_seen THEN EXCLUDED.hostname ELSE asset_identity_history.hostname END,
				vendor=CASE WHEN EXCLUDED.last_seen>=asset_identity_history.last_seen THEN EXCLUDED.vendor ELSE asset_identity_history.vendor END,is_ot=asset_identity_history.is_ot OR EXCLUDED.is_ot,
				protocols=CASE WHEN EXCLUDED.last_seen>=asset_identity_history.last_seen THEN EXCLUDED.protocols ELSE asset_identity_history.protocols END,confirmed=EXCLUDED.confirmed,score=EXCLUDED.score,vlan_id=EXCLUDED.vlan_id,
				packet_count=GREATEST(asset_identity_history.packet_count,EXCLUDED.packet_count),last_seen=GREATEST(asset_identity_history.last_seen,EXCLUDED.last_seen)`,
				sensorID, identity, ip, n.MAC, n.Hostname, n.Vendor, n.IsOT, protocols, n.Confirmed, n.Score, n.VLANID, n.PacketCount, fs, ls); err != nil {
				return err
			}
			// Promote provisional ip:<addr> operator state once this snapshot proves
			// an unambiguous MAC owner. Existing MAC-owned state wins on collision.
			if !conflict && strings.HasPrefix(identity, "mac:") {
				oldIdentity := canonicalAssetIdentity("", ip)
				for _, table := range []string{"asset_context", "asset_security_status", "asset_risk_exceptions", "asset_recon_profile"} {
					q := fmt.Sprintf("UPDATE %s SET asset_identity=$3 WHERE sensor_id=$1 AND asset_identity=$2 AND NOT EXISTS (SELECT 1 FROM %s x WHERE x.sensor_id=$1 AND x.asset_identity=$3)", table, table)
					if _, err := x.ExecContext(ctx, q, sensorID, oldIdentity, identity); err != nil {
						return err
					}
					q = fmt.Sprintf("DELETE FROM %s WHERE sensor_id=$1 AND asset_identity=$2 AND EXISTS (SELECT 1 FROM %s x WHERE x.sensor_id=$1 AND x.asset_identity=$3)", table, table)
					if _, err := x.ExecContext(ctx, q, sensorID, oldIdentity, identity); err != nil {
						return err
					}
				}
			}

			prov := "topology"
			if n.IPVerifiedByARP {
				prov = "arp"
			}
			res, err := x.ExecContext(ctx, `UPDATE asset_ip_binding_history SET last_observed=GREATEST(last_observed,$4),snapshot_seen_at=$5,vlan_id=$6,provenance=CASE WHEN $7='arp' THEN 'arp' ELSE provenance END WHERE sensor_id=$1 AND asset_identity=$2 AND ip=$3 AND valid_to IS NULL`, sensorID, identity, ip, ls, snapshotAt, n.VLANID, prov)
			if err != nil {
				return err
			}
			if rows, _ := res.RowsAffected(); rows == 0 {
				if _, err := x.ExecContext(ctx, `INSERT INTO asset_ip_binding_history(sensor_id,asset_identity,ip,mac,vlan_id,provenance,valid_from,last_observed,snapshot_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, sensorID, identity, ip, n.MAC, n.VLANID, prov, fs, ls, snapshotAt); err != nil {
					return err
				}
			}
		}
	}
	// Complete topology snapshots close only bindings not represented anymore.
	if _, err := x.ExecContext(ctx, `UPDATE asset_ip_binding_history SET valid_to=$2 WHERE sensor_id=$1 AND valid_to IS NULL AND snapshot_seen_at<$2`, sensorID, snapshotAt); err != nil {
		return err
	}
	return nil
}

// ResolveAssetIdentity maps an observed IP to the stable identity currently
// known for that sensor. MAC-backed identities survive DHCP changes; an
// unresolved IP deliberately falls back to an IP identity.
func (r *Repository) ResolveAssetIdentity(ctx context.Context, sensorID, ip string) (string, error) {
	var mac string
	err := r.db.QueryRowContext(ctx, `SELECT CASE WHEN identity_conflict THEN '' ELSE COALESCE(mac,'') END FROM topology_nodes WHERE sensor_id=$1 AND ip=$2 AND active=TRUE ORDER BY last_seen DESC LIMIT 1`, sensorID, ip).Scan(&mac)
	if err == nil {
		return canonicalAssetIdentity(mac, ip), nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	// Historical-detail endpoints may legitimately be opened with an old IP
	// after DHCP moved the device. Resolve the most recently associated identity
	// only when no active device currently owns that address.
	var identity string
	err = r.db.QueryRowContext(ctx, `SELECT asset_identity FROM asset_identity_history WHERE sensor_id=$1 AND ip=$2 ORDER BY last_seen DESC LIMIT 1`, sensorID, ip).Scan(&identity)
	if err == sql.ErrNoRows {
		return canonicalAssetIdentity("", ip), nil
	}
	if err != nil {
		return "", err
	}
	return identity, nil
}

// ResolveAssetIdentityAt resolves historical evidence against the device that
// owned the address at event time. It prefers explicit binding episodes and
// only falls back to the older coarse history for pre-v13 data.
func (r *Repository) ResolveAssetIdentityAt(ctx context.Context, sensorID, ip string, at time.Time) (string, error) {
	if at.IsZero() {
		return r.ResolveAssetIdentity(ctx, sensorID, ip)
	}
	var identity string
	err := r.db.QueryRowContext(ctx, `SELECT asset_identity FROM asset_ip_binding_history WHERE sensor_id=$1 AND ip=$2 AND valid_from<=$3 AND (valid_to IS NULL OR valid_to>=$3) ORDER BY CASE provenance WHEN 'arp' THEN 0 ELSE 1 END,last_observed DESC LIMIT 1`, sensorID, ip, at).Scan(&identity)
	if err == nil {
		return identity, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	err = r.db.QueryRowContext(ctx, `SELECT asset_identity FROM asset_identity_history WHERE sensor_id=$1 AND ip=$2 AND first_seen<=$3 AND last_seen>=$3 ORDER BY last_seen DESC LIMIT 1`, sensorID, ip, at).Scan(&identity)
	if err == sql.ErrNoRows {
		return canonicalAssetIdentity("", ip), nil
	}
	if err != nil {
		return "", err
	}
	return identity, nil
}

// CurrentAssetIP returns the latest IP for a stable identity. It intentionally
// uses the identity history rather than assuming an operator-owned context is
// still attached to the IP on which it was first created.
func (r *Repository) CurrentAssetIP(ctx context.Context, sensorID, identity string) (string, bool, error) {
	var ip string
	err := r.db.QueryRowContext(ctx, `SELECT ip FROM topology_nodes WHERE sensor_id=$1 AND active=TRUE AND (CASE WHEN mac<>'' THEN 'mac:'||lower(mac) ELSE 'ip:'||ip END)=$2 ORDER BY last_seen DESC, ip ASC LIMIT 1`, sensorID, identity).Scan(&ip)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return ip, true, nil
}

// AssetIPAliases returns every address historically associated with the same
// stable identity as the supplied current/old address.
func (r *Repository) AssetIPAliases(ctx context.Context, sensorID, ipOrIdentity string) ([]string, error) {
	identity := strings.TrimSpace(ipOrIdentity)
	if !strings.HasPrefix(identity, "mac:") && !strings.HasPrefix(identity, "ip:") {
		resolved, err := r.ResolveAssetIdentity(ctx, sensorID, identity)
		if err != nil {
			return nil, err
		}
		identity = resolved
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT ip FROM asset_identity_history WHERE sensor_id=$1 AND asset_identity=$2 ORDER BY ip`, sensorID, identity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var x string
		if err := rows.Scan(&x); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	if len(out) == 0 && !strings.HasPrefix(strings.TrimSpace(ipOrIdentity), "mac:") && !strings.HasPrefix(strings.TrimSpace(ipOrIdentity), "ip:") && strings.TrimSpace(ipOrIdentity) != "" {
		out = append(out, strings.TrimSpace(ipOrIdentity))
	}
	return out, rows.Err()
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

// ListCurrentTopologyNodes returns one latest row per canonical asset identity.
// A MAC-backed device that changed IP therefore appears exactly once. IP-only
// nodes remain separate low-confidence identities.
func (r *Repository) ListCurrentTopologyNodes(ctx context.Context, sensorID string) ([]topologyNodeRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT ip,mac,hostname,vendor,is_ot,protocols,confirmed,score,vlan_id,packet_count,first_seen,last_seen
		FROM (
			SELECT n.*, ROW_NUMBER() OVER (
				PARTITION BY CASE WHEN mac<>'' THEN 'mac:'||lower(mac) ELSE 'ip:'||ip END
				ORDER BY last_seen DESC, ip ASC
			) AS rn
			FROM topology_nodes n
			WHERE sensor_id=$1 AND active=TRUE
		) current_nodes
		WHERE rn=1
		ORDER BY last_seen DESC, ip ASC`, sensorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]topologyNodeRecord, 0)
	for rows.Next() {
		var n topologyNodeRecord
		if err := rows.Scan(&n.IP, &n.MAC, &n.Hostname, &n.Vendor, &n.IsOT, &n.Protocols, &n.Confirmed, &n.Score, &n.VLANID, &n.PacketCount, &n.FirstSeen, &n.LastSeen); err != nil {
			return nil, err
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
	if normalized, err := normalizeAssetMAC(mac); err == nil {
		mac = normalized
	} else {
		return nil, err
	}
	identity := canonicalAssetIdentity(mac, "")
	rows, err := r.db.QueryContext(ctx, `
		SELECT ip, MIN(first_seen), MAX(last_seen)
		FROM asset_identity_history
		WHERE sensor_id=$1 AND asset_identity=$2
		GROUP BY ip
		ORDER BY MIN(first_seen) ASC`, sensorID, identity)
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
		WITH active AS (
			SELECT n.sensor_id,n.ip,n.mac,n.hostname,n.vendor,n.first_seen,n.last_seen,
			       CASE WHEN n.mac<>'' THEN 'mac:'||lower(n.mac) ELSE 'ip:'||n.ip END AS asset_identity
			FROM topology_nodes n
			WHERE n.active=TRUE AND COALESCE(n.identity_conflict,FALSE)=FALSE
		), active_ids AS (
			SELECT DISTINCT sensor_id,asset_identity FROM active
		), grouped AS (
			SELECT a.sensor_id,a.asset_identity,
			       MIN(h.first_seen) AS first_seen,
			       MAX(h.last_seen) AS last_seen,
			       COUNT(DISTINCT h.ip)::int AS ip_count,
			       COUNT(h.ip)::int AS source_count,
			       ARRAY_AGG(DISTINCT h.ip ORDER BY h.ip) AS aliases
			FROM active_ids a
			JOIN asset_identity_history h ON h.sensor_id=a.sensor_id AND h.asset_identity=a.asset_identity
			GROUP BY a.sensor_id,a.asset_identity
		)
		SELECT n.sensor_id,n.ip,n.asset_identity,
		       COALESCE(g.first_seen,n.first_seen),COALESCE(g.last_seen,n.last_seen),
		       COALESCE(g.ip_count,1),COALESCE(g.source_count,1),COALESCE(g.aliases,ARRAY[n.ip]::text[]),
		       CASE
		         WHEN n.mac <> '' THEN 'high'
		         WHEN n.hostname <> '' OR n.vendor <> '' THEN 'medium'
		         ELSE 'low'
		       END AS confidence
		FROM active n
		LEFT JOIN grouped g ON g.sensor_id=n.sensor_id AND g.asset_identity=n.asset_identity`)
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
