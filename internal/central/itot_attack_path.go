package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type AssetContext struct {
	SensorID       string    `json:"sensor_id"`
	AssetIP        string    `json:"asset_ip"`
	AssetRole      string    `json:"asset_role"`
	Criticality    string    `json:"criticality"`
	Zone           string    `json:"zone"`
	PurdueOverride *float64  `json:"purdue_override,omitempty"`
	IsEntryPoint   bool      `json:"is_attack_path_entry"`
	IsTarget       bool      `json:"is_attack_path_target"`
	UpdatedBy      string    `json:"updated_by"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type ITOTNode struct {
	IP           string   `json:"ip"`
	Hostname     string   `json:"hostname"`
	Vendor       string   `json:"vendor"`
	VLANID       uint16   `json:"vlan_id"`
	IsOT         bool     `json:"is_ot"`
	Protocols    []string `json:"protocols"`
	AssetRole    string   `json:"asset_role"`
	Criticality  string   `json:"criticality"`
	Zone         string   `json:"zone"`
	PurdueLevel  *float64 `json:"purdue_level,omitempty"`
	PurdueSource string   `json:"purdue_source"`
	IsEntryPoint bool     `json:"is_attack_path_entry"`
	IsTarget     bool     `json:"is_attack_path_target"`
}

type ITOTEdge struct {
	InitiatorIP   string    `json:"initiator_ip"`
	ResponderIP   string    `json:"responder_ip"`
	Protocol      string    `json:"protocol"`
	ResponderPort uint16    `json:"responder_port"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	PacketsAToB   uint64    `json:"packets_a_to_b"`
	PacketsBToA   uint64    `json:"packets_b_to_a"`
	BytesAToB     uint64    `json:"bytes_a_to_b"`
	BytesBToA     uint64    `json:"bytes_b_to_a"`
	IsOT          bool      `json:"is_ot"`
}

type ITOTPath struct {
	Nodes          []ITOTNode `json:"nodes"`
	Edges          []ITOTEdge `json:"edges"`
	PathRiskScore  int        `json:"path_risk_score"`
	PathConfidence int        `json:"path_confidence"`
	CrossesITOT    bool       `json:"crosses_it_ot_boundary"`
	BypassesDMZ    bool       `json:"bypasses_dmz"`
	Reasons        []string   `json:"reasons"`
}

type ITOTPathResponse struct {
	SensorID      string     `json:"sensor_id"`
	SourceIP      string     `json:"source_ip"`
	LookbackHours int        `json:"lookback_hours"`
	MaxHops       int        `json:"max_hops"`
	GeneratedAt   time.Time  `json:"generated_at"`
	Paths         []ITOTPath `json:"paths"`
}

func (r *Repository) SetAssetContext(ctx context.Context, v AssetContext) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO asset_context(sensor_id,asset_ip,asset_role,criticality,zone,purdue_override,is_attack_path_entry,is_attack_path_target,updated_by,updated_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW()) ON CONFLICT(sensor_id,asset_ip) DO UPDATE SET asset_role=EXCLUDED.asset_role,criticality=EXCLUDED.criticality,zone=EXCLUDED.zone,purdue_override=EXCLUDED.purdue_override,is_attack_path_entry=EXCLUDED.is_attack_path_entry,is_attack_path_target=EXCLUDED.is_attack_path_target,updated_by=EXCLUDED.updated_by,updated_at=NOW()`,
		v.SensorID, v.AssetIP, v.AssetRole, v.Criticality, v.Zone, v.PurdueOverride, v.IsEntryPoint, v.IsTarget, v.UpdatedBy)
	return err
}

func (r *Repository) ListAssetContexts(ctx context.Context, sensorID string) (map[string]AssetContext, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id,asset_ip,asset_role,criticality,zone,purdue_override,is_attack_path_entry,is_attack_path_target,updated_by,updated_at FROM asset_context WHERE sensor_id=$1`, sensorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AssetContext{}
	for rows.Next() {
		var v AssetContext
		var p sql.NullFloat64
		if err := rows.Scan(&v.SensorID, &v.AssetIP, &v.AssetRole, &v.Criticality, &v.Zone, &p, &v.IsEntryPoint, &v.IsTarget, &v.UpdatedBy, &v.UpdatedAt); err != nil {
			return nil, err
		}
		if p.Valid {
			x := p.Float64
			v.PurdueOverride = &x
		}
		out[v.AssetIP] = v
	}
	return out, rows.Err()
}

func (r *Repository) buildITOTNodes(ctx context.Context, sensorID string) (map[string]ITOTNode, error) {
	persisted, err := r.ListTopologyNodes(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	contexts, err := r.ListAssetContexts(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	vlanRows, err := r.db.QueryContext(ctx, `SELECT vlan_id,name,purdue_level FROM vlan_config WHERE sensor_id=$1`, sensorID)
	if err != nil {
		return nil, err
	}
	type vc struct {
		name  string
		level *float64
	}
	vlans := map[uint16]vc{}
	for vlanRows.Next() {
		var id int
		var name string
		var p sql.NullFloat64
		if err := vlanRows.Scan(&id, &name, &p); err != nil {
			vlanRows.Close()
			return nil, err
		}
		var level *float64
		if p.Valid {
			x := p.Float64
			level = &x
		}
		vlans[uint16(id)] = vc{name, level}
	}
	vlanRows.Close()
	out := map[string]ITOTNode{}
	for _, n := range persisted {
		c := contexts[n.IP]
		v := vlans[n.VLANID]
		level, source := v.level, "vlan_config"
		if c.PurdueOverride != nil {
			level = c.PurdueOverride
			source = "asset_override"
		}
		if level == nil {
			source = "unclassified"
		}
		role := c.AssetRole
		if role == "" {
			role = inferAssetRole(n.IsOT, splitProtocols(n.Protocols))
		}
		zone := c.Zone
		if zone == "" {
			zone = v.name
		}
		out[n.IP] = ITOTNode{IP: n.IP, Hostname: n.Hostname, Vendor: n.Vendor, VLANID: n.VLANID, IsOT: n.IsOT, Protocols: splitProtocols(n.Protocols), AssetRole: role, Criticality: c.Criticality, Zone: zone, PurdueLevel: level, PurdueSource: source, IsEntryPoint: c.IsEntryPoint, IsTarget: c.IsTarget}
	}
	return out, nil
}

func inferAssetRole(isOT bool, protocols []string) string {
	joined := strings.ToLower(strings.Join(protocols, " "))
	if strings.Contains(joined, "s7") || strings.Contains(joined, "modbus") || strings.Contains(joined, "dnp3") || strings.Contains(joined, "iec104") {
		if isOT {
			return "industrial_controller"
		}
	}
	if isOT {
		return "ot_asset"
	}
	return "unknown"
}

func (r *Repository) observedITOTEdges(ctx context.Context, sensorID string, since time.Time) ([]ITOTEdge, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT COALESCE(NULLIF(initiator_ip,''),src_ip),COALESCE(NULLIF(responder_ip,''),dst_ip),protocol,COALESCE(NULLIF(responder_port,0),dst_port),MIN(bucket_start),MAX(bucket_end),SUM(packets_a_to_b),SUM(packets_b_to_a),SUM(bytes_a_to_b),SUM(bytes_b_to_a),BOOL_OR(is_ot) FROM flow_observations WHERE sensor_id=$1 AND bucket_end >= $2 GROUP BY 1,2,3,4`, sensorID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ITOTEdge
	for rows.Next() {
		var e ITOTEdge
		if err := rows.Scan(&e.InitiatorIP, &e.ResponderIP, &e.Protocol, &e.ResponderPort, &e.FirstSeen, &e.LastSeen, &e.PacketsAToB, &e.PacketsBToA, &e.BytesAToB, &e.BytesBToA, &e.IsOT); err != nil {
			return nil, err
		}
		if e.InitiatorIP != "" && e.ResponderIP != "" {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

func nodeIsOTTarget(n ITOTNode) bool {
	return n.IsTarget || n.IsOT || (n.PurdueLevel != nil && *n.PurdueLevel <= 2)
}
func nodeIsIT(n ITOTNode) bool  { return n.PurdueLevel != nil && *n.PurdueLevel >= 4 }
func nodeIsDMZ(n ITOTNode) bool { return n.PurdueLevel != nil && math.Abs(*n.PurdueLevel-3.5) < 0.01 }

func scoreITOTPath(nodes []ITOTNode, edges []ITOTEdge) (int, int, bool, bool, []string) {
	risk, conf := 10, 30
	reasons := []string{"observed directional network communication"}
	crosses := false
	hasDMZ := false
	for _, n := range nodes {
		if nodeIsDMZ(n) {
			hasDMZ = true
		}
		if n.PurdueSource == "asset_override" {
			conf += 8
		}
		if n.AssetRole != "unknown" && n.AssetRole != "" {
			conf += 4
		}
		if n.Criticality == "critical" {
			risk += 15
			reasons = append(reasons, "critical asset in path")
		}
	}
	for i, e := range edges {
		p := e.ResponderPort
		if p == 445 || p == 3389 || p == 22 || p == 5985 || p == 5986 {
			risk += 18
			reasons = append(reasons, "administrative or file-transfer service")
		}
		if e.IsOT {
			risk += 15
			reasons = append(reasons, "OT protocol observed")
		}
		if e.PacketsAToB+e.PacketsBToA > 100 {
			conf += 5
		}
		if i+1 < len(nodes) && nodeIsIT(nodes[i]) && nodeIsOTTarget(nodes[i+1]) {
			crosses = true
			risk += 30
			reasons = append(reasons, "direct IT to OT transition")
		}
		conf += 6
	}
	if len(nodes) > 1 && nodeIsIT(nodes[0]) && nodeIsOTTarget(nodes[len(nodes)-1]) {
		crosses = true
	}
	bypass := crosses && !hasDMZ
	if bypass {
		risk += 20
		reasons = append(reasons, "path reaches OT without observed Level 3.5 DMZ")
	}
	if risk > 100 {
		risk = 100
	}
	if conf > 100 {
		conf = 100
	}
	return risk, conf, crosses, bypass, dedupeStrings(reasons)
}
func dedupeStrings(in []string) []string {
	m := map[string]bool{}
	var o []string
	for _, s := range in {
		if !m[s] {
			m[s] = true
			o = append(o, s)
		}
	}
	return o
}

func (r *Repository) FindObservedITOTPaths(ctx context.Context, sensorID, sourceIP string, lookback, maxHops, maxPaths int) (ITOTPathResponse, error) {
	if lookback <= 0 {
		lookback = 24
	}
	if maxHops < 1 {
		maxHops = 4
	}
	if maxHops > 8 {
		maxHops = 8
	}
	if maxPaths <= 0 {
		maxPaths = 50
	}
	if maxPaths > 200 {
		maxPaths = 200
	}
	nodes, err := r.buildITOTNodes(ctx, sensorID)
	if err != nil {
		return ITOTPathResponse{}, err
	}
	if _, ok := nodes[sourceIP]; !ok {
		return ITOTPathResponse{}, fmt.Errorf("source asset %s not found", sourceIP)
	}
	edges, err := r.observedITOTEdges(ctx, sensorID, time.Now().UTC().Add(-time.Duration(lookback)*time.Hour))
	if err != nil {
		return ITOTPathResponse{}, err
	}
	adj := map[string][]ITOTEdge{}
	for _, e := range edges {
		adj[e.InitiatorIP] = append(adj[e.InitiatorIP], e)
	}
	type state struct {
		ips []string
		es  []ITOTEdge
	}
	q := []state{{[]string{sourceIP}, nil}}
	var paths []ITOTPath
	for len(q) > 0 && len(paths) < maxPaths {
		cur := q[0]
		q = q[1:]
		last := cur.ips[len(cur.ips)-1]
		if len(cur.es) > 0 && nodeIsOTTarget(nodes[last]) {
			pn := make([]ITOTNode, 0, len(cur.ips))
			for _, ip := range cur.ips {
				pn = append(pn, nodes[ip])
			}
			risk, conf, cross, bypass, reasons := scoreITOTPath(pn, cur.es)
			paths = append(paths, ITOTPath{Nodes: pn, Edges: cur.es, PathRiskScore: risk, PathConfidence: conf, CrossesITOT: cross, BypassesDMZ: bypass, Reasons: reasons})
			continue
		}
		if len(cur.es) >= maxHops {
			continue
		}
		for _, e := range adj[last] {
			seen := false
			for _, ip := range cur.ips {
				if ip == e.ResponderIP {
					seen = true
					break
				}
			}
			if seen {
				continue
			}
			if _, ok := nodes[e.ResponderIP]; !ok {
				continue
			}
			ni := append(append([]string{}, cur.ips...), e.ResponderIP)
			ne := append(append([]ITOTEdge{}, cur.es...), e)
			q = append(q, state{ni, ne})
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].PathRiskScore == paths[j].PathRiskScore {
			return paths[i].PathConfidence > paths[j].PathConfidence
		}
		return paths[i].PathRiskScore > paths[j].PathRiskScore
	})
	return ITOTPathResponse{SensorID: sensorID, SourceIP: sourceIP, LookbackHours: lookback, MaxHops: maxHops, GeneratedAt: time.Now().UTC(), Paths: paths}, nil
}

func (s *Server) setAssetContext(c *gin.Context) {
	var req struct {
		AssetRole      string   `json:"asset_role"`
		Criticality    string   `json:"criticality"`
		Zone           string   `json:"zone"`
		PurdueOverride *float64 `json:"purdue_override"`
		IsEntryPoint   bool     `json:"is_attack_path_entry"`
		IsTarget       bool     `json:"is_attack_path_target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v := AssetContext{SensorID: c.Param("id"), AssetIP: c.Param("ip"), AssetRole: strings.TrimSpace(req.AssetRole), Criticality: strings.TrimSpace(req.Criticality), Zone: strings.TrimSpace(req.Zone), PurdueOverride: req.PurdueOverride, IsEntryPoint: req.IsEntryPoint, IsTarget: req.IsTarget, UpdatedBy: identityFromContext(c).Username}
	if err := s.Repo.SetAssetContext(c, v); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.invalidateTopologyCache()
	c.JSON(200, v)
}
func (s *Server) assetContexts(c *gin.Context) {
	v, e := s.Repo.ListAssetContexts(c, c.Query("sensor_id"))
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	out := make([]AssetContext, 0, len(v))
	for _, x := range v {
		out = append(out, x)
	}
	c.JSON(200, out)
}
func (s *Server) observedITOTPaths(c *gin.Context) {
	lookback, _ := strconv.Atoi(c.DefaultQuery("lookback_hours", "24"))
	hops, _ := strconv.Atoi(c.DefaultQuery("max_hops", "4"))
	limit, _ := strconv.Atoi(c.DefaultQuery("max_paths", "50"))
	v, e := s.Repo.FindObservedITOTPaths(c, c.Param("id"), c.Query("source_ip"), lookback, hops, limit)
	if e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	c.JSON(200, v)
}
func (s *Server) purdueTopology(c *gin.Context) {
	nodes, e := s.Repo.buildITOTNodes(c, c.Param("id"))
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	out := make([]ITOTNode, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := 99.0, 99.0
		if out[i].PurdueLevel != nil {
			a = *out[i].PurdueLevel
		}
		if out[j].PurdueLevel != nil {
			b = *out[j].PurdueLevel
		}
		if a == b {
			return out[i].IP < out[j].IP
		}
		return a > b
	})
	raw, _ := json.Marshal(gin.H{"sensor_id": c.Param("id"), "nodes": out})
	c.Data(200, "application/json", raw)
}

func (s *Server) invalidateTopologyCache() {
	s.topoCache.mu.Lock()
	s.topoCache.fingerprint = ""
	s.topoCache.etag = ""
	s.topoCache.body = nil
	s.topoCache.mu.Unlock()
}
