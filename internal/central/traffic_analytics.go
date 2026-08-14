package central

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type TrafficAnalyticsAsset struct {
	SensorID      string   `json:"sensor_id"`
	AssetIdentity string   `json:"asset_identity"`
	IP            string   `json:"ip"`
	MAC           string   `json:"mac"`
	Hostname      string   `json:"hostname"`
	Vendor        string   `json:"vendor"`
	Name          string   `json:"name"`
	Category      string   `json:"category"`
	Zone          string   `json:"zone"`
	VLANID        int      `json:"vlan_id"`
	PurdueLevel   *float64 `json:"purdue_level,omitempty"`
}

type TrafficAnalyticsOptions struct {
	Assets     []TrafficAnalyticsAsset `json:"assets"`
	Categories []string                `json:"categories"`
	Zones      []string                `json:"zones"`
	VLANs      []int                   `json:"vlans"`
	Purdue     []float64               `json:"purdue_levels"`
	Protocols  []string                `json:"protocols"`
}

type trafficScope struct {
	Type  string
	Value string
	// ResolvedIdentities is populated server-side for inventory scopes such as
	// VLAN, Purdue level, zone and device category. flow_observations stores one
	// packet VLAN only, so using that scalar for both endpoints makes cross-VLAN
	// analytics incorrect. Resolving the operator scope to stable identities first
	// gives each endpoint its own membership and also lets PostgreSQL filter the
	// high-volume flow table before enrichment.
	ResolvedIdentities []string
	// ResolvedKeys keeps sensor ownership attached to the identity. A MAC may be
	// visible through more than one sensor with different VLAN/zone context, so an
	// all-sensors query must not let membership learned on sensor A match sensor B.
	ResolvedKeys []string
	Resolved     bool
	// LegacyIPs is populated server-side for asset/inventory scopes. Modern flow
	// buckets carry stable identities directly; aliases are only used to preserve
	// event-time attribution for pre-v17 rows without choosing the wrong device
	// after DHCP reuse.
	LegacyIPs []string
}

type trafficAnalyticsRequest struct {
	From            time.Time
	To              time.Time
	SensorID        string
	Protocol        string
	Port            int
	Direction       string
	Left            trafficScope
	Right           trafficScope
	LeftLabel       string
	RightLabel      string
	CompareBaseline bool
	BaselineDays    int
	TZOffsetMinutes int
	// Internal query controls. They are never accepted directly from the client.
	BreakdownLimit int
	SkipPorts      bool
}

type TrafficSeriesPoint struct {
	Time         time.Time `json:"time"`
	OutBytes     uint64    `json:"out_bytes"`
	InBytes      uint64    `json:"in_bytes"`
	TotalBytes   uint64    `json:"total_bytes"`
	OutPackets   uint64    `json:"out_packets"`
	InPackets    uint64    `json:"in_packets"`
	TotalPackets uint64    `json:"total_packets"`
	Connections  int64     `json:"connections"`
	Anomaly      bool      `json:"anomaly"`
	Ratio        float64   `json:"ratio,omitempty"`
}

type TrafficBreakdown struct {
	Name        string `json:"name"`
	Bytes       uint64 `json:"bytes"`
	Packets     uint64 `json:"packets"`
	Connections int64  `json:"connections"`
}

type TrafficAnomaly struct {
	Time        time.Time `json:"time"`
	Bytes       uint64    `json:"bytes"`
	Baseline    uint64    `json:"baseline"`
	Threshold   uint64    `json:"threshold"`
	Ratio       float64   `json:"ratio"`
	Description string    `json:"description"`
}

type TrafficBaseline struct {
	Source         string `json:"source"`
	Samples        int    `json:"samples"`
	MedianBytes    uint64 `json:"median_bytes"`
	P95Bytes       uint64 `json:"p95_bytes"`
	ThresholdBytes uint64 `json:"threshold_bytes"`
	MADBytes       uint64 `json:"mad_bytes"`
}

type TrafficAnalyticsSummary struct {
	TotalBytes         uint64  `json:"total_bytes"`
	OutBytes           uint64  `json:"out_bytes"`
	InBytes            uint64  `json:"in_bytes"`
	TotalPackets       uint64  `json:"total_packets"`
	OutPackets         uint64  `json:"out_packets"`
	InPackets          uint64  `json:"in_packets"`
	Connections        int64   `json:"connections"`
	PeakBytesPerBucket uint64  `json:"peak_bytes_per_bucket"`
	PeakBitsPerSecond  float64 `json:"peak_bits_per_second"`
	AnomalousIntervals int     `json:"anomalous_intervals"`
}

type TrafficAnalyticsResponse struct {
	From               time.Time                  `json:"from"`
	To                 time.Time                  `json:"to"`
	StepSeconds        int                        `json:"step_seconds"`
	Direction          string                     `json:"direction"`
	LeftLabel          string                     `json:"left_label"`
	RightLabel         string                     `json:"right_label"`
	Summary            TrafficAnalyticsSummary    `json:"summary"`
	Series             []TrafficSeriesPoint       `json:"series"`
	TopProtocols       []TrafficBreakdown         `json:"top_protocols"`
	TopPorts           []TrafficBreakdown         `json:"top_ports"`
	TopPeers           []TrafficBreakdown         `json:"top_peers"`
	Anomalies          []TrafficAnomaly           `json:"anomalies"`
	Baseline           TrafficBaseline            `json:"baseline"`
	BaselineComparison *TrafficBaselineComparison `json:"baseline_comparison,omitempty"`
	Warning            string                     `json:"warning,omitempty"`
}

const analyticsServiceSQL = `CASE
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=445 OR src_port=445 OR dst_port=445 THEN 'SMB'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=53 OR src_port=53 OR dst_port=53 THEN 'DNS'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=123 OR src_port=123 OR dst_port=123 THEN 'NTP'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port) IN (161,162) OR src_port IN (161,162) OR dst_port IN (161,162) THEN 'SNMP'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=502 OR src_port=502 OR dst_port=502 THEN 'MODBUS'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=102 OR src_port=102 OR dst_port=102 THEN 'S7COMM'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=80 OR src_port=80 OR dst_port=80 THEN 'HTTP'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=443 OR src_port=443 OR dst_port=443 THEN 'HTTPS'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=22 OR src_port=22 OR dst_port=22 THEN 'SSH'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=3389 OR src_port=3389 OR dst_port=3389 THEN 'RDP'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=389 OR src_port=389 OR dst_port=389 THEN 'LDAP'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=636 OR src_port=636 OR dst_port=636 THEN 'LDAPS'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port)=25 OR src_port=25 OR dst_port=25 THEN 'SMTP'
 WHEN COALESCE(NULLIF(responder_port,0),dst_port) IN (137,138,139) OR src_port IN (137,138,139) OR dst_port IN (137,138,139) THEN 'NETBIOS'
 ELSE upper(COALESCE(NULLIF(protocol,''),'UNKNOWN')) END`

func analyticsProtocolOptions() []string {
	return []string{
		"SMB", "DNS", "NTP", "SNMP", "MODBUS", "S7COMM", "HTTP", "HTTPS", "SSH", "RDP", "LDAP", "LDAPS", "SMTP", "NETBIOS",
		"TCP", "UDP", "ICMP", "ICMPV6", "ARP", "UNKNOWN",
	}
}

func analyticsServicePorts(protocol string) []int {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "SMB":
		return []int{445}
	case "DNS":
		return []int{53}
	case "NTP":
		return []int{123}
	case "SNMP":
		return []int{161, 162}
	case "MODBUS":
		return []int{502}
	case "S7COMM":
		return []int{102}
	case "HTTP":
		return []int{80}
	case "HTTPS":
		return []int{443}
	case "SSH":
		return []int{22}
	case "RDP":
		return []int{3389}
	case "LDAP":
		return []int{389}
	case "LDAPS":
		return []int{636}
	case "SMTP":
		return []int{25}
	case "NETBIOS":
		return []int{137, 138, 139}
	default:
		return nil
	}
}

func appendAnalyticsProtocolFilter(base string, req trafficAnalyticsRequest, args *[]interface{}) string {
	protocol := strings.ToUpper(strings.TrimSpace(req.Protocol))
	if protocol == "" {
		return base
	}
	if ports := analyticsServicePorts(protocol); len(ports) > 0 {
		p := appendArg(args, ports)
		return base + ` AND (f.src_port=ANY(` + p + `::int[]) OR f.dst_port=ANY(` + p + `::int[]) OR f.initiator_port=ANY(` + p + `::int[]) OR f.responder_port=ANY(` + p + `::int[]))`
	}
	p := appendArg(args, protocol)
	return base + ` AND upper(f.protocol)=` + p
}

func appendAssetBasePrefilter(base string, scope trafficScope, args *[]interface{}) string {
	if strings.ToLower(strings.TrimSpace(scope.Type)) != "asset" || strings.TrimSpace(scope.Value) == "" {
		return base
	}
	identity := appendArg(args, strings.TrimSpace(scope.Value))
	parts := []string{`f.src_identity=` + identity, `f.dst_identity=` + identity}
	if len(scope.LegacyIPs) > 0 {
		ips := appendArg(args, scope.LegacyIPs)
		parts = append(parts, `f.src_ip=ANY(`+ips+`::text[])`, `f.dst_ip=ANY(`+ips+`::text[])`)
	}
	return base + ` AND (` + strings.Join(parts, ` OR `) + `)`
}

func analyticsInventoryScope(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "category", "zone", "vlan", "purdue":
		return true
	default:
		return false
	}
}

func appendResolvedScopeBasePrefilter(base string, scope trafficScope, args *[]interface{}) string {
	if !analyticsInventoryScope(scope.Type) || strings.TrimSpace(scope.Value) == "" || !scope.Resolved {
		return base
	}
	if len(scope.ResolvedIdentities) == 0 {
		return base + ` AND FALSE`
	}
	ids := appendArg(args, scope.ResolvedIdentities)
	parts := []string{`f.src_identity=ANY(` + ids + `::text[])`, `f.dst_identity=ANY(` + ids + `::text[])`}
	if len(scope.LegacyIPs) > 0 {
		ips := appendArg(args, scope.LegacyIPs)
		parts = append(parts,
			`((f.src_identity='' OR f.src_identity LIKE 'ip:%') AND f.src_ip=ANY(`+ips+`::text[]))`,
			`((f.dst_identity='' OR f.dst_identity LIKE 'ip:%') AND f.dst_ip=ANY(`+ips+`::text[]))`)
	}
	return base + ` AND (` + strings.Join(parts, ` OR `) + `)`
}

func analyticsScopeMatchesAsset(scope trafficScope, a TrafficAnalyticsAsset) bool {
	value := strings.TrimSpace(scope.Value)
	if value == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(scope.Type)) {
	case "category":
		return strings.EqualFold(strings.TrimSpace(a.Category), value)
	case "zone":
		return strings.EqualFold(strings.TrimSpace(a.Zone), value)
	case "vlan":
		v, err := strconv.Atoi(value)
		return err == nil && a.VLANID == v
	case "purdue":
		v, err := strconv.ParseFloat(value, 64)
		return err == nil && a.PurdueLevel != nil && math.Abs(*a.PurdueLevel-v) < 0.0001
	default:
		return false
	}
}

func (r *Repository) resolveAnalyticsInventoryScopes(ctx context.Context, req *trafficAnalyticsRequest) error {
	if req == nil {
		return nil
	}
	if !analyticsInventoryScope(req.Left.Type) && !analyticsInventoryScope(req.Right.Type) {
		return nil
	}
	options, err := r.TrafficAnalyticsOptions(ctx)
	if err != nil {
		return err
	}
	resolve := func(scope *trafficScope) {
		if scope == nil || !analyticsInventoryScope(scope.Type) || strings.TrimSpace(scope.Value) == "" {
			return
		}
		scope.Resolved = true
		seen := make(map[string]struct{})
		seenKeys := make(map[string]struct{})
		for _, a := range options.Assets {
			if req.SensorID != "" && a.SensorID != req.SensorID {
				continue
			}
			if !analyticsScopeMatchesAsset(*scope, a) || strings.TrimSpace(a.AssetIdentity) == "" {
				continue
			}
			if _, ok := seen[a.AssetIdentity]; !ok {
				seen[a.AssetIdentity] = struct{}{}
				scope.ResolvedIdentities = append(scope.ResolvedIdentities, a.AssetIdentity)
			}
			key := a.SensorID + string(rune(31)) + a.AssetIdentity
			if _, ok := seenKeys[key]; !ok {
				seenKeys[key] = struct{}{}
				scope.ResolvedKeys = append(scope.ResolvedKeys, key)
			}
		}
		sort.Strings(scope.ResolvedIdentities)
		sort.Strings(scope.ResolvedKeys)
	}
	resolve(&req.Left)
	resolve(&req.Right)
	return nil
}

func (r *Repository) populateAnalyticsScopeLegacyAliases(ctx context.Context, scope *trafficScope, sensorID string, from, to time.Time) error {
	if scope == nil || len(scope.ResolvedIdentities) == 0 || !analyticsInventoryScope(scope.Type) {
		return nil
	}
	args := []interface{}{scope.ResolvedIdentities, from, to}
	whereSensor := ""
	if sensorID != "" {
		args = append(args, sensorID)
		whereSensor = fmt.Sprintf(" AND sensor_id=$%d", len(args))
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT ip FROM asset_ip_binding_history WHERE asset_identity=ANY($1::text[]) AND valid_from<$3 AND (valid_to IS NULL OR valid_to>=$2)`+whereSensor+` ORDER BY ip LIMIT 2048`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return err
		}
		if strings.TrimSpace(ip) != "" {
			scope.LegacyIPs = append(scope.LegacyIPs, ip)
		}
	}
	return rows.Err()
}

func (r *Repository) populateAnalyticsLegacyAliases(ctx context.Context, scope *trafficScope, sensorID string, from, to time.Time) error {
	if scope == nil || strings.ToLower(strings.TrimSpace(scope.Type)) != "asset" || strings.TrimSpace(scope.Value) == "" {
		return nil
	}
	if strings.HasPrefix(scope.Value, "ip:") {
		scope.LegacyIPs = []string{strings.TrimPrefix(scope.Value, "ip:")}
		return nil
	}
	args := []interface{}{scope.Value, from, to}
	whereSensor := ""
	if sensorID != "" {
		args = append(args, sensorID)
		whereSensor = fmt.Sprintf(" AND sensor_id=$%d", len(args))
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT ip FROM asset_ip_binding_history WHERE asset_identity=$1 AND valid_from<$3 AND (valid_to IS NULL OR valid_to>=$2)`+whereSensor+` ORDER BY ip LIMIT 256`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return err
		}
		if ip != "" {
			scope.LegacyIPs = append(scope.LegacyIPs, ip)
		}
	}
	return rows.Err()
}

func (r *Repository) TrafficAnalyticsOptions(ctx context.Context) (TrafficAnalyticsOptions, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT DISTINCT ON (n.sensor_id, CASE WHEN n.mac<>'' THEN 'mac:'||lower(n.mac) ELSE 'ip:'||n.ip END)
 n.sensor_id,CASE WHEN n.mac<>'' THEN 'mac:'||lower(n.mac) ELSE 'ip:'||n.ip END,n.ip,n.mac,n.hostname,n.vendor,n.is_ot,n.confirmed,n.vlan_id,
 COALESCE(o.category,''),COALESCE(o.name,''),COALESCE(c.asset_role,''),COALESCE(c.zone,''),COALESCE(v.name,''),c.purdue_override,v.purdue_level
FROM topology_nodes n
LEFT JOIN asset_overrides o ON o.sensor_id=n.sensor_id AND lower(o.mac)=lower(n.mac)
LEFT JOIN asset_context c ON c.sensor_id=n.sensor_id AND c.asset_identity=(CASE WHEN n.mac<>'' THEN 'mac:'||lower(n.mac) ELSE 'ip:'||n.ip END)
LEFT JOIN vlan_config v ON v.sensor_id=n.sensor_id AND v.vlan_id=n.vlan_id
WHERE n.active=TRUE AND n.identity_conflict=FALSE
ORDER BY n.sensor_id,(CASE WHEN n.mac<>'' THEN 'mac:'||lower(n.mac) ELSE 'ip:'||n.ip END),n.last_seen DESC`)
	if err != nil {
		return TrafficAnalyticsOptions{}, err
	}
	defer rows.Close()
	out := TrafficAnalyticsOptions{Assets: []TrafficAnalyticsAsset{}, Categories: []string{}, Zones: []string{}, VLANs: []int{}, Purdue: []float64{}, Protocols: []string{}}
	catSet, zoneSet, vlanSet, purdueSet := map[string]bool{}, map[string]bool{}, map[int]bool{}, map[float64]bool{}
	for rows.Next() {
		var a TrafficAnalyticsAsset
		var isOT, confirmed bool
		var overrideCategory, overrideName, role, zone, vlanName string
		var contextPurdue, vlanPurdue sql.NullFloat64
		if err := rows.Scan(&a.SensorID, &a.AssetIdentity, &a.IP, &a.MAC, &a.Hostname, &a.Vendor, &isOT, &confirmed, &a.VLANID, &overrideCategory, &overrideName, &role, &zone, &vlanName, &contextPurdue, &vlanPurdue); err != nil {
			return TrafficAnalyticsOptions{}, err
		}
		effectiveOT := isOT
		if role != "" || contextPurdue.Valid {
			effectiveOT = roleIsOT(role) || (contextPurdue.Valid && contextPurdue.Float64 <= 3)
		}
		a.Category = classifyDeviceCategory(a.Vendor, effectiveOT, confirmed)
		if overrideCategory != "" {
			a.Category = overrideCategory
		}
		a.Name = overrideName
		if a.Name == "" {
			a.Name = a.Hostname
		}
		if a.Name == "" {
			a.Name = a.IP
		}
		a.Zone = zone
		if a.Zone == "" {
			a.Zone = vlanName
		}
		if contextPurdue.Valid {
			v := contextPurdue.Float64
			a.PurdueLevel = &v
		} else if vlanPurdue.Valid {
			v := vlanPurdue.Float64
			a.PurdueLevel = &v
		}
		out.Assets = append(out.Assets, a)
		if a.Category != "" {
			catSet[a.Category] = true
		}
		if a.Zone != "" {
			zoneSet[a.Zone] = true
		}
		if a.VLANID > 0 {
			vlanSet[a.VLANID] = true
		}
		if a.PurdueLevel != nil {
			purdueSet[*a.PurdueLevel] = true
		}
	}
	if err := rows.Err(); err != nil {
		return TrafficAnalyticsOptions{}, err
	}
	// Include the complete operator-managed catalogue, not only categories that
	// happen to be assigned to a currently active asset. This keeps Analytics
	// filters consistent with Device classification immediately after Add category.
	categories, err := r.ListAssetCategories(ctx)
	if err != nil {
		return TrafficAnalyticsOptions{}, err
	}
	for _, category := range categories {
		if strings.TrimSpace(category.Name) != "" {
			catSet[category.Name] = true
		}
	}
	// Do not scan the high-volume flow history just to populate a dropdown.
	// Services are derived deterministically from ports and transport protocols,
	// so the catalogue is stable and can be returned in O(1). This used to scan
	// up to 90 days of flow_observations before any Analytics tab could render.
	out.Protocols = analyticsProtocolOptions()
	for x := range catSet {
		out.Categories = append(out.Categories, x)
	}
	for x := range zoneSet {
		out.Zones = append(out.Zones, x)
	}
	for x := range vlanSet {
		out.VLANs = append(out.VLANs, x)
	}
	for x := range purdueSet {
		out.Purdue = append(out.Purdue, x)
	}
	sort.Slice(out.Assets, func(i, j int) bool {
		if out.Assets[i].SensorID != out.Assets[j].SensorID {
			return out.Assets[i].SensorID < out.Assets[j].SensorID
		}
		return strings.ToLower(out.Assets[i].Name) < strings.ToLower(out.Assets[j].Name)
	})
	sort.Slice(out.Categories, func(i, j int) bool { return strings.ToLower(out.Categories[i]) < strings.ToLower(out.Categories[j]) })
	sort.Strings(out.Zones)
	sort.Ints(out.VLANs)
	sort.Float64s(out.Purdue)
	return out, nil
}

func analyticsCTE(baseWhere string, lightweight bool) string {
	common := `WITH raw AS (
 SELECT f.*
 FROM flow_observations f
 WHERE ` + baseWhere + `
), enriched AS (
 SELECT raw.*,COALESCE(NULLIF(src_identity,''),'ip:'||src_ip) src_id,COALESCE(NULLIF(dst_identity,''),'ip:'||dst_ip) dst_id
 FROM raw
), oriented AS (
 SELECT enriched.*,
   COALESCE(NULLIF(initiator_ip,''),src_ip) initiator_ip_eff,COALESCE(NULLIF(responder_ip,''),dst_ip) responder_ip_eff,
   CASE WHEN COALESCE(NULLIF(initiator_ip,''),src_ip)=src_ip THEN src_id WHEN COALESCE(NULLIF(initiator_ip,''),src_ip)=dst_ip THEN dst_id ELSE src_id END initiator_identity,
   CASE WHEN COALESCE(NULLIF(responder_ip,''),dst_ip)=dst_ip THEN dst_id WHEN COALESCE(NULLIF(responder_ip,''),dst_ip)=src_ip THEN src_id ELSE dst_id END responder_identity
 FROM enriched
)`
	if lightweight {
		// An unrestricted Network/Zone request does not need topology, override or
		// identity-name joins at all. Keep peer labels IP-based in this fast path so
		// an Any↔Any six-hour graph is a bounded flow aggregation rather than a join
		// against the inventory for every bucket.
		return common + `, decorated AS (
 SELECT o.*,
  COALESCE(NULLIF(o.initiator_ip_eff,''),o.initiator_identity,'Unknown') initiator_name,
  COALESCE(NULLIF(o.responder_ip_eff,''),o.responder_identity,'Unknown') responder_name
 FROM oriented o
)`
	}
	// Scoped analytics keeps friendly current peer names. Scope membership itself
	// has already been resolved to stable identities before this hot path.
	return common + `, current_identity AS (
 SELECT DISTINCT ON(sensor_id,identity) sensor_id,identity,ip,mac,hostname FROM (
  SELECT n.sensor_id,CASE WHEN n.mac<>'' THEN 'mac:'||lower(n.mac) ELSE 'ip:'||n.ip END identity,n.ip,n.mac,n.hostname,n.last_seen
  FROM topology_nodes n WHERE n.active=TRUE AND n.identity_conflict=FALSE
 ) q ORDER BY sensor_id,identity,last_seen DESC
), decorated AS (
 SELECT o.*,
  COALESCE(NULLIF(io.name,''),NULLIF(ci.hostname,''),NULLIF(ci.ip,''),o.initiator_ip_eff,o.initiator_identity) initiator_name,
  COALESCE(NULLIF(ro.name,''),NULLIF(cr.hostname,''),NULLIF(cr.ip,''),o.responder_ip_eff,o.responder_identity) responder_name
 FROM oriented o
 LEFT JOIN current_identity ci ON ci.sensor_id=o.sensor_id AND ci.identity=o.initiator_identity
 LEFT JOIN current_identity cr ON cr.sensor_id=o.sensor_id AND cr.identity=o.responder_identity
 LEFT JOIN asset_overrides io ON io.sensor_id=o.sensor_id AND lower(io.mac)=lower(ci.mac)
 LEFT JOIN asset_overrides ro ON ro.sensor_id=o.sensor_id AND lower(ro.mac)=lower(cr.mac)
)`
}

func appendArg(args *[]interface{}, v interface{}) string {
	*args = append(*args, v)
	return fmt.Sprintf("$%d", len(*args))
}

func scopeCondition(prefix string, s trafficScope, args *[]interface{}) string {
	typ := strings.ToLower(strings.TrimSpace(s.Type))
	val := strings.TrimSpace(s.Value)
	if typ == "" || typ == "any" || val == "" {
		return "TRUE"
	}
	if analyticsInventoryScope(typ) {
		if !s.Resolved || len(s.ResolvedIdentities) == 0 {
			return "FALSE"
		}
		identityParam := ""
		keyParam := ""
		cond := ""
		if len(s.ResolvedKeys) > 0 {
			keyParam = appendArg(args, s.ResolvedKeys)
			cond = `(decorated.sensor_id||chr(31)||` + prefix + `_identity)=ANY(` + keyParam + `::text[])`
		} else {
			identityParam = appendArg(args, s.ResolvedIdentities)
			cond = prefix + `_identity=ANY(` + identityParam + `::text[])`
		}
		if len(s.LegacyIPs) > 0 {
			ips := appendArg(args, s.LegacyIPs)
			historyMembership := ""
			if keyParam != "" {
				historyMembership = `(ah.sensor_id||chr(31)||ah.asset_identity)=ANY(` + keyParam + `::text[])`
			} else {
				historyMembership = `ah.asset_identity=ANY(` + identityParam + `::text[])`
			}
			cond += ` OR (` + prefix + `_identity LIKE 'ip:%' AND ` + prefix + `_ip_eff=ANY(` + ips + `::text[]) AND EXISTS (` +
				`SELECT 1 FROM asset_ip_binding_history ah WHERE ah.sensor_id=decorated.sensor_id AND ` + historyMembership +
				` AND ah.ip=` + prefix + `_ip_eff AND ah.valid_from<=decorated.bucket_end AND (ah.valid_to IS NULL OR ah.valid_to>=decorated.bucket_start)))`
		}
		return "(" + cond + ")"
	}

	p := appendArg(args, val)
	switch typ {
	case "asset":
		cond := prefix + "_identity=" + p
		if len(s.LegacyIPs) > 0 {
			ips := appendArg(args, s.LegacyIPs)
			cond += ` OR (` + prefix + `_identity LIKE 'ip:%' AND ` + prefix + `_ip_eff=ANY(` + ips + `::text[]) AND EXISTS (` +
				`SELECT 1 FROM asset_ip_binding_history ah WHERE ah.sensor_id=decorated.sensor_id AND ah.asset_identity=` + p +
				` AND ah.ip=` + prefix + `_ip_eff AND ah.valid_from<=decorated.bucket_end AND (ah.valid_to IS NULL OR ah.valid_to>=decorated.bucket_start)))`
		}
		return "(" + cond + ")"
	default:
		return "FALSE"
	}
}

func buildAnalyticsQuery(req trafficAnalyticsRequest, from, to time.Time, step int, mode string) (string, []interface{}, string, string, string, error) {
	args := []interface{}{}
	pf := appendArg(&args, from)
	pt := appendArg(&args, to)
	base := `f.bucket_start>=date_trunc('minute',` + pf + `::timestamptz) AND f.bucket_start<` + pt
	if req.SensorID != "" {
		p := appendArg(&args, req.SensorID)
		base += ` AND f.sensor_id=` + p
	}
	base = appendAnalyticsProtocolFilter(base, req, &args)
	if req.Port > 0 {
		p := appendArg(&args, req.Port)
		base += ` AND (f.src_port=` + p + ` OR f.dst_port=` + p + ` OR f.initiator_port=` + p + ` OR f.responder_port=` + p + `)`
	}
	// Asset-specific queries are by far the most common Analytics operation.
	// Push the stable identity / legacy IP predicate into the raw table scan so
	// PostgreSQL can use the identity/IP+time indexes before any enrichment joins.
	base = appendAssetBasePrefilter(base, req.Left, &args)
	base = appendAssetBasePrefilter(base, req.Right, &args)
	base = appendResolvedScopeBasePrefilter(base, req.Left, &args)
	base = appendResolvedScopeBasePrefilter(base, req.Right, &args)

	leftAny := req.Left.Type == "" || req.Left.Type == "any" || req.Left.Value == ""
	rightAny := req.Right.Type == "" || req.Right.Type == "any" || req.Right.Value == ""
	cte := analyticsCTE(base, leftAny && rightAny)
	li := scopeCondition("initiator", req.Left, &args)
	lr := scopeCondition("responder", req.Left, &args)
	ri := scopeCondition("initiator", req.Right, &args)
	rr := scopeCondition("responder", req.Right, &args)
	pairCond := "TRUE"
	outExpr := "bytes_a_to_b"
	inExpr := "bytes_b_to_a"
	outPackets := "packets_a_to_b"
	inPackets := "packets_b_to_a"
	switch {
	case !leftAny && !rightAny:
		pairCond = `((` + li + `) AND (` + rr + `)) OR ((` + lr + `) AND (` + ri + `))`
		outExpr = `CASE WHEN (` + li + `) AND (` + rr + `) THEN bytes_a_to_b ELSE bytes_b_to_a END`
		inExpr = `CASE WHEN (` + li + `) AND (` + rr + `) THEN bytes_b_to_a ELSE bytes_a_to_b END`
		outPackets = `CASE WHEN (` + li + `) AND (` + rr + `) THEN packets_a_to_b ELSE packets_b_to_a END`
		inPackets = `CASE WHEN (` + li + `) AND (` + rr + `) THEN packets_b_to_a ELSE packets_a_to_b END`
	case !leftAny:
		pairCond = `(` + li + `) OR (` + lr + `)`
		outExpr = `CASE WHEN (` + li + `) THEN bytes_a_to_b ELSE bytes_b_to_a END`
		inExpr = `CASE WHEN (` + li + `) THEN bytes_b_to_a ELSE bytes_a_to_b END`
		outPackets = `CASE WHEN (` + li + `) THEN packets_a_to_b ELSE packets_b_to_a END`
		inPackets = `CASE WHEN (` + li + `) THEN packets_b_to_a ELSE packets_a_to_b END`
	case !rightAny:
		pairCond = `(` + ri + `) OR (` + rr + `)`
		outExpr = `CASE WHEN (` + rr + `) THEN bytes_a_to_b ELSE bytes_b_to_a END`
		inExpr = `CASE WHEN (` + rr + `) THEN bytes_b_to_a ELSE bytes_a_to_b END`
		outPackets = `CASE WHEN (` + rr + `) THEN packets_a_to_b ELSE packets_b_to_a END`
		inPackets = `CASE WHEN (` + rr + `) THEN packets_b_to_a ELSE packets_a_to_b END`
	}

	stepP := ""
	if mode == "series" || mode == "bundle" {
		stepP = appendArg(&args, step)
	}
	metricExpr := `(` + outExpr + `+` + inExpr + `)`
	metricPackets := `(` + outPackets + `+` + inPackets + `)`
	if req.Direction == "out" {
		metricExpr = `(` + outExpr + `)`
		metricPackets = `(` + outPackets + `)`
	} else if req.Direction == "in" {
		metricExpr = `(` + inExpr + `)`
		metricPackets = `(` + inPackets + `)`
	}
	peerName := `CASE WHEN (` + li + `) THEN responder_name WHEN (` + lr + `) THEN initiator_name ELSE responder_name END`
	if leftAny && !rightAny {
		peerName = `CASE WHEN (` + ri + `) THEN responder_name WHEN (` + rr + `) THEN initiator_name ELSE responder_name END`
	} else if leftAny && rightAny {
		peerName = `responder_name`
	}

	rankLimit := req.BreakdownLimit
	if rankLimit <= 0 {
		rankLimit = 12
	}
	if rankLimit > 4096 {
		rankLimit = 4096
	}
	groupingSets := "((bucket),(service_name),(port_name),(peer_name),())"
	kindCase := "CASE WHEN GROUPING(bucket)=0 THEN 'series' WHEN GROUPING(service_name)=0 THEN 'protocol' WHEN GROUPING(port_name)=0 THEN 'port' WHEN GROUPING(peer_name)=0 THEN 'peer' ELSE 'summary' END"
	nameCase := "CASE WHEN GROUPING(service_name)=0 THEN service_name WHEN GROUPING(port_name)=0 THEN port_name WHEN GROUPING(peer_name)=0 THEN peer_name ELSE ''::text END"
	if req.SkipPorts {
		groupingSets = "((bucket),(service_name),(peer_name),())"
		kindCase = "CASE WHEN GROUPING(bucket)=0 THEN 'series' WHEN GROUPING(service_name)=0 THEN 'protocol' WHEN GROUPING(peer_name)=0 THEN 'peer' ELSE 'summary' END"
		nameCase = "CASE WHEN GROUPING(service_name)=0 THEN service_name WHEN GROUPING(peer_name)=0 THEN peer_name ELSE ''::text END"
	}

	var tail string
	switch mode {
	case "series":
		tail = ` SELECT to_timestamp(floor(extract(epoch from bucket_start)/` + stepP + `)*` + stepP + `) bucket,COALESCE(SUM(` + outExpr + `)::bigint,0),COALESCE(SUM(` + inExpr + `)::bigint,0),COALESCE(SUM(` + outPackets + `)::bigint,0),COALESCE(SUM(` + inPackets + `)::bigint,0),COUNT(DISTINCT (sensor_id,flow_id)) FROM decorated WHERE ` + pairCond + ` GROUP BY 1 ORDER BY 1`
	case "bundle":
		// Aggregate the selected flow rows once with GROUPING SETS. The previous
		// implementation materialized the filtered rows and then scanned that
		// materialization separately for series, summary, protocols, ports and
		// peers. Broad Network/Zone scopes could therefore traverse the same
		// six-hour working set five times before baseline processing even began.
		rankMetric := `(out_bytes+in_bytes)`
		if req.Direction == "out" {
			rankMetric = `out_bytes`
		} else if req.Direction == "in" {
			rankMetric = `in_bytes`
		}
		tail = `, selected AS MATERIALIZED (
 SELECT sensor_id,flow_id,to_timestamp(floor(extract(epoch from bucket_start)/` + stepP + `)*` + stepP + `) bucket,
        (` + outExpr + `)::bigint out_bytes,(` + inExpr + `)::bigint in_bytes,
        (` + outPackets + `)::bigint out_packets,(` + inPackets + `)::bigint in_packets,
        (` + analyticsServiceSQL + `) service_name,
        COALESCE(NULLIF(responder_port,0),dst_port)::text port_name,
        COALESCE(NULLIF(` + peerName + `,''),'Unknown') peer_name
 FROM decorated WHERE ` + pairCond + `
), grouped AS (
 SELECT ` + kindCase + ` kind,
        bucket,
        ` + nameCase + ` name,
        COALESCE(SUM(out_bytes)::bigint,0) out_bytes,COALESCE(SUM(in_bytes)::bigint,0) in_bytes,
        COALESCE(SUM(out_packets)::bigint,0) out_packets,COALESCE(SUM(in_packets)::bigint,0) in_packets,
        COUNT(DISTINCT (sensor_id,flow_id)) connections
 FROM selected
 GROUP BY GROUPING SETS ` + groupingSets + `
), ranked AS (
 SELECT grouped.*,CASE WHEN kind IN ('protocol','port','peer') THEN
        row_number() OVER (PARTITION BY kind ORDER BY ` + rankMetric + ` DESC) ELSE 1 END rn
 FROM grouped
)
 SELECT kind,bucket,name,out_bytes,in_bytes,out_packets,in_packets,connections
 FROM ranked WHERE kind IN ('series','summary') OR rn<=` + strconv.Itoa(rankLimit) + `
 ORDER BY kind,bucket NULLS LAST,` + rankMetric + ` DESC`
	case "summary":
		tail = ` SELECT COALESCE(SUM(` + outExpr + `)::bigint,0),COALESCE(SUM(` + inExpr + `)::bigint,0),COALESCE(SUM(` + outPackets + `)::bigint,0),COALESCE(SUM(` + inPackets + `)::bigint,0),COUNT(DISTINCT (sensor_id,flow_id)) FROM decorated WHERE ` + pairCond
	case "protocols":
		tail = ` SELECT (` + analyticsServiceSQL + `),COALESCE(SUM(` + metricExpr + `)::bigint,0),COALESCE(SUM(` + metricPackets + `)::bigint,0),COUNT(DISTINCT (sensor_id,flow_id)) FROM decorated WHERE ` + pairCond + ` GROUP BY 1 ORDER BY 2 DESC LIMIT 12`
	case "ports":
		tail = ` SELECT COALESCE(NULLIF(responder_port,0),dst_port)::text,COALESCE(SUM(` + metricExpr + `)::bigint,0),COALESCE(SUM(` + metricPackets + `)::bigint,0),COUNT(DISTINCT (sensor_id,flow_id)) FROM decorated WHERE ` + pairCond + ` GROUP BY 1 ORDER BY 2 DESC LIMIT 12`
	case "peers":
		tail = ` SELECT ` + peerName + `,COALESCE(SUM(` + metricExpr + `)::bigint,0),COALESCE(SUM(` + metricPackets + `)::bigint,0),COUNT(DISTINCT (sensor_id,flow_id)) FROM decorated WHERE ` + pairCond + ` GROUP BY 1 ORDER BY 2 DESC LIMIT 12`
	default:
		return "", nil, "", "", "", fmt.Errorf("unsupported analytics query mode %q", mode)
	}
	return cte + tail, args, outExpr, inExpr, pairCond, nil
}

func stepForRange(d time.Duration) int {
	switch {
	case d <= 6*time.Hour:
		return 60
	case d <= 24*time.Hour:
		return 300
	case d <= 7*24*time.Hour:
		return 900
	case d <= 31*24*time.Hour:
		return 3600
	default:
		return 21600
	}
}

func parseAnalyticsTime(c *gin.Context) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	to := now
	from := now.Add(-24 * time.Hour)
	if v := strings.TrimSpace(c.Query("from")); v != "" {
		x, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return from, to, fmt.Errorf("invalid from timestamp")
		}
		from = x.UTC()
	}
	if v := strings.TrimSpace(c.Query("to")); v != "" {
		x, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return from, to, fmt.Errorf("invalid to timestamp")
		}
		to = x.UTC()
	}
	if !from.Before(to) {
		return from, to, fmt.Errorf("from must be before to")
	}
	if to.Sub(from) > 180*24*time.Hour {
		return from, to, fmt.Errorf("maximum analytics range is 180 days")
	}
	return from, to, nil
}

type trafficAnalyticsBundle struct {
	Series       []TrafficSeriesPoint
	Summary      TrafficAnalyticsSummary
	TopProtocols []TrafficBreakdown
	TopPorts     []TrafficBreakdown
	TopPeers     []TrafficBreakdown
}

func queryAnalyticsBundle(ctx context.Context, r *Repository, req trafficAnalyticsRequest, from, to time.Time, step int) (trafficAnalyticsBundle, error) {
	q, args, _, _, _, err := buildAnalyticsQuery(req, from, to, step, "bundle")
	if err != nil {
		return trafficAnalyticsBundle{}, err
	}
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return trafficAnalyticsBundle{}, err
	}
	defer rows.Close()
	out := trafficAnalyticsBundle{Series: []TrafficSeriesPoint{}, TopProtocols: []TrafficBreakdown{}, TopPorts: []TrafficBreakdown{}, TopPeers: []TrafficBreakdown{}}
	for rows.Next() {
		var kind, name string
		var bucket sql.NullTime
		var outBytes, inBytes, outPackets, inPackets, connections int64
		if err := rows.Scan(&kind, &bucket, &name, &outBytes, &inBytes, &outPackets, &inPackets, &connections); err != nil {
			return trafficAnalyticsBundle{}, err
		}
		if outBytes < 0 || inBytes < 0 || outPackets < 0 || inPackets < 0 || connections < 0 {
			return trafficAnalyticsBundle{}, fmt.Errorf("traffic analytics returned negative counters")
		}
		switch kind {
		case "series":
			if !bucket.Valid {
				continue
			}
			p := TrafficSeriesPoint{Time: bucket.Time, OutBytes: uint64(outBytes), InBytes: uint64(inBytes), OutPackets: uint64(outPackets), InPackets: uint64(inPackets), Connections: connections}
			if req.Direction == "out" {
				p.InBytes, p.InPackets = 0, 0
			} else if req.Direction == "in" {
				p.OutBytes, p.OutPackets = 0, 0
			}
			p.TotalBytes = p.OutBytes + p.InBytes
			p.TotalPackets = p.OutPackets + p.InPackets
			out.Series = append(out.Series, p)
		case "summary":
			out.Summary.OutBytes = uint64(outBytes)
			out.Summary.InBytes = uint64(inBytes)
			out.Summary.OutPackets = uint64(outPackets)
			out.Summary.InPackets = uint64(inPackets)
			out.Summary.Connections = connections
		case "protocol", "port", "peer":
			if name == "" {
				name = "Unknown"
			}
			metricBytes := outBytes + inBytes
			metricPackets := outPackets + inPackets
			if req.Direction == "out" {
				metricBytes, metricPackets = outBytes, outPackets
			} else if req.Direction == "in" {
				metricBytes, metricPackets = inBytes, inPackets
			}
			x := TrafficBreakdown{Name: name, Bytes: uint64(metricBytes), Packets: uint64(metricPackets), Connections: connections}
			switch kind {
			case "protocol":
				out.TopProtocols = append(out.TopProtocols, x)
			case "port":
				out.TopPorts = append(out.TopPorts, x)
			case "peer":
				out.TopPeers = append(out.TopPeers, x)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return trafficAnalyticsBundle{}, err
	}
	if req.Direction == "out" {
		out.Summary.InBytes, out.Summary.InPackets = 0, 0
	} else if req.Direction == "in" {
		out.Summary.OutBytes, out.Summary.OutPackets = 0, 0
	}
	out.Summary.TotalBytes = out.Summary.OutBytes + out.Summary.InBytes
	out.Summary.TotalPackets = out.Summary.OutPackets + out.Summary.InPackets
	return out, nil
}

func querySeries(ctx context.Context, r *Repository, req trafficAnalyticsRequest, from, to time.Time, step int) ([]TrafficSeriesPoint, error) {
	q, args, _, _, _, err := buildAnalyticsQuery(req, from, to, step, "series")
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrafficSeriesPoint{}
	for rows.Next() {
		var p TrafficSeriesPoint
		var outBytes, inBytes, outPackets, inPackets, connections int64
		if err := rows.Scan(&p.Time, &outBytes, &inBytes, &outPackets, &inPackets, &connections); err != nil {
			return nil, err
		}
		if outBytes < 0 || inBytes < 0 || outPackets < 0 || inPackets < 0 || connections < 0 {
			return nil, fmt.Errorf("traffic analytics returned negative counters")
		}
		p.OutBytes, p.InBytes = uint64(outBytes), uint64(inBytes)
		p.OutPackets, p.InPackets, p.Connections = uint64(outPackets), uint64(inPackets), connections
		if req.Direction == "out" {
			p.InBytes = 0
			p.InPackets = 0
		} else if req.Direction == "in" {
			p.OutBytes = 0
			p.OutPackets = 0
		}
		p.TotalBytes = p.OutBytes + p.InBytes
		p.TotalPackets = p.OutPackets + p.InPackets
		out = append(out, p)
	}
	return out, rows.Err()
}

func querySummary(ctx context.Context, r *Repository, req trafficAnalyticsRequest, from, to time.Time) (TrafficAnalyticsSummary, error) {
	q, args, _, _, _, err := buildAnalyticsQuery(req, from, to, 60, "summary")
	if err != nil {
		return TrafficAnalyticsSummary{}, err
	}
	var s TrafficAnalyticsSummary
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&s.OutBytes, &s.InBytes, &s.OutPackets, &s.InPackets, &s.Connections); err != nil {
		return s, err
	}
	if req.Direction == "out" {
		s.InBytes = 0
		s.InPackets = 0
	} else if req.Direction == "in" {
		s.OutBytes = 0
		s.OutPackets = 0
	}
	s.TotalBytes = s.OutBytes + s.InBytes
	s.TotalPackets = s.OutPackets + s.InPackets
	return s, nil
}

func queryBreakdown(ctx context.Context, r *Repository, req trafficAnalyticsRequest, from, to time.Time, mode string) ([]TrafficBreakdown, error) {
	q, args, _, _, _, err := buildAnalyticsQuery(req, from, to, 60, mode)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrafficBreakdown{}
	for rows.Next() {
		var x TrafficBreakdown
		if err := rows.Scan(&x.Name, &x.Bytes, &x.Packets, &x.Connections); err != nil {
			return nil, err
		}
		if x.Name == "" {
			x.Name = "Unknown"
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func percentile(vals []float64, p float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	x := append([]float64(nil), vals...)
	sort.Float64s(x)
	idx := p * float64(len(x)-1)
	lo := int(math.Floor(idx))
	hi := int(math.Ceil(idx))
	if lo == hi {
		return x[lo]
	}
	return x[lo] + (x[hi]-x[lo])*(idx-float64(lo))
}
func buildBaseline(series, baseline []TrafficSeriesPoint, sourceOverride ...string) (TrafficBaseline, []TrafficAnomaly) {
	source := "previous_30_days"
	if len(sourceOverride) > 0 && strings.TrimSpace(sourceOverride[0]) != "" {
		source = sourceOverride[0]
	}
	samples := baseline
	if len(samples) < 20 {
		source = "current_window"
		samples = series
	}
	vals := make([]float64, 0, len(samples))
	for _, p := range samples {
		vals = append(vals, float64(p.TotalBytes))
	}
	if len(vals) == 0 {
		return TrafficBaseline{Source: "insufficient_data"}, nil
	}
	med := percentile(vals, .5)
	p95 := percentile(vals, .95)
	dev := make([]float64, 0, len(vals))
	for _, v := range vals {
		dev = append(dev, math.Abs(v-med))
	}
	mad := percentile(dev, .5)
	sigma := 1.4826 * mad
	threshold := math.Max(1024*1024, math.Max(med*3, med+6*sigma))
	if p95 > threshold {
		threshold = p95 * 1.5
	}
	b := TrafficBaseline{Source: source, Samples: len(vals), MedianBytes: uint64(math.Round(med)), P95Bytes: uint64(math.Round(p95)), ThresholdBytes: uint64(math.Round(threshold)), MADBytes: uint64(math.Round(mad))}
	anomalies := []TrafficAnomaly{}
	for i := range series {
		v := float64(series[i].TotalBytes)
		if v <= threshold || series[i].TotalBytes == 0 {
			continue
		}
		comparison := med
		description := "Traffic volume above learned threshold"
		if comparison >= 1 {
			description = "Traffic volume above median baseline"
		} else {
			// A zero median is common for sparse device pairs. Dividing by one byte
			// would produce a spectacular but meaningless ratio, so compare sparse
			// traffic against the learned threshold (or P95 when available).
			comparison = math.Max(p95, threshold)
		}
		ratio := v / math.Max(comparison, 1)
		series[i].Anomaly = true
		series[i].Ratio = ratio
		anomalies = append(anomalies, TrafficAnomaly{Time: series[i].Time, Bytes: series[i].TotalBytes, Baseline: b.MedianBytes, Threshold: b.ThresholdBytes, Ratio: ratio, Description: description})
	}
	return b, anomalies
}

func analyticsBaselineWindow(d time.Duration) (time.Duration, string) {
	switch {
	case d <= 6*time.Hour:
		return 24 * time.Hour, "previous_24_hours"
	case d <= 24*time.Hour:
		return 3 * 24 * time.Hour, "previous_3_days"
	default:
		return 30 * 24 * time.Hour, "previous_30_days"
	}
}

func emptyTrafficAnalyticsResponse(req trafficAnalyticsRequest, step int) TrafficAnalyticsResponse {
	return TrafficAnalyticsResponse{
		From: req.From, To: req.To, StepSeconds: step, Direction: req.Direction,
		LeftLabel: req.LeftLabel, RightLabel: req.RightLabel,
		Series: []TrafficSeriesPoint{}, TopProtocols: []TrafficBreakdown{}, TopPorts: []TrafficBreakdown{},
		TopPeers: []TrafficBreakdown{}, Anomalies: []TrafficAnomaly{}, Baseline: TrafficBaseline{Source: "insufficient_data"},
	}
}

func analyticsScopeResolvedEmpty(scope trafficScope) bool {
	return analyticsInventoryScope(scope.Type) && strings.TrimSpace(scope.Value) != "" && scope.Resolved && len(scope.ResolvedIdentities) == 0
}

func (r *Repository) RunTrafficAnalytics(ctx context.Context, req trafficAnalyticsRequest) (TrafficAnalyticsResponse, error) {
	step := stepForRange(req.To.Sub(req.From))
	lookback, baselineSource := analyticsBaselineWindow(req.To.Sub(req.From))
	baselineFrom := req.From.Add(-lookback)
	legacyFrom := baselineFrom
	if req.CompareBaseline {
		candidate := req.From.Add(-time.Duration(req.BaselineDays) * 24 * time.Hour)
		if candidate.Before(legacyFrom) {
			legacyFrom = candidate
		}
	}

	// Scope resolution is metadata work over the current inventory. Keep it under
	// a short independent deadline so a metadata problem cannot occupy the full
	// analytics execution budget.
	scopeCtx, scopeCancel := context.WithTimeout(ctx, 5*time.Second)
	defer scopeCancel()
	if err := r.resolveAnalyticsInventoryScopes(scopeCtx, &req); err != nil {
		return TrafficAnalyticsResponse{}, err
	}
	if analyticsScopeResolvedEmpty(req.Left) || analyticsScopeResolvedEmpty(req.Right) {
		return emptyTrafficAnalyticsResponse(req, step), nil
	}
	if err := r.populateAnalyticsScopeLegacyAliases(scopeCtx, &req.Left, req.SensorID, legacyFrom, req.To); err != nil {
		return TrafficAnalyticsResponse{}, err
	}
	if err := r.populateAnalyticsScopeLegacyAliases(scopeCtx, &req.Right, req.SensorID, legacyFrom, req.To); err != nil {
		return TrafficAnalyticsResponse{}, err
	}
	if err := r.populateAnalyticsLegacyAliases(scopeCtx, &req.Left, req.SensorID, legacyFrom, req.To); err != nil {
		return TrafficAnalyticsResponse{}, err
	}
	if err := r.populateAnalyticsLegacyAliases(scopeCtx, &req.Right, req.SensorID, legacyFrom, req.To); err != nil {
		return TrafficAnalyticsResponse{}, err
	}

	// The current window is the product-critical result. Give it its own budget;
	// historical baseline work below is best-effort and can no longer make a
	// perfectly valid current graph fail.
	currentCtx, currentCancel := context.WithTimeout(ctx, 25*time.Second)
	defer currentCancel()
	bundle, err := queryAnalyticsBundle(currentCtx, r, req, req.From, req.To, step)
	if err != nil {
		return TrafficAnalyticsResponse{}, err
	}
	if bundle.Summary.TotalBytes == 0 && len(bundle.Series) == 0 {
		out := emptyTrafficAnalyticsResponse(req, step)
		out.Summary = bundle.Summary
		out.TopProtocols, out.TopPorts, out.TopPeers = bundle.TopProtocols, bundle.TopPorts, bundle.TopPeers
		if req.CompareBaseline {
			out.BaselineComparison = &TrafficBaselineComparison{Enabled: true, Available: false, Maturity: "Learning", LookbackDays: req.BaselineDays, Message: "No traffic exists in the selected window."}
		}
		return out, nil
	}
	// Analytics graphs are true time series: explicitly insert zero buckets so
	// quiet intervals keep their temporal width instead of being visually
	// compressed between two active buckets.
	bundle.Series = fillTrafficSeries(bundle.Series, req.From, req.To, step)

	// Always have a usable lightweight baseline from the visible series. A deeper
	// schedule-aware comparison is opt-in because it intentionally scans a longer
	// asset history window.
	baseline, anomalies := buildBaseline(bundle.Series, nil, "current_window")
	warning := ""
	var comparison *TrafficBaselineComparison

	if req.CompareBaseline {
		historyFrom := req.From.Add(-time.Duration(req.BaselineDays) * 24 * time.Hour)
		historyStep := step
		if historyStep < 300 {
			historyStep = 300
		}
		historyReq := req
		historyReq.CompareBaseline = false
		historyReq.BreakdownLimit = 4096
		historyReq.SkipPorts = true
		historyCtx, historyCancel := context.WithTimeout(ctx, 15*time.Second)
		historyBundle, historyErr := queryAnalyticsBundle(historyCtx, r, historyReq, historyFrom, req.From, historyStep)
		historyCancel()
		if historyErr != nil {
			warning = "schedule-aware baseline unavailable; current-window baseline used"
			comparison = &TrafficBaselineComparison{Enabled: true, Available: false, Maturity: "Learning", LookbackDays: req.BaselineDays, Message: "Historical baseline query did not complete in time."}
		} else if len(historyBundle.Series) == 0 && historyBundle.Summary.TotalBytes == 0 {
			warning = "baseline is still learning; no historical traffic is available"
			comparison = &TrafficBaselineComparison{Enabled: true, Available: false, Maturity: "Learning", LookbackDays: req.BaselineDays, Message: "No historical traffic is available before the selected window."}
		} else {
			rawHistory := append([]TrafficSeriesPoint(nil), historyBundle.Series...)
			fillStart := historyFrom
			if len(rawHistory) > 0 && rawHistory[0].Time.After(fillStart) {
				fillStart = rawHistory[0].Time
			}
			filledHistory := fillTrafficSeries(rawHistory, fillStart, req.From, historyStep)
			scaledHistory := scaleTrafficSeries(filledHistory, step, historyStep)
			baseline, _ = buildBaseline(bundle.Series, scaledHistory, fmt.Sprintf("previous_%d_days", req.BaselineDays))
			cmp, scheduleAnomalies := buildTrafficBaselineComparison(req, &bundle, rawHistory, filledHistory, historyBundle, step, historyStep)
			comparison = &cmp
			anomalies = scheduleAnomalies
			if cmp.CoverageCapped {
				warning = "baseline peer/service history reached the comparison coverage cap"
			}
		}
	} else {
		baselineCtx, baselineCancel := context.WithTimeout(ctx, 5*time.Second)
		baselineSeries, baselineErr := querySeries(baselineCtx, r, req, baselineFrom, req.From, step)
		baselineCancel()
		if baselineErr == nil {
			baselineSeries = fillTrafficSeries(baselineSeries, baselineFrom, req.From, step)
			baseline, anomalies = buildBaseline(bundle.Series, baselineSeries, baselineSource)
		} else {
			warning = "historical baseline unavailable; current-window baseline used"
		}
	}

	// buildBaseline mutates the visible series; the schedule-aware builder above
	// also marks its own deviations. Re-apply the final anomaly list so the graph
	// always matches the table returned in this response.
	for i := range bundle.Series {
		bundle.Series[i].Anomaly = false
		bundle.Series[i].Ratio = 0
	}
	for _, a := range anomalies {
		for i := range bundle.Series {
			if bundle.Series[i].Time.Equal(a.Time) {
				bundle.Series[i].Anomaly = true
				bundle.Series[i].Ratio = a.Ratio
				break
			}
		}
	}
	bundle.Summary.PeakBytesPerBucket = 0
	for _, p := range bundle.Series {
		if p.TotalBytes > bundle.Summary.PeakBytesPerBucket {
			bundle.Summary.PeakBytesPerBucket = p.TotalBytes
		}
	}
	bundle.Summary.PeakBitsPerSecond = float64(bundle.Summary.PeakBytesPerBucket*8) / float64(step)
	bundle.Summary.AnomalousIntervals = len(anomalies)
	return TrafficAnalyticsResponse{
		From: req.From, To: req.To, StepSeconds: step, Direction: req.Direction,
		LeftLabel: req.LeftLabel, RightLabel: req.RightLabel, Summary: bundle.Summary,
		Series: bundle.Series, TopProtocols: bundle.TopProtocols, TopPorts: bundle.TopPorts,
		TopPeers: bundle.TopPeers, Anomalies: anomalies, Baseline: baseline, BaselineComparison: comparison, Warning: warning,
	}, nil
}

func parseScope(c *gin.Context, prefix string) trafficScope {
	return trafficScope{Type: strings.TrimSpace(c.Query(prefix + "_type")), Value: strings.TrimSpace(c.Query(prefix + "_value"))}
}
func parseCommonAnalyticsRequest(c *gin.Context) (trafficAnalyticsRequest, error) {
	from, to, err := parseAnalyticsTime(c)
	if err != nil {
		return trafficAnalyticsRequest{}, err
	}
	port := 0
	if v := strings.TrimSpace(c.Query("port")); v != "" {
		port, err = strconv.Atoi(v)
		if err != nil || port < 0 || port > 65535 {
			return trafficAnalyticsRequest{}, fmt.Errorf("invalid port")
		}
	}
	direction := strings.ToLower(strings.TrimSpace(c.Query("direction")))
	if direction == "" {
		direction = "both"
	}
	if direction != "both" && direction != "out" && direction != "in" {
		return trafficAnalyticsRequest{}, fmt.Errorf("invalid direction")
	}
	compareBaseline := false
	switch strings.ToLower(strings.TrimSpace(c.Query("compare_baseline"))) {
	case "1", "true", "yes", "on":
		compareBaseline = true
	}
	baselineDays := 30
	if v := strings.TrimSpace(c.Query("baseline_days")); v != "" {
		baselineDays, err = strconv.Atoi(v)
		if err != nil || baselineDays < 7 || baselineDays > 60 {
			return trafficAnalyticsRequest{}, fmt.Errorf("baseline_days must be between 7 and 60")
		}
	}
	tzOffsetMinutes := 0
	if v := strings.TrimSpace(c.Query("tz_offset_minutes")); v != "" {
		tzOffsetMinutes, err = strconv.Atoi(v)
		if err != nil || tzOffsetMinutes < -840 || tzOffsetMinutes > 840 {
			return trafficAnalyticsRequest{}, fmt.Errorf("invalid timezone offset")
		}
	}
	return trafficAnalyticsRequest{From: from, To: to, SensorID: strings.TrimSpace(c.Query("sensor_id")), Protocol: strings.TrimSpace(c.Query("protocol")), Port: port, Direction: direction, CompareBaseline: compareBaseline, BaselineDays: baselineDays, TZOffsetMinutes: tzOffsetMinutes}, nil
}

func (s *Server) analyticsOptions(c *gin.Context) {
	out, err := s.Repo.TrafficAnalyticsOptions(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}
func (s *Server) communicationAnalytics(c *gin.Context) {
	req, err := parseCommonAnalyticsRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Left = trafficScope{Type: "asset", Value: c.Query("asset_a")}
	req.Right = trafficScope{Type: "asset", Value: c.Query("asset_b")}
	if req.Left.Value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_a is required"})
		return
	}
	req.LeftLabel = c.Query("asset_a_label")
	req.RightLabel = c.Query("asset_b_label")
	if req.Right.Value == "" {
		req.Right = trafficScope{Type: "any"}
		req.RightLabel = "Any peer"
	}
	out, err := s.Repo.RunTrafficAnalytics(c.Request.Context(), req)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}
func (s *Server) assetTrafficAnalytics(c *gin.Context) {
	req, err := parseCommonAnalyticsRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Left = trafficScope{Type: "asset", Value: c.Query("asset")}
	req.Right = trafficScope{Type: "any"}
	if req.Left.Value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset is required"})
		return
	}
	req.LeftLabel = c.Query("asset_label")
	req.RightLabel = "Peers"
	out, err := s.Repo.RunTrafficAnalytics(c.Request.Context(), req)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}
func validateAnalyticsScope(scope trafficScope) error {
	t := strings.ToLower(strings.TrimSpace(scope.Type))
	if t == "" || t == "any" {
		return nil
	}
	if !analyticsInventoryScope(t) && t != "asset" {
		return fmt.Errorf("invalid scope type %q", scope.Type)
	}
	// An empty value is the UI's "Any" placeholder even when a scope type has
	// already been selected. Keep it as an unrestricted side instead of turning a
	// harmless dropdown state into HTTP 400.
	return nil
}

func normalizeNetworkAnalyticsScope(scope trafficScope) trafficScope {
	if analyticsInventoryScope(scope.Type) && strings.TrimSpace(scope.Value) == "" {
		return trafficScope{Type: "any"}
	}
	if strings.TrimSpace(scope.Type) == "" {
		scope.Type = "any"
	}
	return scope
}

func (s *Server) networkTrafficAnalytics(c *gin.Context) {
	req, err := parseCommonAnalyticsRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Left = normalizeNetworkAnalyticsScope(parseScope(c, "left"))
	req.Right = normalizeNetworkAnalyticsScope(parseScope(c, "right"))
	if err := validateAnalyticsScope(req.Left); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateAnalyticsScope(req.Right); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Left.Type == "" {
		req.Left.Type = "any"
	}
	if req.Right.Type == "" {
		req.Right.Type = "any"
	}
	req.LeftLabel = c.Query("left_label")
	req.RightLabel = c.Query("right_label")
	out, err := s.Repo.RunTrafficAnalytics(c.Request.Context(), req)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}
func (s *Server) protocolTrafficAnalytics(c *gin.Context) {
	req, err := parseCommonAnalyticsRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Protocol == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "protocol is required"})
		return
	}
	category := strings.TrimSpace(c.Query("category"))
	if category != "" {
		req.Left = trafficScope{Type: "category", Value: category}
		req.LeftLabel = category
	} else {
		req.Left = trafficScope{Type: "any"}
		req.LeftLabel = "All assets"
	}
	req.Right = trafficScope{Type: "any"}
	req.RightLabel = "All peers"
	out, err := s.Repo.RunTrafficAnalytics(c.Request.Context(), req)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}
