package detect

import (
	"fmt"
	"strings"
	"time"
)

// AssetPolicyContext is the sensor-side copy of Central's operator-owned asset
// context. It is intentionally small and contains only fields useful to local
// detection; usernames/audit metadata stay in Central.
type AssetPolicyContext struct {
	IP          string
	Role        string
	Criticality string
	Zone        string
	PurdueLevel *float64
}

type ReportingPolicySnapshot struct {
	LastSeen   time.Time     `json:"last_seen"`
	LastGap    time.Duration `json:"last_gap"`
	TypicalGap time.Duration `json:"typical_gap"`
	Samples    int           `json:"samples"`
}

// PolicyLearningSnapshot persists security-policy relationships that are
// learned during commissioning. Without this snapshot a sensor restart after
// learning would forget every approved OT master/protocol and remote-management
// relationship and immediately produce false "first seen"/unauthorized hits.
type PolicyLearningSnapshot struct {
	TrustedOTAccess      map[string]map[string]bool `json:"trusted_ot_access,omitempty"`
	TrustedOTMasters     map[string]map[string]bool `json:"trusted_ot_masters,omitempty"`
	TrustedOTTimeSources map[string]map[string]bool `json:"trusted_ot_time_sources,omitempty"`
	TrustedOTProtocols   map[string]map[string]bool `json:"trusted_ot_protocols,omitempty"`
	TrustedRemoteMgmt    map[string]bool            `json:"trusted_remote_management,omitempty"`
	// OTAssets contains only protocol-inferred/learned identity. Central
	// operator context is delivered separately on every sync and must never be
	// folded into this persisted learning snapshot.
	OTAssets      map[string]bool                    `json:"ot_assets,omitempty"`
	HostnameByMAC map[string]string                  `json:"hostname_by_mac,omitempty"`
	Reporting     map[string]ReportingPolicySnapshot `json:"reporting,omitempty"`

	// Central-managed segmentation is persisted with the learned policy state
	// so a restarted sensor keeps the last authoritative VLAN/Purdue policy
	// during the short interval before its first successful Central sync.
	ManagedSegmentation bool               `json:"managed_segmentation,omitempty"`
	VLANLevels          map[uint16]float64 `json:"vlan_levels,omitempty"`
	MaxLevelJump        float64            `json:"max_level_jump,omitempty"`
}

type reportingState struct {
	LastSeen   time.Time
	LastGap    time.Duration
	TypicalGap time.Duration
	Samples    int
	AlertedAt  time.Time
}

type dnsTunnelSample struct {
	At         time.Time
	Name       string
	QueryType  uint16
	QueryBytes int
}

type dnsTunnelResponseSample struct {
	At    time.Time
	Bytes int
}

type dnsTunnelState struct {
	Samples   []dnsTunnelSample
	Responses []dnsTunnelResponseSample
}

type packetWindow struct {
	FirstSeen time.Time
	LastSeen  time.Time
	Bytes     uint64
}

// SetAssetPolicyContexts atomically replaces the Central-provided context
// snapshot. Learned protocol/master relationships remain intact; changing a
// role/zone is a policy update, not a learning reset.
func (e *Engine) SetAssetPolicyContexts(contexts []AssetPolicyContext) {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	next := make(map[string]AssetPolicyContext, len(contexts))
	for _, c := range contexts {
		c.IP = strings.TrimSpace(c.IP)
		if c.IP == "" {
			continue
		}
		c.Role = strings.ToLower(strings.TrimSpace(c.Role))
		c.Zone = strings.ToLower(strings.TrimSpace(c.Zone))
		next[c.IP] = c
	}

	// Keep operator-owned context separate from protocol-inferred learning.
	// Conflating the two makes a temporary Central override leak into the
	// persisted learning snapshot and survive after the override is removed or
	// the IP is later reused by another device. Effective OT classification is
	// resolved at read time by isOTAssetLocked.
	e.assetContexts = next
}

func isOTRole(role string) bool {
	role = strings.ToLower(role)
	return role == "ot" || role == "ot_asset" || strings.Contains(role, "ot asset") ||
		strings.Contains(role, "plc") || strings.Contains(role, "rtu") || strings.Contains(role, "controller") ||
		strings.Contains(role, "ied") || strings.Contains(role, "drive") || strings.Contains(role, "field") ||
		strings.Contains(role, "sensor") || strings.Contains(role, "actuator") || strings.Contains(role, "instrument") || strings.Contains(role, "valve") ||
		strings.Contains(role, "hmi") || strings.Contains(role, "scada") || strings.Contains(role, "historian") ||
		strings.Contains(role, "engineering") || strings.Contains(role, "operator") || strings.Contains(role, "safety")
}

func isControllerRole(role string) bool {
	role = strings.ToLower(role)
	return strings.Contains(role, "plc") || strings.Contains(role, "rtu") || strings.Contains(role, "controller") || strings.Contains(role, "ied") || strings.Contains(role, "drive")
}

func isEngineeringRole(role string) bool {
	role = strings.ToLower(role)
	return strings.Contains(role, "engineering") || strings.Contains(role, "programming") || strings.Contains(role, "maintenance")
}

func isControlMasterRole(role string) bool {
	role = strings.ToLower(role)
	return isEngineeringRole(role) || strings.Contains(role, "hmi") || strings.Contains(role, "scada") || strings.Contains(role, "operator") || strings.Contains(role, "master")
}

func isEnterpriseRole(role string) bool {
	role = strings.ToLower(role)
	return strings.Contains(role, "enterprise") || strings.Contains(role, "erp") || strings.Contains(role, "email") || strings.Contains(role, "domain") || strings.Contains(role, "user workstation") || strings.Contains(role, "office")
}

func (e *Engine) assetContext(ip string) (AssetPolicyContext, bool) {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	x, ok := e.assetContexts[ip]
	return x, ok
}

func (e *Engine) markOTAsset(ip string) {
	if ip == "" {
		return
	}
	e.policyMutex.Lock()
	e.otAssets[ip] = true
	e.policyMutex.Unlock()
}

func (e *Engine) isOTAssetLocked(ip string) bool {
	if ip == "" {
		return false
	}
	if c, ok := e.assetContexts[ip]; ok {
		// Explicit operator context is authoritative in both directions: an OT
		// role/Purdue level can promote a device, and an explicit enterprise
		// role can suppress stale protocol inference without deleting history.
		return isOTRole(c.Role) || (c.PurdueLevel != nil && *c.PurdueLevel <= 3)
	}
	return e.otAssets[ip]
}

func (e *Engine) isOTAsset(ip string) bool {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	return e.isOTAssetLocked(ip)
}

func (e *Engine) sourceExplicitlyApprovedForOT(src string) bool {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if c, ok := e.assetContexts[src]; ok {
		return isControlMasterRole(c.Role)
	}
	return false
}

func relationKey(src, dst string, port uint16) string {
	return fmt.Sprintf("%s|%s|%d", src, dst, port)
}

func otRelationshipKey(src, dst, protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol)) + "|" + src + "|" + dst
}

func policyRelationKey(src, dst string) string {
	return strings.TrimSpace(src) + "|" + strings.TrimSpace(dst)
}

// quarantinePolicyLearning prevents hard-security/policy traffic observed
// during commissioning from becoming a trusted access/master relationship. It
// also removes a relation that may already have been learned by another event
// subscriber before the security detector evaluated the same packet.
func (e *Engine) quarantinePolicyLearning(src, dst string, until time.Time) {
	if src == "" || dst == "" {
		return
	}
	if until.IsZero() {
		until = time.Now().Add(24 * time.Hour)
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if e.policyLearningQuarantine == nil {
		e.policyLearningQuarantine = make(map[string]time.Time)
	}
	key := policyRelationKey(src, dst)
	if existing := e.policyLearningQuarantine[key]; existing.Before(until) {
		e.policyLearningQuarantine[key] = until
	}
	if m := e.trustedOTAccess[dst]; m != nil {
		delete(m, src)
	}
	if m := e.trustedOTMasters[dst]; m != nil {
		delete(m, src)
	}
	if m := e.trustedOTTimeSources[dst]; m != nil {
		delete(m, src)
	}
	prefix := strings.TrimSpace(src) + "|" + strings.TrimSpace(dst) + "|"
	for relation := range e.trustedRemoteMgmt {
		if strings.HasPrefix(relation, prefix) {
			delete(e.trustedRemoteMgmt, relation)
		}
	}
}

func (e *Engine) policyLearningAllowedLocked(src, dst string, now time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	key := policyRelationKey(src, dst)
	until := e.policyLearningQuarantine[key]
	if until.IsZero() {
		return true
	}
	if now.After(until) {
		delete(e.policyLearningQuarantine, key)
		return true
	}
	return false
}

func (e *Engine) learnOTRelationship(src, dst, protocol string, servicePort uint16) {
	// Compatibility helper for restored/tests: an explicitly learned control
	// relationship means both access and command authority. Live learning uses
	// learnOTAccess for reads and learnOTMaster only for actual commands.
	e.learnOTAccess(src, dst)
	e.learnOTMaster(src, dst)
	e.learnOTProtocol(dst, protocol, servicePort)
}

func (e *Engine) learnOTAccess(src, dst string) {
	if src == "" || dst == "" {
		return
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if !e.policyLearningAllowedLocked(src, dst, time.Now()) {
		return
	}
	if e.trustedOTAccess[dst] == nil {
		e.trustedOTAccess[dst] = map[string]bool{}
	}
	e.trustedOTAccess[dst][src] = true
}

func (e *Engine) isTrustedOTAccess(src, dst string) bool {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if c, ok := e.assetContexts[src]; ok && isControlMasterRole(c.Role) {
		t, tok := e.assetContexts[dst]
		if !tok || c.Zone == "" || t.Zone == "" || c.Zone == t.Zone {
			return true
		}
	}
	return e.trustedOTAccess[dst] != nil && e.trustedOTAccess[dst][src]
}

func (e *Engine) approveOTAccessRelationship(src, dst, protocol string, servicePort uint16, commandAuthority bool) {
	if src == "" || dst == "" {
		return
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	delete(e.policyLearningQuarantine, policyRelationKey(src, dst))
	if e.trustedOTAccess[dst] == nil {
		e.trustedOTAccess[dst] = map[string]bool{}
	}
	e.trustedOTAccess[dst][src] = true
	if commandAuthority {
		if e.trustedOTMasters[dst] == nil {
			e.trustedOTMasters[dst] = map[string]bool{}
		}
		e.trustedOTMasters[dst][src] = true
	}
	if strings.TrimSpace(protocol) != "" && servicePort != 0 {
		if e.trustedOTProtocols[dst] == nil {
			e.trustedOTProtocols[dst] = map[string]bool{}
		}
		e.trustedOTProtocols[dst][fmt.Sprintf("%s/%d", strings.ToLower(strings.TrimSpace(protocol)), servicePort)] = true
	}
}

func (e *Engine) approveOTTimeSource(src, dst string) {
	if src == "" || dst == "" {
		return
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	delete(e.policyLearningQuarantine, policyRelationKey(src, dst))
	if e.trustedOTTimeSources[dst] == nil {
		e.trustedOTTimeSources[dst] = map[string]bool{}
	}
	e.trustedOTTimeSources[dst][src] = true
}

func (e *Engine) approveRemoteManagement(src, dst string, port uint16) {
	if src == "" || dst == "" || port == 0 {
		return
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	delete(e.policyLearningQuarantine, policyRelationKey(src, dst))
	if e.trustedRemoteMgmt == nil {
		e.trustedRemoteMgmt = make(map[string]bool)
	}
	e.trustedRemoteMgmt[relationKey(src, dst, port)] = true
}

func (e *Engine) isTrustedOTMaster(src, dst string) bool {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if c, ok := e.assetContexts[src]; ok && isControlMasterRole(c.Role) {
		// Role alone is sufficient only when the target is in the same explicit
		// zone (or one side has no zone metadata); otherwise require a learned
		// relationship so an engineering station in Cell A is not automatically
		// trusted to control Cell B.
		t, tok := e.assetContexts[dst]
		if !tok || c.Zone == "" || t.Zone == "" || c.Zone == t.Zone {
			return true
		}
	}
	return e.trustedOTMasters[dst] != nil && e.trustedOTMasters[dst][src]
}

func (e *Engine) isExpectedOTProtocol(dst, protocol string, port uint16) bool {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	x := e.trustedOTProtocols[dst]
	if len(x) == 0 {
		// In monitoring, a known OT asset with no learned protocol relation is
		// deliberately treated as new/unknown rather than silently trusted.
		// Use the same effective operator+inferred classification as the rest of
		// the policy engine; direct access to e.otAssets would ignore an explicit
		// Central reclassification.
		return !e.isOTAssetLocked(dst)
	}
	return x[fmt.Sprintf("%s/%d", strings.ToLower(protocol), port)]
}

func (e *Engine) learnRemoteManagement(src, dst string, port uint16) {
	if src == "" || dst == "" || port == 0 {
		return
	}
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if !e.policyLearningAllowedLocked(src, dst, time.Now()) {
		return
	}
	if e.trustedRemoteMgmt == nil {
		e.trustedRemoteMgmt = make(map[string]bool)
	}
	e.trustedRemoteMgmt[relationKey(src, dst, port)] = true
}

func (e *Engine) isTrustedRemoteManagement(src, dst string, port uint16) bool {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if e.trustedRemoteMgmt[relationKey(src, dst, port)] {
		return true
	}
	c, cok := e.assetContexts[src]
	t, tok := e.assetContexts[dst]
	if cok && tok && isEngineeringRole(c.Role) && (c.Zone == "" || t.Zone == "" || c.Zone == t.Zone) {
		return true
	}
	return false
}

// PolicyLearningSnapshot returns a deep copy of restart-stable learned policy
// state. Short-lived rate windows (command bursts, GARP storms, DNS tunnel
// samples, DNP Select state) intentionally remain runtime-only.
func (e *Engine) PolicyLearningSnapshot() PolicyLearningSnapshot {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	out := PolicyLearningSnapshot{
		TrustedOTAccess:      make(map[string]map[string]bool, len(e.trustedOTAccess)),
		TrustedOTMasters:     make(map[string]map[string]bool, len(e.trustedOTMasters)),
		TrustedOTTimeSources: make(map[string]map[string]bool, len(e.trustedOTTimeSources)),
		TrustedOTProtocols:   make(map[string]map[string]bool, len(e.trustedOTProtocols)),
		TrustedRemoteMgmt:    make(map[string]bool, len(e.trustedRemoteMgmt)),
		OTAssets:             make(map[string]bool, len(e.otAssets)),
		HostnameByMAC:        make(map[string]string, len(e.hostnameByMAC)),
		Reporting:            make(map[string]ReportingPolicySnapshot, len(e.reporting)),
	}
	for dst, access := range e.trustedOTAccess {
		m := make(map[string]bool, len(access))
		for src, trusted := range access {
			m[src] = trusted
		}
		out.TrustedOTAccess[dst] = m
	}
	for dst, masters := range e.trustedOTMasters {
		m := make(map[string]bool, len(masters))
		for src, trusted := range masters {
			m[src] = trusted
		}
		out.TrustedOTMasters[dst] = m
	}
	for dst, sources := range e.trustedOTTimeSources {
		m := make(map[string]bool, len(sources))
		for src, trusted := range sources {
			m[src] = trusted
		}
		out.TrustedOTTimeSources[dst] = m
	}
	for dst, protocols := range e.trustedOTProtocols {
		m := make(map[string]bool, len(protocols))
		for protocol, trusted := range protocols {
			m[protocol] = trusted
		}
		out.TrustedOTProtocols[dst] = m
	}
	for k, v := range e.trustedRemoteMgmt {
		out.TrustedRemoteMgmt[k] = v
	}
	for k, v := range e.otAssets {
		out.OTAssets[k] = v
	}
	for k, v := range e.hostnameByMAC {
		out.HostnameByMAC[k] = v
	}
	for ip, st := range e.reporting {
		if st != nil {
			out.Reporting[ip] = ReportingPolicySnapshot{LastSeen: st.LastSeen, LastGap: st.LastGap, TypicalGap: st.TypicalGap, Samples: st.Samples}
		}
	}
	e.ipVLANMutex.RLock()
	out.ManagedSegmentation = e.segmentationManaged
	out.MaxLevelJump = e.maxLevelJump
	if e.segmentationManaged {
		out.VLANLevels = make(map[uint16]float64, len(e.vlanLevels))
		for vlan, level := range e.vlanLevels {
			out.VLANLevels[vlan] = level
		}
	}
	e.ipVLANMutex.RUnlock()
	return out
}

// RestorePolicyLearning rehydrates learned policy relationships from SQLite.
// It is intentionally tolerant of a zero/older snapshot so upgrades are safe.
func (e *Engine) RestorePolicyLearning(snapshot PolicyLearningSnapshot) {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	if snapshot.TrustedOTAccess != nil {
		e.trustedOTAccess = make(map[string]map[string]bool, len(snapshot.TrustedOTAccess))
		for dst, access := range snapshot.TrustedOTAccess {
			m := make(map[string]bool, len(access))
			for src, trusted := range access {
				m[src] = trusted
			}
			e.trustedOTAccess[dst] = m
		}
	}
	if snapshot.TrustedOTMasters != nil {
		e.trustedOTMasters = make(map[string]map[string]bool, len(snapshot.TrustedOTMasters))
		for dst, masters := range snapshot.TrustedOTMasters {
			m := make(map[string]bool, len(masters))
			for src, trusted := range masters {
				m[src] = trusted
			}
			e.trustedOTMasters[dst] = m
		}
	}
	// v13 snapshots predate TrustedOTAccess. A trusted command master is also
	// necessarily a trusted reader/access source, so use master relations as a
	// safe compatibility seed without granting the opposite direction.
	if snapshot.TrustedOTAccess == nil && snapshot.TrustedOTMasters != nil {
		e.trustedOTAccess = make(map[string]map[string]bool, len(snapshot.TrustedOTMasters))
		for dst, masters := range snapshot.TrustedOTMasters {
			m := make(map[string]bool, len(masters))
			for src, trusted := range masters {
				m[src] = trusted
			}
			e.trustedOTAccess[dst] = m
		}
	}
	if snapshot.TrustedOTTimeSources != nil {
		e.trustedOTTimeSources = make(map[string]map[string]bool, len(snapshot.TrustedOTTimeSources))
		for dst, sources := range snapshot.TrustedOTTimeSources {
			m := make(map[string]bool, len(sources))
			for src, trusted := range sources {
				m[src] = trusted
			}
			e.trustedOTTimeSources[dst] = m
		}
	}
	if snapshot.TrustedOTProtocols != nil {
		e.trustedOTProtocols = make(map[string]map[string]bool, len(snapshot.TrustedOTProtocols))
		for dst, protocols := range snapshot.TrustedOTProtocols {
			m := make(map[string]bool, len(protocols))
			for protocol, trusted := range protocols {
				m[protocol] = trusted
			}
			e.trustedOTProtocols[dst] = m
		}
	}
	if snapshot.TrustedRemoteMgmt != nil {
		e.trustedRemoteMgmt = make(map[string]bool, len(snapshot.TrustedRemoteMgmt))
		for k, v := range snapshot.TrustedRemoteMgmt {
			e.trustedRemoteMgmt[k] = v
		}
	}
	if snapshot.OTAssets != nil {
		e.otAssets = make(map[string]bool, len(snapshot.OTAssets))
		for k, v := range snapshot.OTAssets {
			e.otAssets[k] = v
		}
	}
	if snapshot.HostnameByMAC != nil {
		e.hostnameByMAC = make(map[string]string, len(snapshot.HostnameByMAC))
		for k, v := range snapshot.HostnameByMAC {
			e.hostnameByMAC[k] = v
		}
	}
	if snapshot.Reporting != nil {
		e.reporting = make(map[string]*reportingState, len(snapshot.Reporting))
		for ip, st := range snapshot.Reporting {
			e.reporting[ip] = &reportingState{LastSeen: st.LastSeen, LastGap: st.LastGap, TypicalGap: st.TypicalGap, Samples: st.Samples}
		}
	}
	if snapshot.ManagedSegmentation {
		levels := make(map[uint16]float64, len(snapshot.VLANLevels))
		for vlan, level := range snapshot.VLANLevels {
			if vlan > 4094 || !validSegmentationPurdueLevel(level) {
				continue
			}
			levels[vlan] = level
		}
		e.ipVLANMutex.Lock()
		e.vlanLevels = levels
		e.maxLevelJump = snapshot.MaxLevelJump
		if e.maxLevelJump <= 0 || e.maxLevelJump > 5 {
			e.maxLevelJump = 1
		}
		e.segmentationManaged = true
		e.segmentationEnabled = len(levels) > 0 || len(e.segmentationPolicy) > 0
		e.ipVLANMutex.Unlock()
	}
}

func (e *Engine) resetPolicyLearningState() {
	e.policyMutex.Lock()
	defer e.policyMutex.Unlock()
	e.trustedOTAccess = make(map[string]map[string]bool)
	e.trustedOTMasters = make(map[string]map[string]bool)
	e.trustedOTTimeSources = make(map[string]map[string]bool)
	e.trustedOTProtocols = make(map[string]map[string]bool)
	e.trustedRemoteMgmt = make(map[string]bool)
	e.policyLearningQuarantine = make(map[string]time.Time)
	e.engineeringTargets = make(map[string]map[string]time.Time)
	e.remoteTransfers = make(map[string]*packetWindow)
	e.ioBursts = make(map[string][]time.Time)
	e.dnpSelect = make(map[string]time.Time)
	e.icsErrors = make(map[string][]time.Time)
	e.reporting = make(map[string]*reportingState)
	e.hostnameByMAC = make(map[string]string)
	e.gratuitousARP = make(map[string][]time.Time)
	e.externalPeers = make(map[string]map[string]bool)
	e.externalFlows = make(map[string]externalFlowState)
	e.externalFlowLastSweep = time.Time{}
	e.dnsTunnel = make(map[string]*dnsTunnelState)
	e.lastPacketObserved = time.Time{}
	// Forget protocol-inferred OT identity so a learning reset rebuilds it
	// exclusively from live traffic. Central operator context is intentionally
	// kept separately and remains effective through isOTAssetLocked.
	e.otAssets = make(map[string]bool)
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
