package detect

import (
	"fmt"
	"testing"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	passivedns "github.com/zabojnikvlado/otlens_linux/internal/dns"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"go.uber.org/zap"
)

func newBuiltinTestEngine() *Engine {
	logger.Log = zap.NewNop()
	return NewEngine(time.Minute, 3, false, nil, 100, false, nil, 1, true, time.Minute, 15, 15, true, 6, .15, 5*time.Second, time.Hour, 5000)
}

func TestV14BuiltinCatalogContainsProtocolAwareRules(t *testing.T) {
	rules := builtinRules()
	ids := []string{
		"builtin.unauthorized_ot_command",
		"builtin.controller_program_change",
		"builtin.controller_mode_change",
		"builtin.unauthorized_ot_write",
		"builtin.new_engineering_workstation",
		"builtin.remote_management_into_ot",
		"builtin.smb_tool_transfer",
		"builtin.brute_force_io",
		"builtin.asset_identity_drift",
		"builtin.dns_tunneling",
		"builtin.unexpected_ot_protocol",
		"builtin.firmware_change",
		"builtin.unauthorized_time_change",
		"builtin.process_sequence_violation",
		"builtin.ot_reporting_loss",
		"builtin.malformed_ot_burst",
		// Previously documentation-only rules are executable in v14.
		"builtin.first_seen_remote_management",
		"builtin.direct_ot_protocol_access",
		"builtin.smb_into_ot",
		"builtin.unexpected_engineering_access",
		"builtin.large_controller_transfer",
		// Additional semantic split from the old catch-all critical rule.
		"builtin.controller_configuration_change",
	}
	for _, id := range ids {
		r := rules[id]
		if r == nil {
			t.Fatalf("missing built-in %s", id)
		}
		if r.Kind != RuleKindBuiltin || r.Detector == "" || r.Description == "" {
			t.Fatalf("incomplete product metadata for %s: %#v", id, r)
		}
	}
	for _, id := range []string{"builtin.first_seen_remote_management", "builtin.remote_management_into_ot", "builtin.direct_ot_protocol_access", "builtin.smb_into_ot", "builtin.unexpected_engineering_access", "builtin.large_controller_transfer"} {
		if !rules[id].Simulation {
			t.Fatalf("context-heavy upgrade rule %s must start in simulation", id)
		}
	}
}

func TestBuiltinPolicyOverrideAppliesWithoutReplacingDefinition(t *testing.T) {
	e := newBuiltinTestEngine()
	severity := "low"
	simulation := true
	schedule := "weekday@08:00-18:00"
	if err := e.ApplyRulePolicyPatch(RulePolicyPatch{ID: "builtin.unauthorized_ot_command", Severity: &severity, Simulation: &simulation, Schedule: &schedule}); err != nil {
		t.Fatal(err)
	}
	r := e.rules["builtin.unauthorized_ot_command"]
	if r.Severity != "low" || !r.Simulation || r.Schedule != schedule {
		t.Fatalf("policy patch not applied: %#v", r)
	}
	if r.Detector != "ics_policy" || r.AlertType != AlertUnauthorizedOTCommand {
		t.Fatalf("product definition was replaced: %#v", r)
	}
}

func TestARPConflictNeverAutoTrustsClaimant(t *testing.T) {
	e := newBuiltinTestEngine()
	now := time.Now()
	e.handleARP(core.Packet{L4Protocol: "ARP", ARPSrcIP: "10.0.0.1", ARPSrcMAC: "00:11:22:33:44:55", Timestamp: now})
	for i := 1; i <= 5; i++ {
		e.handleARP(core.Packet{L4Protocol: "ARP", ARPSrcIP: "10.0.0.1", ARPSrcMAC: "66:77:88:99:aa:bb", Timestamp: now.Add(time.Duration(i) * time.Second)})
	}
	if got := e.knownMAC["10.0.0.1"]; got != "00:11:22:33:44:55" {
		t.Fatalf("conflicting claimant was auto-trusted: %s", got)
	}
	id := "duplicate-ip|10.0.0.1|00:11:22:33:44:55|66:77:88:99:aa:bb"
	if e.alerts[id] == nil {
		t.Fatalf("persistent duplicate-IP alert not raised")
	}
	if !e.ApproveAlert(id) {
		t.Fatalf("failed to approve identity transition")
	}
	if got := e.knownMAC["10.0.0.1"]; got != "66:77:88:99:aa:bb" {
		t.Fatalf("approved claimant not promoted: %s", got)
	}
}

func TestExplicitSegmentationMatrixWorksWithoutVLANLevels(t *testing.T) {
	e := newBuiltinTestEngine()
	e.SetAssetPolicyContexts([]AssetPolicyContext{{IP: "10.0.0.10", Role: "enterprise workstation", Zone: "it"}, {IP: "10.0.1.20", Role: "plc", Zone: "cell-a"}})
	e.ConfigureSegmentationPolicy([]SegmentationPolicyRule{{SourceZone: "it", DestinationZone: "cell-a", Protocol: "any", Direction: "outbound", Allowed: false}})
	e.handleSegmentation(core.Packet{SrcIP: "10.0.0.10", DstIP: "10.0.1.20", L4Protocol: "TCP", DstPort: 502, Timestamp: time.Now()})
	if e.alerts["segmentation-zone|10.0.0.10|10.0.1.20|modbus"] == nil {
		t.Fatalf("explicit zone policy did not raise without VLAN level config")
	}
}

func TestDNSTunnelSignalsEntropyAndByteAsymmetry(t *testing.T) {
	e := newBuiltinTestEngine()
	now := time.Now()
	for i := 0; i < 30; i++ {
		label := fmt.Sprintf("a9f8e7d6c5b4a3%08x9e8d7c6b5a4f3e2d", i)
		e.handleDNSTunnel(passivedns.Observation{Timestamp: now.Add(time.Duration(i) * time.Second), ClientIP: "10.0.0.50", ServerIP: "8.8.8.8", QueryName: label + ".example.test", QueryType: 16, PayloadBytes: 180})
	}
	if e.alerts["dns-tunnel|10.0.0.50"] == nil {
		t.Fatalf("DNS tunnel detector did not raise on sustained high-entropy/TXT/asymmetric queries")
	}
}

func TestPolicyLearningSnapshotRestoresRelationships(t *testing.T) {
	e := newBuiltinTestEngine()
	e.learnOTRelationship("10.0.0.10", "10.0.0.20", "Modbus", 502)
	e.learnRemoteManagement("10.0.0.30", "10.0.0.20", 3389)
	e.policyMutex.Lock()
	e.hostnameByMAC["aa:bb:cc:dd:ee:ff"] = "plc-a"
	e.reporting["10.0.0.20"] = &reportingState{LastSeen: time.Now(), TypicalGap: time.Second, Samples: 50}
	e.policyMutex.Unlock()

	snap := e.PolicyLearningSnapshot()
	other := newBuiltinTestEngine()
	other.RestorePolicyLearning(snap)
	if !other.isTrustedOTMaster("10.0.0.10", "10.0.0.20") || !other.isExpectedOTProtocol("10.0.0.20", "Modbus", 502) || !other.isTrustedRemoteManagement("10.0.0.30", "10.0.0.20", 3389) {
		t.Fatalf("restart-stable relationships were not restored")
	}
	if other.PolicyLearningSnapshot().HostnameByMAC["aa:bb:cc:dd:ee:ff"] != "plc-a" {
		t.Fatalf("identity baseline was not restored")
	}
}

func TestReadOnlyOTAccessDoesNotGrantCommandAuthority(t *testing.T) {
	e := newBuiltinTestEngine()
	e.learnOTAccess("10.0.0.10", "10.0.0.20")
	e.learnOTProtocolForRelation("10.0.0.10", "10.0.0.20", "Modbus", 502)
	if !e.isTrustedOTAccess("10.0.0.10", "10.0.0.20") {
		t.Fatal("read relationship was not learned as access")
	}
	if e.isTrustedOTMaster("10.0.0.10", "10.0.0.20") {
		t.Fatal("read-only access incorrectly granted OT command authority")
	}
}

func TestQuarantinePreventsRelationshipRelearningUntilApproval(t *testing.T) {
	e := newBuiltinTestEngine()
	src, dst := "10.0.0.10", "10.0.0.20"
	e.learnOTRelationship(src, dst, "Modbus", 502)
	if !e.isTrustedOTMaster(src, dst) {
		t.Fatal("fixture did not learn command authority")
	}
	e.quarantinePolicyLearning(src, dst, time.Now().Add(time.Hour))
	if e.isTrustedOTMaster(src, dst) || e.isTrustedOTAccess(src, dst) {
		t.Fatal("quarantine did not revoke learned relationship")
	}
	e.learnOTAccess(src, dst)
	e.learnOTMaster(src, dst)
	if e.isTrustedOTMaster(src, dst) || e.isTrustedOTAccess(src, dst) {
		t.Fatal("quarantined relationship was silently relearned")
	}
	e.approveOTAccessRelationship(src, dst, "Modbus", 502, true)
	if !e.isTrustedOTMaster(src, dst) || !e.isTrustedOTAccess(src, dst) {
		t.Fatal("explicit analyst approval did not promote relationship")
	}
}

func TestExplicitNonOTContextOverridesStaleProtocolInference(t *testing.T) {
	e := newBuiltinTestEngine()
	e.markOTAsset("10.0.0.20")
	if !e.isOTAsset("10.0.0.20") {
		t.Fatal("fixture did not infer OT asset")
	}
	e.SetAssetPolicyContexts([]AssetPolicyContext{{IP: "10.0.0.20", Role: "enterprise workstation", Zone: "it"}})
	if e.isOTAsset("10.0.0.20") {
		t.Fatal("explicit non-OT operator context did not override stale inferred OT identity")
	}
}

func TestBuiltInParameterAndSeverityPolicyAreOperatorOverrides(t *testing.T) {
	e := newBuiltinTestEngine()
	params := map[string]float64{"commands_threshold": 7, "window_seconds": 3}
	sev := "low"
	if err := e.ApplyRulePolicyPatch(RulePolicyPatch{ID: "builtin.brute_force_io", Severity: &sev, Parameters: &params}); err != nil {
		t.Fatal(err)
	}
	r := e.rules["builtin.brute_force_io"]
	if !r.SeverityOverride || r.Severity != "low" || r.Parameters["commands_threshold"] != 7 || r.Parameters["window_seconds"] != 3 {
		t.Fatalf("operator policy not retained: %#v", r)
	}
	reset := false
	if err := e.ApplyRulePolicyPatch(RulePolicyPatch{ID: "builtin.brute_force_io", SeverityOverride: &reset}); err != nil {
		t.Fatal(err)
	}
	if e.rules["builtin.brute_force_io"].SeverityOverride || e.rules["builtin.brute_force_io"].Severity != "high" {
		t.Fatalf("severity reset did not restore product default: %#v", e.rules["builtin.brute_force_io"])
	}
}
