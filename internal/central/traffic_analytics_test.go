package central

import (
	"strings"
	"testing"
	"time"
)

func TestStepForRange(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want int
	}{
		{time.Hour, 60},
		{6 * time.Hour, 60},
		{12 * time.Hour, 300},
		{3 * 24 * time.Hour, 900},
		{14 * 24 * time.Hour, 3600},
		{60 * 24 * time.Hour, 21600},
	}
	for _, tc := range cases {
		if got := stepForRange(tc.d); got != tc.want {
			t.Fatalf("stepForRange(%s)=%d, want %d", tc.d, got, tc.want)
		}
	}
}

func TestBuildBaselineFlagsLargeVolumeSpike(t *testing.T) {
	baseline := make([]TrafficSeriesPoint, 30)
	for i := range baseline {
		baseline[i].TotalBytes = 2 * 1024 * 1024
	}
	series := []TrafficSeriesPoint{{TotalBytes: 2 * 1024 * 1024}, {TotalBytes: 20 * 1024 * 1024}}
	b, anomalies := buildBaseline(series, baseline)
	if b.Source != "previous_30_days" {
		t.Fatalf("baseline source=%q", b.Source)
	}
	if len(anomalies) != 1 || !series[1].Anomaly {
		t.Fatalf("expected one spike anomaly, got %#v", anomalies)
	}
	if series[0].Anomaly {
		t.Fatal("normal bucket marked anomalous")
	}
}

func TestBuildBaselineSparseMedianDoesNotCreateMeaninglessRatio(t *testing.T) {
	baseline := make([]TrafficSeriesPoint, 30)
	series := []TrafficSeriesPoint{{TotalBytes: 4 * 1024 * 1024}}
	_, anomalies := buildBaseline(series, baseline)
	if len(anomalies) != 1 {
		t.Fatalf("expected sparse spike to cross 1 MiB floor, got %d anomalies", len(anomalies))
	}
	if anomalies[0].Ratio <= 0 || anomalies[0].Ratio > 100 {
		t.Fatalf("unexpected sparse-baseline ratio %.2f", anomalies[0].Ratio)
	}
}

func TestAnalyticsBaselineWindowIsBoundedForInteractiveRanges(t *testing.T) {
	if d, source := analyticsBaselineWindow(24 * time.Hour); d != 3*24*time.Hour || source != "previous_3_days" {
		t.Fatalf("24h baseline=(%s,%q), want 72h previous_3_days", d, source)
	}
}

func TestAnalyticsKnownServiceUsesPortPredicate(t *testing.T) {
	req := trafficAnalyticsRequest{From: time.Now().Add(-time.Hour), To: time.Now(), Protocol: "SMB", Left: trafficScope{Type: "any"}, Right: trafficScope{Type: "any"}}
	q, _, _, _, _, err := buildAnalyticsQuery(req, req.From, req.To, 60, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(q, "LATERAL") {
		t.Fatal("interactive analytics query must not contain per-row LATERAL identity lookups")
	}
	if !strings.Contains(q, "selected AS MATERIALIZED") {
		t.Fatal("bundle query should materialize the filtered row set once")
	}
	if !strings.Contains(q, "src_port=ANY") {
		t.Fatal("known SMB filter should use indexed service ports")
	}
}

func TestNetworkScopeUsesResolvedEndpointIdentities(t *testing.T) {
	now := time.Now()
	req := trafficAnalyticsRequest{
		From: now.Add(-time.Hour), To: now,
		Left:  trafficScope{Type: "vlan", Value: "107", Resolved: true, ResolvedIdentities: []string{"mac:aa:bb:cc:dd:ee:01"}},
		Right: trafficScope{Type: "vlan", Value: "222", Resolved: true, ResolvedIdentities: []string{"mac:aa:bb:cc:dd:ee:02"}},
	}
	q, _, _, _, pair, err := buildAnalyticsQuery(req, req.From, req.To, 60, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pair, "_vlan") {
		t.Fatalf("network scope must not use the single packet VLAN as both endpoint VLANs: %s", pair)
	}
	if !strings.Contains(pair, "initiator_identity=ANY") || !strings.Contains(pair, "responder_identity=ANY") {
		t.Fatalf("network scope should be matched by endpoint stable identity: %s", pair)
	}
	if !strings.Contains(q, "f.src_identity=ANY") || !strings.Contains(q, "f.dst_identity=ANY") {
		t.Fatal("resolved network scopes should be pushed into the raw flow scan")
	}
	if strings.Contains(q, "initiator_category") || strings.Contains(q, "initiator_zone") || strings.Contains(q, "initiator_purdue") {
		t.Fatal("hot analytics query should not classify every flow row after scope resolution")
	}
}

func TestAnalyticsInventoryScopeMatching(t *testing.T) {
	p := 3.5
	a := TrafficAnalyticsAsset{Category: "Engineering Workstation", Zone: "DMZ", VLANID: 222, PurdueLevel: &p}
	cases := []trafficScope{
		{Type: "category", Value: "engineering workstation"},
		{Type: "zone", Value: "dmz"},
		{Type: "vlan", Value: "222"},
		{Type: "purdue", Value: "3.5"},
	}
	for _, scope := range cases {
		if !analyticsScopeMatchesAsset(scope, a) {
			t.Fatalf("scope %#v should match asset %#v", scope, a)
		}
	}
}

func TestNetworkScopeEmptyValueRemainsAny(t *testing.T) {
	if err := validateAnalyticsScope(trafficScope{Type: "vlan", Value: ""}); err != nil {
		t.Fatalf("empty dropdown value should mean Any, got %v", err)
	}
}

func TestNetworkRightOnlyPeerPointsOutsideSelectedScope(t *testing.T) {
	now := time.Now()
	req := trafficAnalyticsRequest{
		From: now.Add(-time.Hour), To: now,
		Left:  trafficScope{Type: "any"},
		Right: trafficScope{Type: "zone", Value: "Server", Resolved: true, ResolvedIdentities: []string{"mac:aa:bb:cc:dd:ee:02"}},
	}
	q, _, _, _, _, err := buildAnalyticsQuery(req, req.From, req.To, 60, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, "CASE WHEN (") || !strings.Contains(q, "THEN responder_name WHEN (") || !strings.Contains(q, "THEN initiator_name") {
		t.Fatal("right-only scope should report the opposite endpoint as peer")
	}
}
