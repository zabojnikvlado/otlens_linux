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

func TestAnalyticsBundleUsesSingleGroupingSetsAggregation(t *testing.T) {
	now := time.Now()
	req := trafficAnalyticsRequest{
		From: now.Add(-6 * time.Hour), To: now,
		Left:  trafficScope{Type: "any"},
		Right: trafficScope{Type: "category", Value: "IT", Resolved: true, ResolvedIdentities: []string{"mac:aa:bb:cc:dd:ee:01"}},
	}
	q, _, _, _, _, err := buildAnalyticsQuery(req, req.From, req.To, 60, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, "GROUPING SETS") {
		t.Fatal("bundle query must aggregate the selected rows in one grouping-sets pass")
	}
	if strings.Contains(q, "protocol_agg AS") || strings.Contains(q, "peer_agg AS") {
		t.Fatal("bundle query must not rescan the selected working set for each breakdown")
	}
}

func TestResolvedEmptyInventoryScopeCanShortCircuit(t *testing.T) {
	s := trafficScope{Type: "category", Value: "Unused category", Resolved: true}
	if !analyticsScopeResolvedEmpty(s) {
		t.Fatal("resolved inventory scope with no identities should short-circuit to an empty response")
	}
	if analyticsScopeResolvedEmpty(trafficScope{Type: "category", Value: "", Resolved: true}) {
		t.Fatal("empty scope value represents Any and must not short-circuit")
	}
}

func TestAnyAnyAnalyticsUsesLightweightFlowPath(t *testing.T) {
	now := time.Now()
	req := trafficAnalyticsRequest{From: now.Add(-6 * time.Hour), To: now, Left: trafficScope{Type: "any"}, Right: trafficScope{Type: "any"}}
	q, _, _, _, _, err := buildAnalyticsQuery(req, req.From, req.To, 60, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(q, "current_identity AS") || strings.Contains(q, "LEFT JOIN asset_overrides") {
		t.Fatal("Any↔Any analytics should not join topology/asset overrides")
	}
	if !strings.Contains(q, "FROM flow_observations f") || !strings.Contains(q, "GROUPING SETS") {
		t.Fatal("Any↔Any analytics should remain a bounded flow aggregation")
	}
}

func TestNetworkScopeTypeWithAnyValueNormalizesToAny(t *testing.T) {
	for _, typ := range []string{"vlan", "zone", "purdue", "category"} {
		got := normalizeNetworkAnalyticsScope(trafficScope{Type: typ, Value: ""})
		if got.Type != "any" || got.Value != "" {
			t.Fatalf("%s/Any normalized to %#v, want unrestricted Any", typ, got)
		}
	}
}

func TestFillTrafficSeriesPreservesQuietIntervals(t *testing.T) {
	from := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	to := from.Add(5 * time.Minute)
	series := []TrafficSeriesPoint{{Time: from.Add(2 * time.Minute), TotalBytes: 123, OutBytes: 123}}
	got := fillTrafficSeries(series, from, to, 60)
	if len(got) != 5 {
		t.Fatalf("got %d buckets, want 5", len(got))
	}
	if got[2].TotalBytes != 123 || got[0].TotalBytes != 0 || got[4].TotalBytes != 0 {
		t.Fatalf("unexpected filled series: %#v", got)
	}
}

func TestScheduleAwareBaselineUsesTimeOfDayHistory(t *testing.T) {
	locOffset := -120                                            // browser in UTC+2 reports -120 minutes
	currentStart := time.Date(2026, 8, 13, 8, 0, 0, 0, time.UTC) // 10:00 local
	current := []TrafficSeriesPoint{{Time: currentStart, TotalBytes: 20 * 1024 * 1024, OutBytes: 20 * 1024 * 1024}}
	history := []TrafficSeriesPoint{}
	for d := 1; d <= 14; d++ {
		tm := currentStart.Add(-time.Duration(d) * 24 * time.Hour)
		history = append(history, TrafficSeriesPoint{Time: tm, TotalBytes: 2 * 1024 * 1024, OutBytes: 2 * 1024 * 1024})
	}
	expected, _ := scheduleAwareExpectedSeries(current, history, 300, 300, locOffset)
	if len(expected) != 1 || expected[0].Samples < 4 {
		t.Fatalf("unexpected expected series: %#v", expected)
	}
	if expected[0].MedianBytes != 2*1024*1024 {
		t.Fatalf("median=%d, want %d", expected[0].MedianBytes, 2*1024*1024)
	}
}

func TestHistoricalBaselineBundleCanSkipPortBreakdown(t *testing.T) {
	now := time.Now()
	req := trafficAnalyticsRequest{
		From: now.Add(-24 * time.Hour), To: now,
		Left: trafficScope{Type: "asset", Value: "mac:aa:bb:cc:dd:ee:ff"}, Right: trafficScope{Type: "any"},
		BreakdownLimit: 4096, SkipPorts: true,
	}
	q, _, _, _, _, err := buildAnalyticsQuery(req, req.From, req.To, 300, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(q, "GROUPING SETS ((bucket),(service_name),(port_name)") {
		t.Fatal("baseline history bundle should skip the high-cardinality port breakdown")
	}
	if !strings.Contains(q, "rn<=4096") {
		t.Fatal("baseline history bundle should widen peer/service coverage")
	}
}
