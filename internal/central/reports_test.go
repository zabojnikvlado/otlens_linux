package central

import (
	"strings"
	"testing"
	"time"
)

func TestDueReportWindowAnchorsToConfiguredHour(t *testing.T) {
	cfg := ReportsConfig{Enabled: true, Schedule: "weekly", DayOfWeek: "tuesday", HourUTC: 10}
	now := time.Date(2026, 8, 11, 10, 37, 42, 0, time.UTC) // Tuesday
	start, end, due := DueReportWindow(cfg, now)
	if !due {
		t.Fatal("expected report to be due")
	}
	wantEnd := time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC)
	if !end.Equal(wantEnd) {
		t.Fatalf("end=%s want %s", end, wantEnd)
	}
	if !start.Equal(wantEnd.AddDate(0, 0, -7)) {
		t.Fatalf("start=%s", start)
	}
}

func TestDueReportWindowRejectsInvalidSchedule(t *testing.T) {
	for _, cfg := range []ReportsConfig{
		{Enabled: false, Schedule: "weekly", DayOfWeek: "tuesday", HourUTC: 10},
		{Enabled: true, Schedule: "daily", DayOfWeek: "tuesday", HourUTC: 10},
		{Enabled: true, Schedule: "weekly", DayOfWeek: "tueday", HourUTC: 10},
		{Enabled: true, Schedule: "weekly", DayOfWeek: "tuesday", HourUTC: 27},
	} {
		if _, _, due := DueReportWindow(cfg, time.Date(2026, 8, 11, 10, 10, 0, 0, time.UTC)); due {
			t.Fatalf("unexpected due for %#v", cfg)
		}
	}
}

func TestReportLabelsReviewStateSeparatelyFromActivity(t *testing.T) {
	html := renderReportHTML(reportData{
		PeriodStart:      time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC),
		PeriodEnd:        time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC),
		UnreviewedAlerts: 2200,
		ActiveAlerts:     238,
		AlertsBySeverity: map[string]int{"high": 2200},
	})
	for _, want := range []string{"Unreviewed alerts", "238 active in last 5m", "Managed incidents"} {
		if !strings.Contains(html, want) {
			t.Fatalf("report missing %q", want)
		}
	}
	if strings.Contains(html, ">Open alerts<") {
		t.Fatal("report still conflates unreviewed alerts with open/active alerts")
	}
}

func TestReportDeliveryBackoffIsBounded(t *testing.T) {
	if got := reportDeliveryBackoff(0); got != 15*time.Minute {
		t.Fatalf("first retry=%s", got)
	}
	if got := reportDeliveryBackoff(1000); got != 6*time.Hour {
		t.Fatalf("capped retry=%s", got)
	}
}

func TestReportHTMLBlocksExternalResources(t *testing.T) {
	html := renderReportHTML(reportData{AlertsBySeverity: map[string]int{}})
	if !strings.Contains(html, "Content-Security-Policy") || !strings.Contains(html, "default-src 'none'") {
		t.Fatal("report HTML is missing restrictive CSP")
	}
}
