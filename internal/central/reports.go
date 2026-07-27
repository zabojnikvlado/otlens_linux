package central

import (
	"context"
	"fmt"
	"html"
	"log"
	"strings"
	"time"
)

// ReportsConfig mirrors config.CentralConfig.Reports — kept as its own
// type here for the same reason RetentionConfig/NotificationConfig are.
type ReportsConfig struct {
	Enabled    bool
	Schedule   string // "weekly" is the only supported value for now
	DayOfWeek  string
	HourUTC    int
	Recipients []string
}

// weekdayFromName parses "monday".."sunday" (case-insensitive), for
// ReportsConfig.DayOfWeek. Defaults to Monday on anything unrecognized
// rather than erroring — a scheduled job shouldn't get permanently
// stuck over one typo'd config value.
func weekdayFromName(name string) time.Weekday {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sunday":
		return time.Sunday
	case "monday":
		return time.Monday
	case "tuesday":
		return time.Tuesday
	case "wednesday":
		return time.Wednesday
	case "thursday":
		return time.Thursday
	case "friday":
		return time.Friday
	case "saturday":
		return time.Saturday
	default:
		return time.Monday
	}
}

// DueReportWindow reports whether now falls within the hour a weekly
// report is due (matching both the configured weekday and hour, UTC),
// and if so, the [periodStart, periodEnd) it should cover — the 7 days
// immediately before now. Checked on an hourly-or-finer ticker (see
// main.go), so "within the hour" is enough granularity to not miss or
// double-fire the schedule.
func DueReportWindow(cfg ReportsConfig, now time.Time) (start, end time.Time, due bool) {
	now = now.UTC()
	if now.Weekday() != weekdayFromName(cfg.DayOfWeek) || now.Hour() != cfg.HourUTC {
		return time.Time{}, time.Time{}, false
	}
	return now.AddDate(0, 0, -7), now, true
}

// GenerateAndDispatchReport runs the full pipeline: generate, save
// (always, regardless of what happens next), then email if recipients
// are configured. A failed email doesn't lose the report — it's
// already saved by that point, and the failure reason is saved
// alongside it so it's visible from the Reports tab.
func (s *Server) GenerateAndDispatchReport(ctx context.Context, periodStart, periodEnd time.Time) error {
	rep, err := s.Repo.GenerateReport(ctx, periodStart, periodEnd)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	rep.ID = fmt.Sprintf("report-%d", periodEnd.Unix())
	rep.Recipients = s.Reports.Recipients

	if len(s.Reports.Recipients) > 0 {
		subject := fmt.Sprintf("OTLens weekly summary — %s to %s",
			periodStart.Format("Jan 2"), periodEnd.Format("Jan 2, 2006"))
		if err := s.sendEmailHTML(subject, rep.HTML, s.Reports.Recipients); err != nil {
			rep.EmailError = err.Error()
			log.Printf("report: email send failed: %v", err)
		} else {
			rep.EmailSent = true
		}
	}

	if err := s.Repo.SaveReport(ctx, rep); err != nil {
		return fmt.Errorf("save: %w", err)
	}
	return nil
}

// Report is one generated summary — see GenerateReport.
type Report struct {
	ID          string
	PeriodStart time.Time
	PeriodEnd   time.Time
	HTML        string
	Recipients  []string
	EmailSent   bool
	EmailError  string
	GeneratedAt time.Time
}

// reportData is everything GenerateReport pulls together before
// rendering — kept separate from the HTML rendering step so the two
// can be tested/reasoned about independently.
type reportData struct {
	PeriodStart, PeriodEnd time.Time
	NewAssets              int
	OpenAlerts             int
	AlertsBySeverity       map[string]int
	NewAlertsThisPeriod    int
	NewIncidents           []Incident
	TopologyEdgeGrowth     int
	OfflineSensors         []string
	TotalSensors           int
}

// GenerateReport pulls together a summary for [periodStart, periodEnd)
// and renders it to HTML — see renderReportHTML. Does not send or save
// anything itself; see (s *Server).GenerateAndDispatchReport for the
// full pipeline (this function, then SaveReport, then optionally
// email).
func (r *Repository) GenerateReport(ctx context.Context, periodStart, periodEnd time.Time) (Report, error) {
	data := reportData{PeriodStart: periodStart, PeriodEnd: periodEnd, AlertsBySeverity: map[string]int{}}

	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT (sensor_id, mac)) FROM topology_nodes
		WHERE mac != '' AND first_seen >= $1 AND first_seen < $2`,
		periodStart, periodEnd).Scan(&data.NewAssets); err != nil {
		return Report{}, fmt.Errorf("new assets: %w", err)
	}

	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM alert_history WHERE status = 'new'`,
	).Scan(&data.OpenAlerts); err != nil {
		return Report{}, fmt.Errorf("open alerts: %w", err)
	}

	sevRows, err := r.db.QueryContext(ctx, `
		SELECT severity, COUNT(*) FROM alert_history WHERE status = 'new' GROUP BY severity`,
	)
	if err != nil {
		return Report{}, fmt.Errorf("alerts by severity: %w", err)
	}
	for sevRows.Next() {
		var sev string
		var n int
		if err := sevRows.Scan(&sev, &n); err != nil {
			sevRows.Close()
			return Report{}, err
		}
		data.AlertsBySeverity[sev] = n
	}
	sevRows.Close()

	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM alert_history WHERE first_seen >= $1 AND first_seen < $2`,
		periodStart, periodEnd).Scan(&data.NewAlertsThisPeriod); err != nil {
		return Report{}, fmt.Errorf("new alerts this period: %w", err)
	}

	incidents, err := r.ListIncidents(ctx, periodEnd.Sub(periodStart), 2)
	if err != nil {
		return Report{}, fmt.Errorf("incidents: %w", err)
	}
	data.NewIncidents = incidents

	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM topology_edges WHERE first_seen >= $1 AND first_seen < $2`,
		periodStart, periodEnd).Scan(&data.TopologyEdgeGrowth); err != nil {
		return Report{}, fmt.Errorf("topology growth: %w", err)
	}

	offlineRows, err := r.db.QueryContext(ctx, `SELECT id FROM sensors WHERE status = 'offline'`)
	if err != nil {
		return Report{}, fmt.Errorf("offline sensors: %w", err)
	}
	for offlineRows.Next() {
		var id string
		if err := offlineRows.Scan(&id); err != nil {
			offlineRows.Close()
			return Report{}, err
		}
		data.OfflineSensors = append(data.OfflineSensors, id)
	}
	offlineRows.Close()

	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensors`).Scan(&data.TotalSensors); err != nil {
		return Report{}, fmt.Errorf("total sensors: %w", err)
	}

	return Report{
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		HTML:        renderReportHTML(data),
		GeneratedAt: time.Now(),
	}, nil
}

// renderReportHTML formats reportData as a self-contained HTML document
// (inline styles, no external assets) — safe to email directly or open
// standalone from the Reports tab. All dynamic text is html.EscapeString'd;
// none of it is trusted input (sensor IDs, alert types), but a
// compromised/misbehaving sensor could still try to inject markup via a
// crafted hostname or similar, so this isn't skipped just because the
// values are "usually" safe.
func renderReportHTML(d reportData) string {
	esc := html.EscapeString
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><style>
body{font-family:-apple-system,Segoe UI,sans-serif;background:#f4f6f8;color:#1a2332;margin:0;padding:24px}
.card{background:#fff;border-radius:8px;padding:24px;max-width:640px;margin:0 auto}
h1{font-size:20px;margin:0 0 4px} .period{color:#64748b;font-size:13px;margin-bottom:20px}
h2{font-size:14px;color:#334155;border-bottom:1px solid #e2e8f0;padding-bottom:6px;margin-top:24px}
.kpi{display:inline-block;background:#f1f5f9;border-radius:6px;padding:10px 16px;margin:4px 8px 4px 0}
.kpi b{display:block;font-size:20px} .kpi span{font-size:12px;color:#64748b}
.warn{color:#b45309} .crit{color:#b91c1c} table{width:100%;border-collapse:collapse;font-size:13px}
td,th{text-align:left;padding:4px 8px;border-bottom:1px solid #eef1f4}
</style></head><body><div class="card">`)
	sb.WriteString(fmt.Sprintf(`<h1>OTLens weekly summary</h1><div class="period">%s &ndash; %s</div>`,
		esc(d.PeriodStart.Format("Jan 2, 2006")), esc(d.PeriodEnd.Format("Jan 2, 2006"))))

	sb.WriteString(`<h2>At a glance</h2>`)
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d</b><span>new assets</span></div>`, d.NewAssets))
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d</b><span>open alerts</span></div>`, d.OpenAlerts))
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d</b><span>new alerts this period</span></div>`, d.NewAlertsThisPeriod))
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d</b><span>new connections</span></div>`, d.TopologyEdgeGrowth))

	sb.WriteString(`<h2>Open alerts by severity</h2><table>`)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		n := d.AlertsBySeverity[sev]
		class := ""
		if sev == "critical" {
			class = "crit"
		} else if sev == "high" {
			class = "warn"
		}
		sb.WriteString(fmt.Sprintf(`<tr><td class="%s">%s</td><td>%d</td></tr>`, class, esc(strings.Title(sev)), n))
	}
	sb.WriteString(`</table>`)

	sb.WriteString(`<h2>Incidents (2+ related alert types, same sensor+IP)</h2>`)
	if len(d.NewIncidents) == 0 {
		sb.WriteString(`<p>None.</p>`)
	} else {
		sb.WriteString(`<table><tr><th>Sensor</th><th>IP</th><th>Severity</th><th>Types</th></tr>`)
		for _, inc := range d.NewIncidents {
			sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				esc(inc.SensorID), esc(inc.IP), esc(inc.Severity), esc(strings.Join(inc.Types, ", "))))
		}
		sb.WriteString(`</table>`)
	}

	sb.WriteString(`<h2>Sensors</h2>`)
	sb.WriteString(fmt.Sprintf(`<p>%d total, %d offline.</p>`, d.TotalSensors, len(d.OfflineSensors)))
	if len(d.OfflineSensors) > 0 {
		sb.WriteString(`<p class="warn">Offline: ` + esc(strings.Join(d.OfflineSensors, ", ")) + `</p>`)
	}

	sb.WriteString(`</div></body></html>`)
	return sb.String()
}

// SaveReport persists a generated report, and optionally the outcome
// of trying to email it (a failed send still gets saved — the report
// itself isn't lost just because delivery didn't work).
func (r *Repository) SaveReport(ctx context.Context, rep Report) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO report_history(id, period_start, period_end, html, recipients, email_sent, email_error, generated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		rep.ID, rep.PeriodStart, rep.PeriodEnd, rep.HTML, strings.Join(rep.Recipients, ","), rep.EmailSent, rep.EmailError, rep.GeneratedAt,
	)
	return err
}

// ListReports returns the most recently generated reports, newest
// first, without their (potentially large) HTML body — use GetReport
// for the full content of one specific report.
func (r *Repository) ListReports(ctx context.Context, limit int) ([]Report, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, period_start, period_end, recipients, email_sent, email_error, generated_at
		FROM report_history ORDER BY generated_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Report, 0)
	for rows.Next() {
		var rep Report
		var recipients string
		if err := rows.Scan(&rep.ID, &rep.PeriodStart, &rep.PeriodEnd, &recipients, &rep.EmailSent, &rep.EmailError, &rep.GeneratedAt); err != nil {
			return nil, err
		}
		if recipients != "" {
			rep.Recipients = strings.Split(recipients, ",")
		}
		out = append(out, rep)
	}
	return out, rows.Err()
}

// GetReport returns one report's full content, including its HTML body.
func (r *Repository) GetReport(ctx context.Context, id string) (Report, error) {
	var rep Report
	var recipients string
	err := r.db.QueryRowContext(ctx, `
		SELECT id, period_start, period_end, html, recipients, email_sent, email_error, generated_at
		FROM report_history WHERE id=$1`, id,
	).Scan(&rep.ID, &rep.PeriodStart, &rep.PeriodEnd, &rep.HTML, &recipients, &rep.EmailSent, &rep.EmailError, &rep.GeneratedAt)
	if err != nil {
		return Report{}, err
	}
	if recipients != "" {
		rep.Recipients = strings.Split(recipients, ",")
	}
	return rep, nil
}
