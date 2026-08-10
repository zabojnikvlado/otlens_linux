package central

import (
	"context"
	"database/sql"
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
	availability := 100
	if d.TotalSensors > 0 {
		availability = ((d.TotalSensors - len(d.OfflineSensors)) * 100) / d.TotalSensors
	}
	severityTotal := 0
	for _, n := range d.AlertsBySeverity {
		severityTotal += n
	}

	sb.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
*{box-sizing:border-box}body{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;background:#eef2f6;color:#172033;margin:0;padding:32px 16px;line-height:1.45}
.report{background:#fff;max-width:900px;margin:0 auto;border:1px solid #dce3eb;border-radius:14px;overflow:hidden;box-shadow:0 16px 40px rgba(15,23,42,.08)}
.hero{background:linear-gradient(135deg,#0f2942,#174f73);color:#fff;padding:30px 36px}.brand{font-size:12px;letter-spacing:.16em;text-transform:uppercase;opacity:.78}.hero h1{font-size:28px;line-height:1.2;margin:8px 0 6px}.period{font-size:14px;opacity:.82}.content{padding:30px 36px 38px}
.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:28px}.kpi{border:1px solid #dce3eb;border-radius:10px;padding:16px;background:#f8fafc}.kpi b{display:block;font-size:27px;line-height:1;color:#0f2942}.kpi span{display:block;font-size:12px;color:#64748b;margin-top:8px}.kpi small{display:block;font-size:11px;color:#94a3b8;margin-top:3px}
section{margin-top:28px}h2{font-size:16px;color:#0f2942;margin:0 0 12px;padding-bottom:9px;border-bottom:2px solid #dbe8f1}.section-note{font-size:12px;color:#64748b;margin:-6px 0 12px}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;border:1px solid #dce3eb;border-radius:9px;overflow:hidden}th{background:#f1f5f9;color:#475569;font-size:11px;text-transform:uppercase;letter-spacing:.05em}td,th{text-align:left;padding:10px 12px;border-bottom:1px solid #e8edf2}tr:last-child td{border-bottom:0}.number{text-align:right;font-variant-numeric:tabular-nums}.severity{display:inline-block;border-radius:999px;padding:3px 9px;font-size:11px;font-weight:700;text-transform:uppercase}.critical{background:#fee2e2;color:#991b1b}.high{background:#ffedd5;color:#9a3412}.medium{background:#fef3c7;color:#92400e}.low{background:#e0f2fe;color:#075985}
.health{display:flex;align-items:center;gap:16px;padding:15px 16px;border-radius:9px;background:#f8fafc;border:1px solid #dce3eb}.health-score{font-size:25px;font-weight:750;color:#0f2942}.muted{color:#64748b}.warning{color:#9a3412;font-weight:600}.empty{padding:16px;border:1px dashed #cbd5e1;border-radius:9px;color:#64748b;background:#f8fafc}.footer{border-top:1px solid #e5eaf0;padding:16px 36px;color:#64748b;font-size:11px;background:#f8fafc}
@media(max-width:700px){body{padding:0}.report{border-radius:0;border:0}.hero,.content{padding-left:20px;padding-right:20px}.summary{grid-template-columns:repeat(2,minmax(0,1fr))}}
@page{size:A4;margin:12mm}@media print{*{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}html,body{background:#fff!important;padding:0;margin:0}.report{box-shadow:none;border:0;border-radius:0;max-width:none;width:100%}.hero{padding:24px 28px}.content{padding:24px 28px 22px}.summary{gap:9px;margin-bottom:20px}.kpi{padding:12px}.kpi b{font-size:23px}section{break-inside:avoid;page-break-inside:avoid;margin-top:20px}tr,.health,.kpi{break-inside:avoid;page-break-inside:avoid}.footer{position:static;margin-top:18px;padding:12px 28px}table{font-size:11px}td,th{padding:7px 9px}}
</style></head><body><article class="report">`)
	sb.WriteString(fmt.Sprintf(`<header class="hero"><div class="brand">OTLens Security Operations</div><h1>Weekly security summary</h1><div class="period">%s - %s</div></header><main class="content">`,
		esc(d.PeriodStart.Format("Jan 2, 2006")), esc(d.PeriodEnd.Format("Jan 2, 2006"))))

	sb.WriteString(`<div class="summary">`)
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d</b><span>New assets</span><small>First observed this period</small></div>`, d.NewAssets))
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d</b><span>Open alerts</span><small>%d newly observed</small></div>`, d.OpenAlerts, d.NewAlertsThisPeriod))
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d</b><span>New connections</span><small>Topology growth</small></div>`, d.TopologyEdgeGrowth))
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d%%</b><span>Sensor availability</span><small>%d of %d online</small></div>`, availability, d.TotalSensors-len(d.OfflineSensors), d.TotalSensors))
	sb.WriteString(`</div>`)

	sb.WriteString(`<section><h2>Alert posture</h2>`)
	sb.WriteString(fmt.Sprintf(`<p class="section-note">%d open alerts grouped by severity.</p><table><thead><tr><th>Severity</th><th class="number">Open alerts</th><th class="number">Share</th></tr></thead><tbody>`, severityTotal))
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		n := d.AlertsBySeverity[sev]
		share := 0
		if severityTotal > 0 {
			share = n * 100 / severityTotal
		}
		sb.WriteString(fmt.Sprintf(`<tr><td><span class="severity %s">%s</span></td><td class="number">%d</td><td class="number muted">%d%%</td></tr>`, sev, esc(strings.ToUpper(sev)), n, share))
	}
	sb.WriteString(`</tbody></table></section>`)

	sb.WriteString(`<section><h2>Correlated incidents</h2><p class="section-note">Incidents with two or more related alert types on the same sensor and IP.</p>`)
	if len(d.NewIncidents) == 0 {
		sb.WriteString(`<div class="empty">No correlated incidents were identified in this reporting window.</div>`)
	} else {
		sb.WriteString(`<table><thead><tr><th>Sensor</th><th>IP address</th><th>Severity</th><th>Detection types</th></tr></thead><tbody>`)
		for _, inc := range d.NewIncidents {
			sev := strings.ToLower(inc.Severity)
			if sev == "" {
				sev = "low"
			}
			sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><span class="severity %s">%s</span></td><td>%s</td></tr>`,
				esc(inc.SensorID), esc(inc.IP), esc(sev), esc(strings.ToUpper(inc.Severity)), esc(strings.Join(inc.Types, ", "))))
		}
		sb.WriteString(`</tbody></table>`)
	}
	sb.WriteString(`</section>`)

	sb.WriteString(`<section><h2>Sensor health</h2>`)
	sb.WriteString(fmt.Sprintf(`<div class="health"><div class="health-score">%d%%</div><div><strong>%d of %d sensors online</strong><div class="muted">Availability at report generation time</div></div></div>`, availability, d.TotalSensors-len(d.OfflineSensors), d.TotalSensors))
	if len(d.OfflineSensors) > 0 {
		sb.WriteString(`<p class="warning">Offline sensors: ` + esc(strings.Join(d.OfflineSensors, ", ")) + `</p>`)
	}
	sb.WriteString(`</section></main>`)
	sb.WriteString(fmt.Sprintf(`<footer class="footer">Generated by OTLens on %s UTC. This report is intended for operational review and does not replace incident validation.</footer>`, time.Now().UTC().Format("Jan 2, 2006 15:04")))
	sb.WriteString(`</article></body></html>`)
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

// DeleteReport permanently removes one saved report.
func (r *Repository) DeleteReport(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM report_history WHERE id=$1`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
