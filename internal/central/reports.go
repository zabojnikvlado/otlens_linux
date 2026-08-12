package central

import (
	"context"
	"database/sql"
	"encoding/json"
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

// weekdayFromName parses "monday".."sunday" (case-insensitive). The bool is
// deliberately explicit: silently treating a typo as Monday can generate a
// report on the wrong day, which is worse than not generating one and logging
// the configuration error.
func weekdayFromName(name string) (time.Weekday, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sunday":
		return time.Sunday, true
	case "monday":
		return time.Monday, true
	case "tuesday":
		return time.Tuesday, true
	case "wednesday":
		return time.Wednesday, true
	case "thursday":
		return time.Thursday, true
	case "friday":
		return time.Friday, true
	case "saturday":
		return time.Saturday, true
	default:
		return time.Monday, false
	}
}

// DueReportWindow reports whether now falls within the hour a weekly
// report is due (matching both the configured weekday and hour, UTC), and if
// so, the exact anchored [periodStart, periodEnd) it should cover. Anchoring
// to HH:00:00 is important: otherwise a Central restart at 10:37 would shift
// every weekly report window by 37 minutes.
func DueReportWindow(cfg ReportsConfig, now time.Time) (start, end time.Time, due bool) {
	now = now.UTC()
	if !cfg.Enabled || !strings.EqualFold(strings.TrimSpace(cfg.Schedule), "weekly") || cfg.HourUTC < 0 || cfg.HourUTC > 23 {
		return time.Time{}, time.Time{}, false
	}
	weekday, ok := weekdayFromName(cfg.DayOfWeek)
	if !ok || now.Weekday() != weekday || now.Hour() != cfg.HourUTC {
		return time.Time{}, time.Time{}, false
	}
	end = time.Date(now.Year(), now.Month(), now.Day(), cfg.HourUTC, 0, 0, 0, time.UTC)
	return end.AddDate(0, 0, -7), end, true
}

// GenerateAndDispatchReport is idempotent for one reporting slot. The report
// is persisted before any email is attempted, so report content/window is
// durable before delivery begins. SMTP itself has no idempotency primitive:
// if the remote server accepts the message but persisting EmailSent fails,
// a later retry can still duplicate that message; this residual is surfaced
// in documentation rather than pretending SMTP provides exactly-once delivery.
func (s *Server) GenerateAndDispatchReport(ctx context.Context, periodStart, periodEnd time.Time) error {
	reportID := fmt.Sprintf("report-%d", periodEnd.UTC().UnixNano())
	rep, err := s.Repo.GetReport(ctx, reportID)
	if err != nil {
		if err != sql.ErrNoRows {
			return fmt.Errorf("load existing report: %w", err)
		}
		rep, err = s.Repo.GenerateReport(ctx, periodStart, periodEnd)
		if err != nil {
			return fmt.Errorf("generate: %w", err)
		}
		rep.ID = reportID
		rep.Recipients = append([]string(nil), s.Reports.Recipients...)
		if err := s.Repo.SaveReport(ctx, rep); err != nil {
			return fmt.Errorf("save before delivery: %w", err)
		}
	}
	return s.deliverSavedReport(ctx, rep)
}

func reportDeliveryBackoff(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	// 15m, 30m, 45m ... capped at six hours. Linear backoff avoids a
	// multi-day silent gap after a short SMTP outage while still preventing a
	// broken mail relay from being hammered every scheduler tick forever.
	d := 15 * time.Minute * time.Duration(attempts+1)
	if d > 6*time.Hour {
		d = 6 * time.Hour
	}
	return d
}

// deliverSavedReport retries only an already-persisted report. The report
// body/window never changes between attempts. A future NextEmailAttemptAt is
// respected so the scheduler can call this method frequently without turning
// a broken SMTP server into a tight retry loop.
func (s *Server) deliverSavedReport(ctx context.Context, rep Report) error {
	if rep.EmailSent || len(rep.Recipients) == 0 {
		return nil
	}
	now := time.Now().UTC()
	if rep.NextEmailAttemptAt != nil && rep.NextEmailAttemptAt.After(now) {
		return nil
	}
	subject := fmt.Sprintf("OTLens weekly summary — %s to %s",
		rep.PeriodStart.Format("Jan 2"), rep.PeriodEnd.Format("Jan 2, 2006"))
	sent := true
	deliveryErr := ""
	if err := s.sendEmailHTML(subject, rep.HTML, rep.Recipients); err != nil {
		sent = false
		deliveryErr = err.Error()
		log.Printf("report: email send failed id=%s attempt=%d: %v", rep.ID, rep.EmailAttempts+1, err)
	}
	retryAfter := time.Duration(0)
	if !sent {
		retryAfter = reportDeliveryBackoff(rep.EmailAttempts)
	}
	if err := s.Repo.UpdateReportDelivery(ctx, rep.ID, rep.Recipients, sent, deliveryErr, retryAfter); err != nil {
		return fmt.Errorf("persist delivery result: %w", err)
	}
	return nil
}

// RetryPendingReportDeliveries allows a transient SMTP outage to recover after
// the configured weekly generation hour has passed. Older code retried only
// while DueReportWindow was true, so an outage lasting that one hour left a
// saved report permanently unsent.
func (s *Server) RetryPendingReportDeliveries(ctx context.Context) error {
	reports, err := s.Repo.ListReportsPendingDelivery(ctx, 20)
	if err != nil {
		return err
	}
	for _, rep := range reports {
		if err := s.deliverSavedReport(ctx, rep); err != nil {
			return err
		}
	}
	return nil
}

// Report is one generated summary — see GenerateReport.
type Report struct {
	ID                 string
	PeriodStart        time.Time
	PeriodEnd          time.Time
	HTML               string
	Recipients         []string
	EmailSent          bool
	EmailError         string
	EmailAttempts      int
	LastEmailAttemptAt *time.Time
	NextEmailAttemptAt *time.Time
	GeneratedAt        time.Time
}

// reportData is everything GenerateReport pulls together before
// rendering — kept separate from the HTML rendering step so the two
// can be tested/reasoned about independently.
type reportData struct {
	PeriodStart, PeriodEnd time.Time
	NewAssets              int
	UnreviewedAlerts       int
	ActiveAlerts           int
	AlertsBySeverity       map[string]int
	NewAlertsThisPeriod    int
	NewIncidents           []ManagedIncident
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
	// Build every KPI/table from one database snapshot. Without this, a live
	// telemetry sync between SELECTs could make the exported report internally
	// inconsistent (for example alert totals from one moment and incidents from
	// another).
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Report{}, err
	}
	defer tx.Rollback()
	data := reportData{PeriodStart: periodStart, PeriodEnd: periodEnd, AlertsBySeverity: map[string]int{}}

	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
		 SELECT sensor_id,asset_identity,MIN(first_seen) AS first_seen
		 FROM asset_identity_history
		 WHERE asset_identity<>''
		 GROUP BY sensor_id,asset_identity
		) assets WHERE first_seen >= $1 AND first_seen < $2`,
		periodStart, periodEnd).Scan(&data.NewAssets); err != nil {
		return Report{}, fmt.Errorf("new assets: %w", err)
	}

	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM alert_history WHERE status = 'new'`,
	).Scan(&data.UnreviewedAlerts); err != nil {
		return Report{}, fmt.Errorf("unreviewed alerts: %w", err)
	}

	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM alert_history
		WHERE status <> 'approved' AND last_seen >= NOW() - INTERVAL '5 minutes'`,
	).Scan(&data.ActiveAlerts); err != nil {
		return Report{}, fmt.Errorf("active alerts: %w", err)
	}

	sevRows, err := tx.QueryContext(ctx, `
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
		data.AlertsBySeverity[strings.ToLower(strings.TrimSpace(sev))] += n
	}
	sevRows.Close()

	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM alert_history WHERE first_seen >= $1 AND first_seen < $2`,
		periodStart, periodEnd).Scan(&data.NewAlertsThisPeriod); err != nil {
		return Report{}, fmt.Errorf("new alerts this period: %w", err)
	}

	incidents, err := listManagedIncidentsCreatedBetween(ctx, tx, periodStart, periodEnd)
	if err != nil {
		return Report{}, fmt.Errorf("incidents: %w", err)
	}
	data.NewIncidents = incidents

	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM topology_edges WHERE first_seen >= $1 AND first_seen < $2`,
		periodStart, periodEnd).Scan(&data.TopologyEdgeGrowth); err != nil {
		return Report{}, fmt.Errorf("topology growth: %w", err)
	}

	offlineRows, err := tx.QueryContext(ctx, `SELECT id FROM sensors WHERE status = 'offline'`)
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

	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensors`).Scan(&data.TotalSensors); err != nil {
		return Report{}, fmt.Errorf("total sensors: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Report{}, err
	}
	return Report{
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		HTML:        renderReportHTML(data),
		GeneratedAt: time.Now().UTC(),
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

	sb.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><style>
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
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d</b><span>Unreviewed alerts</span><small>%d active in last 5m · %d newly observed</small></div>`, d.UnreviewedAlerts, d.ActiveAlerts, d.NewAlertsThisPeriod))
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d</b><span>New connections</span><small>Topology growth</small></div>`, d.TopologyEdgeGrowth))
	sb.WriteString(fmt.Sprintf(`<div class="kpi"><b>%d%%</b><span>Sensor availability</span><small>%d of %d online</small></div>`, availability, d.TotalSensors-len(d.OfflineSensors), d.TotalSensors))
	sb.WriteString(`</div>`)

	sb.WriteString(`<section><h2>Alert posture</h2>`)
	sb.WriteString(fmt.Sprintf(`<p class="section-note">%d unreviewed alerts grouped by severity; %d are active in the last 5 minutes.</p><table><thead><tr><th>Severity</th><th class="number">Unreviewed</th><th class="number">Share</th></tr></thead><tbody>`, severityTotal, d.ActiveAlerts))
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		n := d.AlertsBySeverity[sev]
		share := 0
		if severityTotal > 0 {
			share = n * 100 / severityTotal
		}
		sb.WriteString(fmt.Sprintf(`<tr><td><span class="severity %s">%s</span></td><td class="number">%d</td><td class="number muted">%d%%</td></tr>`, sev, esc(strings.ToUpper(sev)), n, share))
	}
	sb.WriteString(`</tbody></table></section>`)

	sb.WriteString(`<section><h2>Managed incidents</h2><p class="section-note">Incidents created during this exact reporting window.</p>`)
	if len(d.NewIncidents) == 0 {
		sb.WriteString(`<div class="empty">No correlated incidents were identified in this reporting window.</div>`)
	} else {
		sb.WriteString(`<table><thead><tr><th>Sensor</th><th>IP address</th><th>Severity</th><th>Rule / title</th></tr></thead><tbody>`)
		for _, inc := range d.NewIncidents {
			sev := strings.ToLower(inc.Severity)
			if sev == "" {
				sev = "low"
			}
			label := strings.TrimSpace(inc.RuleName)
			if label == "" {
				label = strings.TrimSpace(inc.Title)
			}
			sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><span class="severity %s">%s</span></td><td>%s</td></tr>`,
				esc(inc.SensorID), esc(inc.IP), esc(sev), esc(strings.ToUpper(inc.Severity)), esc(label)))
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
		INSERT INTO report_history(id, period_start, period_end, html, recipients, email_sent, email_error, email_attempts, last_email_attempt_at, next_email_attempt_at, generated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT(id) DO NOTHING`,
		rep.ID, rep.PeriodStart, rep.PeriodEnd, rep.HTML, strings.Join(rep.Recipients, ","), rep.EmailSent, rep.EmailError, rep.EmailAttempts, rep.LastEmailAttemptAt, rep.NextEmailAttemptAt, rep.GeneratedAt,
	)
	return err
}

// UpdateReportDelivery records the last SMTP outcome without regenerating or
// replacing the report body. This is intentionally separate from SaveReport so
// delivery retries cannot mutate the historical reporting window/content.
func (r *Repository) UpdateReportDelivery(ctx context.Context, id string, recipients []string, sent bool, deliveryErr string, retryAfter time.Duration) error {
	var next interface{}
	if !sent && retryAfter > 0 {
		next = time.Now().UTC().Add(retryAfter)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE report_history
		SET recipients=$2,email_sent=$3,email_error=$4,
		    email_attempts=email_attempts+1,last_email_attempt_at=NOW(),next_email_attempt_at=$5
		WHERE id=$1`, id, strings.Join(recipients, ","), sent, deliveryErr, next)
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

// ListManagedIncidentsCreatedBetween is the report-specific incident query.
// Using the legacy rolling ListIncidents helper here made report contents drift
// with the time the report happened to run and did not match the managed
// Incident workbench. Reports instead need an exact half-open time window.
type reportQueryer interface {
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
}

func (r *Repository) ListManagedIncidentsCreatedBetween(ctx context.Context, start, end time.Time) ([]ManagedIncident, error) {
	return listManagedIncidentsCreatedBetween(ctx, r.db, start, end)
}

func listManagedIncidentsCreatedBetween(ctx context.Context, q reportQueryer, start, end time.Time) ([]ManagedIncident, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id,sensor_id,asset_ip,title,severity,score,confidence,status,owner,summary,
		       first_seen,last_seen,updated_at,COALESCE(correlation_rule_id,0),correlation_rule_name,
		       mitre_tactics,mitre_techniques
		FROM incidents
		WHERE created_at >= $1 AND created_at < $2
		ORDER BY created_at DESC,id DESC`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ManagedIncident, 0)
	for rows.Next() {
		var x ManagedIncident
		var tactics, techniques string
		if err := rows.Scan(&x.ID, &x.SensorID, &x.IP, &x.Title, &x.Severity, &x.Score, &x.Confidence,
			&x.Status, &x.Owner, &x.Summary, &x.FirstSeen, &x.LastSeen, &x.UpdatedAt, &x.RuleID,
			&x.RuleName, &tactics, &techniques); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tactics), &x.MITRETactics)
		_ = json.Unmarshal([]byte(techniques), &x.MITRETechniques)
		out = append(out, x)
	}
	return out, rows.Err()
}

// ListReports returns the most recently generated reports, newest
// first, without their (potentially large) HTML body — use GetReport
// for the full content of one specific report.
func (r *Repository) ListReports(ctx context.Context, limit int) ([]Report, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, period_start, period_end, recipients, email_sent, email_error,
		       email_attempts,last_email_attempt_at,next_email_attempt_at,generated_at
		FROM report_history ORDER BY generated_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Report, 0)
	for rows.Next() {
		var rep Report
		var recipients string
		if err := rows.Scan(&rep.ID, &rep.PeriodStart, &rep.PeriodEnd, &recipients, &rep.EmailSent, &rep.EmailError, &rep.EmailAttempts, &rep.LastEmailAttemptAt, &rep.NextEmailAttemptAt, &rep.GeneratedAt); err != nil {
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
		SELECT id, period_start, period_end, html, recipients, email_sent, email_error,
		       email_attempts,last_email_attempt_at,next_email_attempt_at,generated_at
		FROM report_history WHERE id=$1`, id,
	).Scan(&rep.ID, &rep.PeriodStart, &rep.PeriodEnd, &rep.HTML, &recipients, &rep.EmailSent, &rep.EmailError, &rep.EmailAttempts, &rep.LastEmailAttemptAt, &rep.NextEmailAttemptAt, &rep.GeneratedAt)
	if err != nil {
		return Report{}, err
	}
	if recipients != "" {
		rep.Recipients = strings.Split(recipients, ",")
	}
	return rep, nil
}

// ListReportsPendingDelivery returns saved, unsent reports whose SMTP retry
// backoff has elapsed. A durable saved report therefore does not depend on the
// Central process remaining up during one specific weekly hour.
func (r *Repository) ListReportsPendingDelivery(ctx context.Context, limit int) ([]Report, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id,period_start,period_end,html,recipients,email_sent,email_error,
		       email_attempts,last_email_attempt_at,next_email_attempt_at,generated_at
		FROM report_history
		WHERE email_sent=FALSE AND recipients<>''
		  AND (next_email_attempt_at IS NULL OR next_email_attempt_at<=NOW())
		ORDER BY COALESCE(next_email_attempt_at,generated_at),generated_at
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Report, 0)
	for rows.Next() {
		var rep Report
		var recipients string
		if err := rows.Scan(&rep.ID, &rep.PeriodStart, &rep.PeriodEnd, &rep.HTML, &recipients, &rep.EmailSent, &rep.EmailError, &rep.EmailAttempts, &rep.LastEmailAttemptAt, &rep.NextEmailAttemptAt, &rep.GeneratedAt); err != nil {
			return nil, err
		}
		if recipients != "" {
			rep.Recipients = strings.Split(recipients, ",")
		}
		out = append(out, rep)
	}
	return out, rows.Err()
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
