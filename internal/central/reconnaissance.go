package central

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	if len(b) == 0 || string(b) == "null" {
		return []byte("{}")
	}
	return b
}

func reconID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return "recon-" + hex.EncodeToString(b)
}

func serviceKeys(in []management.ReconService) []string {
	out := make([]string, 0, len(in))
	for _, x := range in {
		out = append(out, fmt.Sprintf("%d/%s %s %s %s", x.Port, x.Transport, x.Service, x.Product, x.Version))
	}
	sort.Strings(out)
	return out
}

func reconChanges(previous *management.ReconResult, current management.ReconResult) []management.ReconChange {
	if previous == nil {
		return []management.ReconChange{{Kind: "baseline", Field: "asset", Current: "Initial discovery baseline created", Severity: "info"}}
	}
	var out []management.ReconChange
	fields := []struct{ name, old, next string }{
		{"hostname", previous.Hostname, current.Hostname}, {"vendor", previous.Vendor, current.Vendor}, {"operating_system", previous.OS, current.OS},
		{"model", previous.Model, current.Model}, {"firmware", previous.Firmware, current.Firmware}, {"serial", previous.Serial, current.Serial},
	}
	for _, f := range fields {
		if f.old != f.next && f.next != "" {
			severity := "info"
			if f.name == "firmware" || f.name == "operating_system" {
				severity = "medium"
			}
			out = append(out, management.ReconChange{Kind: "changed", Field: f.name, Previous: f.old, Current: f.next, Severity: severity})
		}
	}
	oldServices, newServices := serviceKeys(previous.Services), serviceKeys(current.Services)
	oldSet, newSet := map[string]bool{}, map[string]bool{}
	for _, x := range oldServices {
		oldSet[x] = true
	}
	for _, x := range newServices {
		newSet[x] = true
	}
	for _, x := range newServices {
		if !oldSet[x] {
			out = append(out, management.ReconChange{Kind: "added", Field: "service", Current: x, Severity: "medium"})
		}
	}
	for _, x := range oldServices {
		if !newSet[x] {
			out = append(out, management.ReconChange{Kind: "removed", Field: "service", Previous: x, Severity: "info"})
		}
	}
	return out
}

type reconBuiltinPolicy struct {
	Enabled          bool                       `json:"enabled"`
	Severity         string                     `json:"severity"`
	SeverityOverride bool                       `json:"severity_override"`
	Simulation       bool                       `json:"simulation"`
	Suppression      management.RuleSuppression `json:"suppression"`
	Schedule         string                     `json:"schedule"`
}

func reconRulePolicyTx(ctx context.Context, tx *sql.Tx, sensorID, ruleID, fallbackSeverity string) reconBuiltinPolicy {
	out := reconBuiltinPolicy{Enabled: true, Severity: fallbackSeverity}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT rules FROM sensor_telemetry WHERE sensor_id=$1`, sensorID).Scan(&raw); err != nil {
		return out
	}
	var rows []struct {
		ID               string                     `json:"id"`
		Enabled          bool                       `json:"enabled"`
		Severity         string                     `json:"severity"`
		SeverityOverride bool                       `json:"severity_override"`
		Simulation       bool                       `json:"simulation"`
		Suppression      management.RuleSuppression `json:"suppression"`
		Schedule         string                     `json:"schedule"`
	}
	if json.Unmarshal(raw, &rows) != nil {
		return out
	}
	for _, r := range rows {
		if r.ID == ruleID {
			out.Enabled = r.Enabled
			out.Simulation = r.Simulation
			out.SeverityOverride = r.SeverityOverride
			out.Suppression = r.Suppression
			out.Schedule = r.Schedule
			if r.SeverityOverride && strings.TrimSpace(r.Severity) != "" {
				out.Severity = strings.ToLower(strings.TrimSpace(r.Severity))
			}
			return out
		}
	}
	return out
}

func reconScheduleAllows(schedule string, now time.Time) bool {
	schedule = strings.TrimSpace(strings.ToLower(schedule))
	if schedule == "" || schedule == "always" {
		return true
	}
	window := schedule
	if i := strings.Index(schedule, "@"); i >= 0 {
		days, candidate := schedule[:i], schedule[i+1:]
		weekday := strings.ToLower(now.UTC().Weekday().String()[:3])
		allowed := false
		for _, day := range strings.Split(days, ",") {
			day = strings.TrimSpace(day)
			if day == weekday || (day == "weekday" && weekday != "sat" && weekday != "sun") || (day == "weekend" && (weekday == "sat" || weekday == "sun")) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
		window = candidate
	}
	parts := strings.Split(window, "-")
	if len(parts) != 2 {
		return false
	}
	parse := func(v string) (int, bool) {
		var h, m int
		if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
			return 0, false
		}
		return h*60 + m, true
	}
	from, okFrom := parse(parts[0])
	to, okTo := parse(parts[1])
	if !okFrom || !okTo {
		return false
	}
	minute := now.UTC().Hour()*60 + now.UTC().Minute()
	if from <= to {
		return minute >= from && minute < to
	}
	return minute >= from || minute < to
}

func insertReconDerivedAlertTx(ctx context.Context, tx *sql.Tx, sensorID, ruleID, alertType, fallbackSeverity, key, message, ip string, evidence map[string]interface{}) error {
	policy := reconRulePolicyTx(ctx, tx, sensorID, ruleID, fallbackSeverity)
	now := time.Now().UTC()
	if !policy.Enabled || policy.Simulation || !reconScheduleAllows(policy.Schedule, now) {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(policy.Suppression.Mode))
	if mode == "" {
		mode = "aggregate"
	}
	if mode == "once" || mode == "interval" {
		var lastSeen time.Time
		err := tx.QueryRowContext(ctx, `SELECT last_seen FROM alert_history WHERE sensor_id=$1 AND alert_key=$2`, sensorID, key).Scan(&lastSeen)
		if err == nil {
			if mode == "once" {
				return nil
			}
			interval := time.Duration(policy.Suppression.IntervalSeconds) * time.Second
			if interval <= 0 {
				interval = 5 * time.Minute
			}
			if now.Sub(lastSeen) < interval {
				return nil
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if mode == "every" {
		key = fmt.Sprintf("%s|%d", key, now.UnixNano())
	}
	ev, _ := json.Marshal(evidence)
	_, err := tx.ExecContext(ctx, `INSERT INTO alert_history(sensor_id,alert_key,type,severity,message,ip,status,count,first_seen,last_seen,evidence)
		VALUES($1,$2,$3,$4,$5,$6,'new',1,$7,$7,$8)
		ON CONFLICT(sensor_id,alert_key) DO UPDATE SET severity=EXCLUDED.severity,message=EXCLUDED.message,last_seen=EXCLUDED.last_seen,
		count=CASE WHEN alert_history.last_seen < EXCLUDED.last_seen-INTERVAL '5 minutes' THEN alert_history.count+1 ELSE alert_history.count END,
		evidence=EXCLUDED.evidence,status=CASE WHEN alert_history.status='approved' THEN alert_history.status ELSE 'new' END`, sensorID, key, alertType, policy.Severity, message, ip, now, ev)
	return err
}

func persistReconSecurityChangesTx(ctx context.Context, tx *sql.Tx, sensorID string, x management.ReconResult) error {
	for _, ch := range x.Changes {
		if ch.Kind != "changed" {
			continue
		}
		ev := map[string]interface{}{"source": "reconnaissance_profile", "field": ch.Field, "previous": ch.Previous, "current": ch.Current, "job_target": x.Target}
		switch ch.Field {
		case "firmware":
			if err := insertReconDerivedAlertTx(ctx, tx, sensorID, "builtin.firmware_change", "firmware_change", "critical",
				fmt.Sprintf("recon-firmware|%s|%s", x.Target, ch.Current), fmt.Sprintf("Firmware on %s changed from %s to %s", x.Target, ch.Previous, ch.Current), x.Target, ev); err != nil {
				return err
			}
		case "hostname", "vendor", "model", "serial", "operating_system":
			if err := insertReconDerivedAlertTx(ctx, tx, sensorID, "builtin.asset_identity_drift", "asset_identity_drift", "high",
				fmt.Sprintf("recon-identity|%s|%s|%s", x.Target, ch.Field, ch.Current), fmt.Sprintf("Asset %s identity field %s changed from %s to %s", x.Target, ch.Field, ch.Previous, ch.Current), x.Target, ev); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Repository) CreateReconJob(ctx context.Context, j management.ReconJob) error {
	t, _ := json.Marshal(j.Targets)
	p, _ := json.Marshal(j.Policy)
	_, err := r.db.ExecContext(ctx, `INSERT INTO reconnaissance_jobs(id,sensor_id,campaign_id,profile,targets,policy,status) VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7)`, j.ID, j.SensorID, j.CampaignID, j.Profile, t, p, j.Status)
	return err
}
func (r *Repository) ListReconJobs(ctx context.Context) ([]management.ReconJob, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,sensor_id,COALESCE(campaign_id,''),profile,targets,policy,status,error,created_at,started_at,completed_at FROM reconnaissance_jobs ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.ReconJob
	for rows.Next() {
		var j management.ReconJob
		var t, p []byte
		if err := rows.Scan(&j.ID, &j.SensorID, &j.CampaignID, &j.Profile, &t, &p, &j.Status, &j.Error, &j.CreatedAt, &j.StartedAt, &j.CompletedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(t, &j.Targets)
		_ = json.Unmarshal(p, &j.Policy)
		rr, _ := r.ReconResults(ctx, j.ID)
		j.Results = rr
		out = append(out, j)
	}
	return out, rows.Err()
}
func (r *Repository) ReconResults(ctx context.Context, jobID string) ([]management.ReconResult, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT result FROM reconnaissance_results WHERE job_id=$1 ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.ReconResult
	for rows.Next() {
		var b []byte
		if rows.Scan(&b) == nil {
			var x management.ReconResult
			if json.Unmarshal(b, &x) == nil {
				out = append(out, x)
			}
		}
	}
	return out, rows.Err()
}
func (r *Repository) CompleteReconJob(ctx context.Context, jobID string, results []management.ReconResult, jobErr string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sensorID string
	if err = tx.QueryRowContext(ctx, `SELECT sensor_id FROM reconnaissance_jobs WHERE id=$1`, jobID).Scan(&sensorID); err != nil {
		return err
	}
	for i := range results {
		x := &results[i]
		var previous management.ReconResult
		var previousServices []byte
		previous.Target = x.Target
		errPrev := tx.QueryRowContext(ctx, `SELECT hostname,vendor,operating_system,model,firmware,serial,services FROM asset_recon_profile WHERE sensor_id=$1 AND ip=$2`, sensorID, x.Target).Scan(&previous.Hostname, &previous.Vendor, &previous.OS, &previous.Model, &previous.Firmware, &previous.Serial, &previousServices)
		var previousPtr *management.ReconResult
		if errPrev == nil {
			_ = json.Unmarshal(previousServices, &previous.Services)
			previousPtr = &previous
		}
		x.Changes = reconChanges(previousPtr, *x)
		if err = persistReconSecurityChangesTx(ctx, tx, sensorID, *x); err != nil {
			return err
		}
		services, _ := json.Marshal(x.Services)
		evidence, _ := json.Marshal(x.Evidence)
		if _, err = tx.ExecContext(ctx, `INSERT INTO asset_recon_profile(sensor_id,ip,hostname,vendor,operating_system,model,firmware,serial,ot_identity,services,evidence,last_profiled_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
			ON CONFLICT(sensor_id,ip) DO UPDATE SET hostname=COALESCE(NULLIF(EXCLUDED.hostname,''),asset_recon_profile.hostname),vendor=COALESCE(NULLIF(EXCLUDED.vendor,''),asset_recon_profile.vendor),operating_system=COALESCE(NULLIF(EXCLUDED.operating_system,''),asset_recon_profile.operating_system),model=COALESCE(NULLIF(EXCLUDED.model,''),asset_recon_profile.model),firmware=COALESCE(NULLIF(EXCLUDED.firmware,''),asset_recon_profile.firmware),serial=COALESCE(NULLIF(EXCLUDED.serial,''),asset_recon_profile.serial),ot_identity=CASE WHEN EXCLUDED.ot_identity='{}'::jsonb THEN asset_recon_profile.ot_identity ELSE EXCLUDED.ot_identity END,services=EXCLUDED.services,evidence=EXCLUDED.evidence,last_profiled_at=NOW()`, sensorID, x.Target, x.Hostname, x.Vendor, x.OS, x.Model, x.Firmware, x.Serial, mustJSON(x.OTIdentity), services, evidence); err != nil {
			return err
		}
		x.Audit = append(x.Audit, management.ReconAuditStep{Stage: "persist_results", Status: "ok", Detail: "result stored and asset profile updated", ObservedAt: time.Now().UTC()})
		b, _ := json.Marshal(x)
		changes, _ := json.Marshal(x.Changes)
		if _, err = tx.ExecContext(ctx, `INSERT INTO asset_recon_history(sensor_id,ip,job_id,result,changes) VALUES($1,$2,$3,$4,$5)`, sensorID, x.Target, jobID, b, changes); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO reconnaissance_results(job_id,target,result) VALUES($1,$2,$3)`, jobID, x.Target, b); err != nil {
			return err
		}
	}
	status := "completed"
	if jobErr != "" {
		status = "failed"
	} else {
		for _, x := range results {
			if x.Error != "" {
				status = "partially_completed"
				break
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE reconnaissance_jobs SET status=$2,error=$3,started_at=COALESCE(started_at,NOW()),completed_at=NOW() WHERE id=$1`, jobID, status, jobErr); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) listReconJobs(c *gin.Context) {
	x, e := s.Repo.ListReconJobs(c)
	if e != nil {
		respondInternalError(c, e)
		return
	}
	c.JSON(200, x)
}
func (s *Server) createReconJob(c *gin.Context) {
	var j management.ReconJob
	if c.ShouldBindJSON(&j) != nil || strings.TrimSpace(j.SensorID) == "" || len(j.Targets) == 0 {
		c.JSON(400, gin.H{"error": "sensor_id and targets are required"})
		return
	}
	if j.Profile == "" {
		j.Profile = "safe-discovery"
	}
	if j.Profile != "safe-discovery" && j.Profile != "ot-conservative" && j.Profile != "authenticated-inventory" {
		c.JSON(400, gin.H{"error": "profile must be safe-discovery, ot-conservative or authenticated-inventory"})
		return
	}
	if j.Profile == "ot-conservative" {
		if !j.Policy.RequireManualApproval {
			c.JSON(400, gin.H{"error": "OT conservative discovery requires manual approval"})
			return
		}
		if len(j.Policy.OTProtocols) == 0 {
			j.Policy.OTProtocols = []string{"modbus", "ethernet-ip", "s7", "opcua", "bacnet"}
		}
	}
	if j.Policy.PacketsPerSecond <= 0 {
		j.Policy.PacketsPerSecond = 5
	}
	if j.Policy.PacketsPerSecond > 20 {
		c.JSON(400, gin.H{"error": "packets_per_second may not exceed 20"})
		return
	}
	if j.Policy.ConcurrentTargets <= 0 {
		j.Policy.ConcurrentTargets = 1
	}
	if j.Policy.TimeoutSeconds <= 0 {
		j.Policy.TimeoutSeconds = 3
	}
	if j.Profile == "authenticated-inventory" {
		if !j.Policy.RequireManualApproval || j.Policy.CredentialID == "" {
			c.JSON(400, gin.H{"error": "authenticated inventory requires approval and credential_id"})
			return
		}
		if len(j.Policy.AuthenticatedMethods) == 0 {
			j.Policy.AuthenticatedMethods = []string{"ssh"}
		}
	}
	j.ID = reconID()
	j.Status = "queued"
	if err := s.Repo.CreateReconJob(c, j); err != nil {
		respondInternalError(c, err)
		return
	}
	cmd := management.ReconCommand{JobID: j.ID, Targets: j.Targets, Profile: j.Profile, Policy: j.Policy}
	if j.Policy.CredentialID != "" {
		cred, err := s.Repo.GetReconCredential(c, j.Policy.CredentialID)
		if err != nil {
			c.JSON(400, gin.H{"error": "credential not found or unavailable"})
			return
		}
		cmd.Credential = &cred
	}
	b, _ := json.Marshal(cmd)
	if err := s.Repo.QueueCommands(c, j.SensorID, "recon.safe_discovery", []string{string(b)}); err != nil {
		_, _ = s.Repo.db.ExecContext(c, `UPDATE reconnaissance_jobs SET status='failed',error=$2,completed_at=NOW() WHERE id=$1`, j.ID, "failed to queue sensor command: "+err.Error())
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusCreated, j)
}
func (s *Server) reconResult(c *gin.Context) {
	var body struct {
		Results []management.ReconResult `json:"results"`
		Error   string                   `json:"error"`
	}
	if c.ShouldBindJSON(&body) != nil {
		c.JSON(400, gin.H{"error": "invalid result"})
		return
	}
	if err := s.Repo.CompleteReconJob(c, c.Param("job"), body.Results, body.Error); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		respondInternalError(c, err)
		return
	}
	status := "completed"
	if strings.TrimSpace(body.Error) != "" {
		status = "failed"
	}
	s.publishLive(LiveEvent{Type: "discovery.completed", SensorID: c.GetHeader("X-OTLens-Sensor-ID"), EntityID: c.Param("job"), Message: "discovery " + status, Data: gin.H{"status": status, "result_count": len(body.Results)}})
	c.JSON(200, gin.H{"accepted": true})
}

func (r *Repository) ListReconCampaigns(ctx context.Context) ([]management.ReconCampaign, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,name,sensor_id,profile,targets,policy,enabled,created_at,updated_at,last_run_at FROM reconnaissance_campaigns ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.ReconCampaign
	for rows.Next() {
		var x management.ReconCampaign
		var targets, policy []byte
		if err := rows.Scan(&x.ID, &x.Name, &x.SensorID, &x.Profile, &targets, &policy, &x.Enabled, &x.CreatedAt, &x.UpdatedAt, &x.LastRunAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targets, &x.Targets)
		_ = json.Unmarshal(policy, &x.Policy)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Server) listReconCampaigns(c *gin.Context) {
	x, err := s.Repo.ListReconCampaigns(c)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(200, x)
}

func normalizeReconPolicy(profile string, p *management.ReconPolicy) error {
	if profile == "" {
		profile = "safe-discovery"
	}
	if profile != "safe-discovery" && profile != "ot-conservative" && profile != "authenticated-inventory" {
		return errors.New("unsupported discovery profile")
	}
	if p.PacketsPerSecond <= 0 {
		p.PacketsPerSecond = 5
	}
	if p.PacketsPerSecond > 20 {
		return errors.New("packets_per_second may not exceed 20")
	}
	if p.ConcurrentTargets <= 0 {
		p.ConcurrentTargets = 1
	}
	if p.ConcurrentTargets > 10 {
		return errors.New("concurrent_targets may not exceed 10")
	}
	if p.TimeoutSeconds <= 0 {
		p.TimeoutSeconds = 3
	}
	if profile == "ot-conservative" {
		if !p.RequireManualApproval {
			return errors.New("OT conservative discovery requires manual approval")
		}
		if len(p.OTProtocols) == 0 {
			p.OTProtocols = []string{"modbus", "ethernet-ip", "s7", "opcua", "bacnet"}
		}
	}
	if profile == "authenticated-inventory" && (!p.RequireManualApproval || p.CredentialID == "") {
		return errors.New("authenticated inventory requires approval and credential_id")
	}
	return nil
}

func (s *Server) createReconCampaign(c *gin.Context) {
	var x management.ReconCampaign
	if c.ShouldBindJSON(&x) != nil || strings.TrimSpace(x.Name) == "" || strings.TrimSpace(x.SensorID) == "" || len(x.Targets) == 0 {
		c.JSON(400, gin.H{"error": "name, sensor_id and targets are required"})
		return
	}
	if x.Profile == "" {
		x.Profile = "safe-discovery"
	}
	if err := normalizeReconPolicy(x.Profile, &x.Policy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	x.ID = "campaign-" + strings.TrimPrefix(reconID(), "recon-")
	x.Enabled = true
	targets, _ := json.Marshal(x.Targets)
	policy, _ := json.Marshal(x.Policy)
	_, err := s.Repo.db.ExecContext(c, `INSERT INTO reconnaissance_campaigns(id,name,sensor_id,profile,targets,policy,enabled) VALUES($1,$2,$3,$4,$5,$6,$7)`, x.ID, x.Name, x.SensorID, x.Profile, targets, policy, x.Enabled)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	c.JSON(http.StatusCreated, x)
}

func (s *Server) runReconCampaign(c *gin.Context) {
	var x management.ReconCampaign
	var targets, policy []byte
	if err := s.Repo.db.QueryRowContext(c, `SELECT id,name,sensor_id,profile,targets,policy,enabled,created_at,updated_at,last_run_at FROM reconnaissance_campaigns WHERE id=$1`, c.Param("id")).Scan(&x.ID, &x.Name, &x.SensorID, &x.Profile, &targets, &policy, &x.Enabled, &x.CreatedAt, &x.UpdatedAt, &x.LastRunAt); err != nil {
		c.JSON(404, gin.H{"error": "campaign not found"})
		return
	}
	if !x.Enabled {
		c.JSON(409, gin.H{"error": "campaign is disabled"})
		return
	}
	_ = json.Unmarshal(targets, &x.Targets)
	_ = json.Unmarshal(policy, &x.Policy)
	j := management.ReconJob{ID: reconID(), SensorID: x.SensorID, CampaignID: x.ID, Targets: x.Targets, Profile: x.Profile, Policy: x.Policy, Status: "queued"}
	if err := s.Repo.CreateReconJob(c, j); err != nil {
		respondInternalError(c, err)
		return
	}
	cmd := management.ReconCommand{JobID: j.ID, Targets: j.Targets, Profile: j.Profile, Policy: j.Policy}
	if j.Policy.CredentialID != "" {
		cred, err := s.Repo.GetReconCredential(c, j.Policy.CredentialID)
		if err != nil {
			c.JSON(400, gin.H{"error": "credential not found or unavailable"})
			return
		}
		cmd.Credential = &cred
	}
	b, _ := json.Marshal(cmd)
	if err := s.Repo.QueueCommands(c, j.SensorID, "recon.safe_discovery", []string{string(b)}); err != nil {
		_, _ = s.Repo.db.ExecContext(c, `UPDATE reconnaissance_jobs SET status='failed',error=$2,completed_at=NOW() WHERE id=$1`, j.ID, err.Error())
		respondInternalError(c, err)
		return
	}
	_, _ = s.Repo.db.ExecContext(c, `UPDATE reconnaissance_campaigns SET last_run_at=NOW(),updated_at=NOW() WHERE id=$1`, x.ID)
	c.JSON(http.StatusCreated, j)
}

func (s *Server) deleteReconCampaign(c *gin.Context) {
	res, err := s.Repo.db.ExecContext(c, `DELETE FROM reconnaissance_campaigns WHERE id=$1`, c.Param("id"))
	if err != nil {
		respondInternalError(c, err)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(404, gin.H{"error": "campaign not found"})
		return
	}
	c.Status(204)
}

func (s *Server) assetReconHistory(c *gin.Context) {
	rows, err := s.Repo.db.QueryContext(c, `SELECT job_id,result,changes,observed_at FROM asset_recon_history WHERE sensor_id=$1 AND ip=$2 ORDER BY observed_at DESC LIMIT 50`, c.Param("id"), c.Param("ip"))
	if err != nil {
		respondInternalError(c, err)
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var job string
		var result, changes []byte
		var at time.Time
		if rows.Scan(&job, &result, &changes, &at) == nil {
			var r management.ReconResult
			var ch []management.ReconChange
			_ = json.Unmarshal(result, &r)
			_ = json.Unmarshal(changes, &ch)
			out = append(out, gin.H{"job_id": job, "observed_at": at, "result": r, "changes": ch})
		}
	}
	c.JSON(200, out)
}

type AssetReconProfile struct {
	SensorID       string
	IP             string
	Hostname       string
	Vendor         string
	OS             string
	Model          string
	Firmware       string
	Serial         string
	OTIdentity     json.RawMessage
	Services       json.RawMessage
	Evidence       json.RawMessage
	LastProfiledAt string
}

func (r *Repository) AssetReconProfiles(ctx context.Context) (map[string]AssetReconProfile, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id,ip,hostname,vendor,operating_system,model,firmware,serial,ot_identity,services,evidence,last_profiled_at::text FROM asset_recon_profile`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AssetReconProfile{}
	for rows.Next() {
		var x AssetReconProfile
		if err := rows.Scan(&x.SensorID, &x.IP, &x.Hostname, &x.Vendor, &x.OS, &x.Model, &x.Firmware, &x.Serial, &x.OTIdentity, &x.Services, &x.Evidence, &x.LastProfiledAt); err != nil {
			return nil, err
		}
		out[x.SensorID+"\x00"+x.IP] = x
	}
	return out, rows.Err()
}
