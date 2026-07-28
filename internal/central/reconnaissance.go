package central

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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

func (r *Repository) CreateReconJob(ctx context.Context, j management.ReconJob) error {
	t, _ := json.Marshal(j.Targets)
	p, _ := json.Marshal(j.Policy)
	_, err := r.db.ExecContext(ctx, `INSERT INTO reconnaissance_jobs(id,sensor_id,profile,targets,policy,status) VALUES($1,$2,$3,$4,$5,$6)`, j.ID, j.SensorID, j.Profile, t, p, j.Status)
	return err
}
func (r *Repository) ListReconJobs(ctx context.Context) ([]management.ReconJob, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,sensor_id,profile,targets,policy,status,error,created_at,started_at,completed_at FROM reconnaissance_jobs ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []management.ReconJob
	for rows.Next() {
		var j management.ReconJob
		var t, p []byte
		if err := rows.Scan(&j.ID, &j.SensorID, &j.Profile, &t, &p, &j.Status, &j.Error, &j.CreatedAt, &j.StartedAt, &j.CompletedAt); err != nil {
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
	for _, x := range results {
		b, _ := json.Marshal(x)
		if _, err = tx.ExecContext(ctx, `INSERT INTO reconnaissance_results(job_id,target,result) VALUES($1,$2,$3)`, jobID, x.Target, b); err != nil {
			return err
		}
		services, _ := json.Marshal(x.Services)
		evidence, _ := json.Marshal(x.Evidence)
		if _, err = tx.ExecContext(ctx, `INSERT INTO asset_recon_profile(sensor_id,ip,hostname,vendor,operating_system,model,firmware,serial,ot_identity,services,evidence,last_profiled_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
			ON CONFLICT(sensor_id,ip) DO UPDATE SET hostname=COALESCE(NULLIF(EXCLUDED.hostname,''),asset_recon_profile.hostname),vendor=COALESCE(NULLIF(EXCLUDED.vendor,''),asset_recon_profile.vendor),operating_system=COALESCE(NULLIF(EXCLUDED.operating_system,''),asset_recon_profile.operating_system),model=COALESCE(NULLIF(EXCLUDED.model,''),asset_recon_profile.model),firmware=COALESCE(NULLIF(EXCLUDED.firmware,''),asset_recon_profile.firmware),serial=COALESCE(NULLIF(EXCLUDED.serial,''),asset_recon_profile.serial),ot_identity=CASE WHEN EXCLUDED.ot_identity='{}'::jsonb THEN asset_recon_profile.ot_identity ELSE EXCLUDED.ot_identity END,services=EXCLUDED.services,evidence=EXCLUDED.evidence,last_profiled_at=NOW()`, sensorID, x.Target, x.Hostname, x.Vendor, x.OS, x.Model, x.Firmware, x.Serial, mustJSON(x.OTIdentity), services, evidence); err != nil {
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
		c.JSON(500, gin.H{"error": e.Error()})
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
		c.JSON(500, gin.H{"error": err.Error()})
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
		c.JSON(500, gin.H{"error": err.Error()})
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
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"accepted": true})
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
