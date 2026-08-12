package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/central"
	"github.com/zabojnikvlado/otlens_linux/internal/config"
	"github.com/zabojnikvlado/otlens_linux/internal/siem"
	"github.com/zabojnikvlado/otlens_linux/internal/vuln"
)

// defaultConfigPath is config.yaml next to wherever otlens-central.exe
// actually is — not a fixed ProgramData path. This matches how
// internal/central's centralWebDir() already resolves the web UI folder
// (relative to the executable), so "drop the exe, its config, and web/
// somewhere and run it" works as one self-contained unit regardless of
// where that happens to be, rather than requiring a specific install
// location. Falls back to the bare relative name only if the OS can't
// even tell us our own executable's path.
func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(filepath.Dir(exe), "config.yaml")
}

// tokenFingerprint is a short one-way identifier used only for diagnostics.
// It lets an operator confirm that Central and a sensor loaded the same
// enrollment credential without placing that credential in logs.
func tokenFingerprint(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return "<empty>"
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:12]
}

func main() {
	configPath := flag.String("config", defaultConfigPath(), "path to the Central Management configuration file")
	flag.Parse()

	cfg, err := config.LoadCentral(*configPath)
	if err != nil {
		log.Fatalf("configuration loading failed: %v", err)
	}

	_, sensorTokenEnvOverride := os.LookupEnv("OTLENS_CENTRAL_AUTH_SENSOR_TOKEN")
	log.Printf(
		"OTLens Central configuration: config_path=%s sensor_enrollment_configured=%t sensor_enrollment_token_fingerprint=%s sensor_token_env_override=%t",
		*configPath,
		strings.TrimSpace(cfg.Auth.SensorToken) != "",
		tokenFingerprint(cfg.Auth.SensorToken),
		sensorTokenEnvOverride,
	)

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)

	repo, err := central.OpenPostgres(dsn)
	if err != nil {
		log.Fatalf("postgres connection failed: %v", err)
	}
	defer repo.Close()
	repo.ConfigureSIEM(cfg.SIEM.Enabled && cfg.SIEM.ExportAlerts, cfg.SIEM.Enabled && cfg.SIEM.ExportAudit, cfg.SIEM.Source)

	bootstrapHash, err := central.HashPassword(cfg.Auth.BootstrapPassword)
	if err != nil {
		log.Fatalf("bootstrap admin password hashing failed: %v", err)
	}
	if err := repo.EnsureAuthBootstrap(context.Background(), cfg.Auth.BootstrapUsername, bootstrapHash); err != nil {
		log.Fatalf("auth bootstrap failed: %v", err)
	}

	// Catch-up for edges written before upsertTopologyEdges started
	// guaranteeing both endpoints have a node — see that function's
	// comment. Not fatal if it fails: the Topology tab just keeps
	// showing whatever gap already existed until the next successful
	// run, same as any other startup task that isn't strictly required
	// to serve traffic.
	if n, err := repo.BackfillOrphanedEdgeNodes(context.Background()); err != nil {
		log.Printf("topology node backfill failed: %v", err)
	} else if n > 0 {
		log.Printf("topology node backfill: created %d missing node stub(s) for existing edges", n)
	}

	// vuln.New() alone is a working no-op — Lookup just returns an empty
	// slice — so this is unconditional; LoadCSV only runs when configured,
	// and a failed/missing snapshot logs a warning rather than crashing
	// Central over what's a supplementary lookup, not a core function.
	vulnDB := vuln.New()
	if rows, loadErr := repo.ListVulnerabilityAdvisories(context.Background()); loadErr != nil {
		log.Printf("vulnerability database load failed: %v", loadErr)
	} else {
		log.Printf("vulnerability database loaded: %d advisories", vulnDB.Replace(rows))
	}

	retentionCfg := central.RetentionConfig{
		Enabled: cfg.DatabaseRetention.Enabled, TelemetryDays: cfg.DatabaseRetention.TelemetryDays,
		AlertsDays: cfg.DatabaseRetention.AlertsDays, AuditDays: cfg.DatabaseRetention.AuditDays,
		MaxDatabaseSizeGB: cfg.DatabaseRetention.MaxDatabaseSizeGB, TargetDatabaseSizeGB: cfg.DatabaseRetention.TargetDatabaseSizeGB,
		DeleteBatchSize: cfg.DatabaseRetention.DeleteBatchSize, Interval: cfg.DatabaseRetention.Interval,
	}

	var notificationsCfg central.NotificationConfig
	notificationsCfg.Enabled = cfg.Notifications.Enabled
	notificationsCfg.MinSeverity = cfg.Notifications.MinSeverity
	notificationsCfg.Email.Enabled = cfg.Notifications.Email.Enabled
	notificationsCfg.Email.SMTPHost = cfg.Notifications.Email.SMTPHost
	notificationsCfg.Email.SMTPPort = cfg.Notifications.Email.SMTPPort
	notificationsCfg.Email.Username = cfg.Notifications.Email.Username
	notificationsCfg.Email.Password = cfg.Notifications.Email.Password
	notificationsCfg.Email.From = cfg.Notifications.Email.From
	notificationsCfg.Email.To = cfg.Notifications.Email.To
	notificationsCfg.Email.UseTLS = cfg.Notifications.Email.UseTLS
	notificationsCfg.Webhook.Enabled = cfg.Notifications.Webhook.Enabled
	notificationsCfg.Webhook.URL = cfg.Notifications.Webhook.URL
	notificationsCfg.Webhook.Headers = cfg.Notifications.Webhook.Headers

	reportsCfg := central.ReportsConfig{
		Enabled: cfg.Reports.Enabled, Schedule: cfg.Reports.Schedule,
		DayOfWeek: cfg.Reports.DayOfWeek, HourUTC: cfg.Reports.HourUTC, Recipients: cfg.Reports.Recipients,
	}

	srv := &central.Server{StartedAt: time.Now().UTC(),
		Repo: repo, ManagementToken: cfg.Auth.ManagementToken, SensorToken: strings.TrimSpace(cfg.Auth.SensorToken),
		BootstrapUsername: cfg.Auth.BootstrapUsername, BootstrapPasswordHash: bootstrapHash,
		SIEMEnabled: cfg.SIEM.Enabled, SIEMMaxAttempts: cfg.SIEM.MaxAttempts,
		AnalysisEnabled: cfg.Analysis.Enabled && cfg.Analysis.AllowImport, AnalysisDir: cfg.Analysis.UploadDirectory,
		AnalysisMaxBytes:    cfg.Analysis.MaxUploadSizeMB * 1024 * 1024,
		Vuln:                vulnDB,
		SensorOfflineAfter:  cfg.Sensors.OfflineAfter,
		SensorCheckInterval: cfg.Sensors.CheckInterval,
		WebTLSEnabled:       cfg.Web.TLS.Enabled,
		SensorAPITLSEnabled: cfg.SensorAPI.TLS.Enabled,
		SessionDuration:     cfg.Auth.SessionDuration,
		Retention:           retentionCfg,
		Notifications:       notificationsCfg,
		Reports:             reportsCfg,
		RuntimeConfig: map[string]map[string]interface{}{
			"Web listener":                  {"host": cfg.Web.Host, "port": cfg.Web.Port, "tls.enabled": cfg.Web.TLS.Enabled, "tls.min_version": cfg.Web.TLS.MinVersion, "tls.cipher_suites": cfg.Web.TLS.CipherSuites},
			"Sensor API":                    {"host": cfg.SensorAPI.Host, "port": cfg.SensorAPI.Port, "tls.enabled": cfg.SensorAPI.TLS.Enabled, "tls.min_version": cfg.SensorAPI.TLS.MinVersion, "tls.cipher_suites": cfg.SensorAPI.TLS.CipherSuites},
			"Database":                      {"host": cfg.Database.Host, "port": cfg.Database.Port, "name": cfg.Database.Name, "user": cfg.Database.User, "sslmode": cfg.Database.SSLMode},
			"Authentication":                {"session_duration": cfg.Auth.SessionDuration.String(), "bootstrap_username": cfg.Auth.BootstrapUsername},
			"Sensors":                       {"offline_after": cfg.Sensors.OfflineAfter.String(), "check_interval": cfg.Sensors.CheckInterval.String()},
			"Analysis":                      {"enabled": cfg.Analysis.Enabled, "allow_import": cfg.Analysis.AllowImport, "upload_directory": cfg.Analysis.UploadDirectory, "max_upload_size_mb": cfg.Analysis.MaxUploadSizeMB, "job_timeout": cfg.Analysis.JobTimeout.String(), "retain_pcap": cfg.Analysis.RetainPCAP.String()},
			"SIEM":                          {"enabled": cfg.SIEM.Enabled, "url": cfg.SIEM.URL, "export_alerts": cfg.SIEM.ExportAlerts, "export_audit": cfg.SIEM.ExportAudit, "source": cfg.SIEM.Source, "timeout": cfg.SIEM.Timeout.String(), "retry_interval": cfg.SIEM.RetryInterval.String(), "batch_size": cfg.SIEM.BatchSize, "max_attempts": cfg.SIEM.MaxAttempts, "tls.insecure_skip_verify": cfg.SIEM.TLS.InsecureSkipVerify, "tls.ca_cert_file": cfg.SIEM.TLS.CACertFile, "tls.client_cert_file": cfg.SIEM.TLS.ClientCertFile, "tls.server_name": cfg.SIEM.TLS.ServerName},
			"Vulnerability":                 {"enabled": cfg.Vulnerability.Enabled, "csv_path": cfg.Vulnerability.CSVPath},
			"Database retention":            {"enabled": cfg.DatabaseRetention.Enabled, "interval": cfg.DatabaseRetention.Interval.String(), "telemetry_days": cfg.DatabaseRetention.TelemetryDays, "alerts_days": cfg.DatabaseRetention.AlertsDays, "audit_days": cfg.DatabaseRetention.AuditDays, "max_database_size_gb": cfg.DatabaseRetention.MaxDatabaseSizeGB, "target_database_size_gb": cfg.DatabaseRetention.TargetDatabaseSizeGB, "delete_batch_size": cfg.DatabaseRetention.DeleteBatchSize},
			"Notifications":                 {"enabled": cfg.Notifications.Enabled, "min_severity": cfg.Notifications.MinSeverity, "email.enabled": cfg.Notifications.Email.Enabled, "email.smtp_host": cfg.Notifications.Email.SMTPHost, "email.smtp_port": cfg.Notifications.Email.SMTPPort, "email.username": cfg.Notifications.Email.Username, "email.from": cfg.Notifications.Email.From, "email.to": cfg.Notifications.Email.To, "email.use_tls": cfg.Notifications.Email.UseTLS, "webhook.enabled": cfg.Notifications.Webhook.Enabled, "webhook.url": cfg.Notifications.Webhook.URL},
			"Reports":                       {"enabled": cfg.Reports.Enabled, "schedule": cfg.Reports.Schedule, "day_of_week": cfg.Reports.DayOfWeek, "hour_utc": cfg.Reports.HourUTC, "recipients": cfg.Reports.Recipients},
			"Sensor-side security features": {"configuration_file": "sensor.config.yaml", "tcp_reassembly": "capture.tcp_reassembly", "threat_intelligence": "detect.threatintel.enabled plus Central-managed feeds", "ot_value_anomaly": "detect.otvalueanomaly", "lateral_movement": "detect.lateralmovement", "c2_correlation": "detect.c2correlation"},
		},
	}
	exporter, err := siem.New(siem.Config{
		Enabled: cfg.SIEM.Enabled, URL: cfg.SIEM.URL, ExportAlerts: cfg.SIEM.ExportAlerts,
		ExportAudit: cfg.SIEM.ExportAudit, BearerToken: cfg.SIEM.BearerToken, Headers: cfg.SIEM.Headers,
		Timeout: cfg.SIEM.Timeout, RetryInterval: cfg.SIEM.RetryInterval, BatchSize: cfg.SIEM.BatchSize,
		MaxAttempts: cfg.SIEM.MaxAttempts, InsecureSkipVerify: cfg.SIEM.TLS.InsecureSkipVerify,
		CACertFile: cfg.SIEM.TLS.CACertFile, ClientCertFile: cfg.SIEM.TLS.ClientCertFile,
		ClientKeyFile: cfg.SIEM.TLS.ClientKeyFile, ServerName: cfg.SIEM.TLS.ServerName,
	}, repo)
	if err != nil {
		log.Fatalf("SIEM exporter initialization failed: %v", err)
	}
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	go exporter.Run(workerCtx)
	go srv.RunThreatIntelFeeds(workerCtx)

	// Nothing else flips a sensor's status away from whatever it last
	// reported in a heartbeat — if a sensor's process dies, its host loses
	// power, or the network to it drops, Central would otherwise show it
	// as "online" forever. This sweep is what makes the Sensors tab
	// actually reflect reality once a sensor stops checking in.
	go func() {
		ticker := time.NewTicker(cfg.Sensors.CheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				offlineIDs, err := repo.MarkOffline(workerCtx, cfg.Sensors.OfflineAfter)
				if err != nil {
					log.Printf("mark stale sensors offline: %v", err)
					continue
				}
				for _, id := range offlineIDs {
					if err := repo.InsertAuditLog(workerCtx, central.AuditEntry{
						Action: "sensor went offline", Success: true, SensorID: id,
					}); err != nil {
						log.Printf("audit_log insert failed: %v", err)
					}
				}
			}
		}
	}()

	// See internal/central/retention.go for exactly what this does and
	// doesn't touch. Runs once shortly after startup (so a long-idle
	// Central doesn't wait a full interval before its first sweep), then
	// on cfg.DatabaseRetention.Interval from there.
	go func() {
		if !retentionCfg.Enabled {
			return
		}
		select {
		case <-workerCtx.Done():
			return
		case <-time.After(2 * time.Minute):
		}
		repo.RunRetention(workerCtx, retentionCfg)
		ticker := time.NewTicker(cfg.DatabaseRetention.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				repo.RunRetention(workerCtx, retentionCfg)
			}
		}
	}()

	// Check immediately and then every 15 minutes. GenerateAndDispatchReport is
	// idempotent for the anchored weekly slot, so frequent checks are safe and a
	// Central restart during the configured hour can no longer make the report
	// disappear for an entire week.
	go func() {
		if !reportsCfg.Enabled {
			return
		}
		run := func() {
			// Delivery retries are independent of the one-hour weekly generation
			// window. A temporary SMTP outage must not strand a saved report until
			// the operator notices it manually.
			if err := srv.RetryPendingReportDeliveries(workerCtx); err != nil {
				log.Printf("scheduled report delivery retry failed: %v", err)
			}
			start, end, due := central.DueReportWindow(reportsCfg, time.Now())
			if !due {
				return
			}
			if err := srv.GenerateAndDispatchReport(workerCtx, start, end); err != nil {
				log.Printf("scheduled report generation failed: %v", err)
			}
		}
		run()
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
	webAddr := fmt.Sprintf("%s:%d", cfg.Web.Host, cfg.Web.Port)
	sensorAddr := fmt.Sprintf("%s:%d", cfg.SensorAPI.Host, cfg.SensorAPI.Port)
	log.Printf("OTLens Central web/API listener: %s", webAddr)
	log.Printf("OTLens Central sensor API listener: %s", sensorAddr)
	log.Printf("PostgreSQL: %s:%d database=%s user=%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.Name, cfg.Database.User)

	errCh := make(chan error, 2)
	go func() {
		errCh <- srv.StartWeb(webAddr, cfg.Web.TLS.Enabled, cfg.Web.TLS.CertFile, cfg.Web.TLS.KeyFile, 0, nil)
	}()
	go func() {
		errCh <- srv.StartSensorAPI(sensorAddr, cfg.SensorAPI.TLS.Enabled, cfg.SensorAPI.TLS.CertFile, cfg.SensorAPI.TLS.KeyFile, 0, nil)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatal(err)
		}
	case <-stop:
		log.Println("OTLens Central shutting down")
		workerCancel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("central shutdown: %v", err)
		}
	}
}
