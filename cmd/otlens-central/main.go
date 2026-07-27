package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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

func main() {
	configPath := flag.String("config", defaultConfigPath(), "path to the Central Management configuration file")
	flag.Parse()

	cfg, err := config.LoadCentral(*configPath)
	if err != nil {
		log.Fatalf("configuration loading failed: %v", err)
	}

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
	repo.ConfigureSIEM(cfg.SIEM.Enabled && cfg.SIEM.ExportAlerts)

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
	if cfg.Vulnerability.Enabled && cfg.Vulnerability.CSVPath != "" {
		count, err := vulnDB.LoadCSV(cfg.Vulnerability.CSVPath)
		if err != nil {
			log.Printf("vulnerability snapshot not loaded: %v", err)
		} else {
			log.Printf("vulnerability snapshot loaded: %d advisories", count)
		}
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

	srv := &central.Server{
		Repo: repo, ManagementToken: cfg.Auth.ManagementToken, SensorToken: cfg.Auth.SensorToken,
		SIEMSource: cfg.SIEM.Source, SIEMEnabled: cfg.SIEM.Enabled, AuditExport: cfg.SIEM.Enabled && cfg.SIEM.ExportAudit,
		AnalysisEnabled: cfg.Analysis.Enabled && cfg.Analysis.AllowImport, AnalysisDir: cfg.Analysis.UploadDirectory,
		AnalysisMaxBytes:     cfg.Analysis.MaxUploadSizeMB * 1024 * 1024,
		Vuln:                 vulnDB,
		SensorOfflineAfter:   cfg.Sensors.OfflineAfter,
		SensorCheckInterval:  cfg.Sensors.CheckInterval,
		WebTLSEnabled:        cfg.Web.TLS.Enabled,
		SensorAPITLSEnabled:  cfg.SensorAPI.TLS.Enabled,
		SessionDuration:      cfg.Auth.SessionDuration,
		Retention:            retentionCfg,
		Notifications:        notificationsCfg,
		Reports:              reportsCfg,
	}
	exporter, err := siem.New(siem.Config{
		Enabled: cfg.SIEM.Enabled, URL: cfg.SIEM.URL, ExportAlerts: cfg.SIEM.ExportAlerts,
		ExportAudit: cfg.SIEM.ExportAudit, BearerToken: cfg.SIEM.BearerToken, Headers: cfg.SIEM.Headers,
		Timeout: cfg.SIEM.Timeout, RetryInterval: cfg.SIEM.RetryInterval, BatchSize: cfg.SIEM.BatchSize,
		MaxAttempts: cfg.SIEM.MaxAttempts, Source: cfg.SIEM.Source, InsecureSkipVerify: cfg.SIEM.TLS.InsecureSkipVerify,
		CACertFile: cfg.SIEM.TLS.CACertFile, ClientCertFile: cfg.SIEM.TLS.ClientCertFile,
		ClientKeyFile: cfg.SIEM.TLS.ClientKeyFile, ServerName: cfg.SIEM.TLS.ServerName,
	}, repo)
	if err != nil {
		log.Fatalf("SIEM exporter initialization failed: %v", err)
	}
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	go exporter.Run(workerCtx)

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

	// Checks once an hour whether the configured weekly slot
	// (Reports.DayOfWeek/HourUTC) is the current hour — see
	// DueReportWindow in internal/central/reports.go. Hourly is coarse
	// enough that this can't double-fire within the same due hour (it
	// only checks, doesn't track "already ran this week" separately,
	// so an hourly cadence is what keeps a single due hour from
	// producing more than one report).
	go func() {
		if !reportsCfg.Enabled {
			return
		}
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				start, end, due := central.DueReportWindow(reportsCfg, time.Now())
				if !due {
					continue
				}
				if err := srv.GenerateAndDispatchReport(workerCtx, start, end); err != nil {
					log.Printf("scheduled report generation failed: %v", err)
				}
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
