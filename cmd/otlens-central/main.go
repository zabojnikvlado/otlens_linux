package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/central"
	"github.com/zabojnikvlado/otlens_linux/internal/config"
	"github.com/zabojnikvlado/otlens_linux/internal/siem"
	"github.com/zabojnikvlado/otlens_linux/internal/vuln"
)

func main() {
	configPath := flag.String("config", `C:\ProgramData\OTLens\config.yaml`, "path to the Central Management configuration file")
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
				if err := repo.MarkOffline(workerCtx, cfg.Sensors.OfflineAfter); err != nil {
					log.Printf("mark stale sensors offline: %v", err)
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
