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

	srv := &central.Server{
		Repo: repo, ManagementToken: cfg.Auth.ManagementToken, SensorToken: cfg.Auth.SensorToken,
		SIEMSource: cfg.SIEM.Source, AuditExport: cfg.SIEM.Enabled && cfg.SIEM.ExportAudit,
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
