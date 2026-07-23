// Command otlens is OTLens's main entry point: loads the Linux sensor config file,
// wires up every engine via internal/app, and runs until interrupted
// (Ctrl+C / SIGTERM), flushing persisted state cleanly on the way
// out. See README.md for configuration and the API surface.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"github.com/zabojnikvlado/otlens_linux/internal/topology"
	"syscall"

	"github.com/zabojnikvlado/otlens_linux/internal/app"
	"github.com/zabojnikvlado/otlens_linux/internal/config"
	"github.com/zabojnikvlado/otlens_linux/internal/detect"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"github.com/zabojnikvlado/otlens_linux/internal/oui"
	"github.com/zabojnikvlado/otlens_linux/internal/syncagent"
	"go.uber.org/zap"
)

func main() {
	configPath := flag.String("config", "/etc/otlens/config.yaml", "path to the Linux sensor configuration file")
	flag.Parse()

	// Config has to load before the logger can be initialized (its
	// level comes from cfg.Logging.Level), so a config failure here
	// is the one place in the program that can't log through zap.
	cfg, err := config.Load(*configPath)

	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration loading failed: %v\n", err)
		os.Exit(1)
	}

	if err := logger.Init(
		cfg.Logging.Level,
		cfg.Logging.Output,
		logger.RotationConfig{
			Enabled:    cfg.Logging.Rotation.Enabled,
			MaxSizeMB:  cfg.Logging.Rotation.MaxSizeMB,
			MaxBackups: cfg.Logging.Rotation.MaxBackups,
			MaxAgeDays: cfg.Logging.Rotation.MaxAgeDays,
			Compress:   cfg.Logging.Rotation.Compress,
		},
	); err != nil {
		panic(err)
	}

	defer logger.Sync()

	logger.Log.Info("OTLens starting")

	logger.Log.Info(
		"Configuration loaded",
		zap.String("logging_level", cfg.Logging.Level),
		zap.Strings("logging_output", cfg.Logging.Output),
	)

	logger.Log.Info(
		"Capture interface",
		zap.String(
			"interface",
			cfg.Capture.Interface,
		),
	)

	logger.Log.Info(
		"OTLens ready",
	)

	if cfg.OUI.CSVPath != "" {

		if err := oui.LoadCSV(cfg.OUI.CSVPath); err != nil {

			logger.Log.Warn(
				"Loading OUI vendor database failed, falling back to built-in list",
				zap.String("path", cfg.OUI.CSVPath),
				zap.Error(err),
			)

		} else {

			logger.Log.Info(
				"OUI vendor database loaded",
				zap.String("path", cfg.OUI.CSVPath),
			)
		}
	}

	application, err := app.New(cfg)

	if err != nil {

		logger.Log.Fatal(
			"Application initialization failed",
			zap.Error(err),
		)
	}

	application.Start()

	ctx, cancel := context.WithCancel(context.Background())
	if cfg.Central.Enabled {
		hostname, _ := os.Hostname()
		client := syncagent.New(syncagent.Config{
			BaseURL: cfg.Central.URL, Token: cfg.Central.Token, SensorID: cfg.Central.SensorID,
			Name: cfg.Central.Name, SiteID: cfg.Central.SiteID, Version: cfg.App.Version, Hostname: hostname,
			Interval: cfg.Central.Interval, Timeout: cfg.Central.Timeout, InsecureSkipVerify: cfg.Central.InsecureSkipVerify,
		})
		marshal := func(v interface{}) (json.RawMessage, error) {
			b, err := json.Marshal(v)
			return json.RawMessage(b), err
		}
		worker := &syncagent.Worker{Client: client, Detect: application.DetectEngine, ApplyCommand: func(command management.Command) {
			switch command.Type {
			case "asset.confirm":
				application.AssetEngine.Confirm(command.Target)
			case "asset.delete":
				application.AssetEngine.Delete(command.Target)
			case "alert.approve":
				application.DetectEngine.ApproveAlert(command.Target)
			case "alert.confirm":
				application.DetectEngine.ConfirmAlert(command.Target)
			case "rule.add", "rule.upsert":
				var rule detect.Rule
				if err := json.Unmarshal([]byte(command.Target), &rule); err != nil {
					log.Printf("OTLens invalid %s command: %v", command.Type, err)
					break
				}
				if command.Type == "rule.add" {
					if _, err := application.DetectEngine.AddPolicyRule(&rule); err != nil {
						log.Printf("OTLens rule creation failed: %v", err)
					}
				} else if err := application.DetectEngine.UpsertPolicyRule(&rule); err != nil {
					log.Printf("OTLens rule update failed: %v", err)
				}
			case "rule.toggle":
				var request struct {
					ID      string `json:"id"`
					Enabled bool   `json:"enabled"`
				}
				if err := json.Unmarshal([]byte(command.Target), &request); err == nil {
					application.DetectEngine.ToggleRule(request.ID, request.Enabled)
				}
			case "rule.delete":
				application.DetectEngine.DeleteRule(command.Target)
			}
		}, Snapshot: func() (management.TelemetrySnapshot, error) {
			graph := topology.Build(application.AssetEngine.GetAll(), application.FlowEngine.GetAll(), application.StoreEngine.GetTags(), cfg.ICS.ModbusPort, cfg.ICS.S7Port, cfg.Deception.HoneypotThreshold)
			graphJSON, err := marshal(graph)
			if err != nil {
				return management.TelemetrySnapshot{}, err
			}
			tagsJSON, err := marshal(application.StoreEngine.GetTags())
			if err != nil {
				return management.TelemetrySnapshot{}, err
			}
			changesJSON, err := marshal(application.StoreEngine.GetValueChanges())
			if err != nil {
				return management.TelemetrySnapshot{}, err
			}
			eventsJSON, err := marshal(application.StoreEngine.GetControlEvents())
			if err != nil {
				return management.TelemetrySnapshot{}, err
			}
			alertsJSON, err := marshal(application.DetectEngine.GetAlerts())
			if err != nil {
				return management.TelemetrySnapshot{}, err
			}
			baselineJSON, err := marshal(application.DetectEngine.BaselineStatus())
			if err != nil {
				return management.TelemetrySnapshot{}, err
			}
			rulesJSON, err := marshal(application.DetectEngine.GetRules())
			if err != nil {
				return management.TelemetrySnapshot{}, err
			}
			return management.TelemetrySnapshot{SensorID: cfg.Central.SensorID, CapturedAt: time.Now().UTC(), Topology: graphJSON, Tags: tagsJSON, TagChanges: changesJSON, TagEvents: eventsJSON, Alerts: alertsJSON, Baseline: baselineJSON, Rules: rulesJSON}, nil
		}}
		go worker.Run(ctx)
		logger.Log.Info("Central synchronization started", zap.String("url", cfg.Central.URL), zap.String("sensor_id", cfg.Central.SensorID))
	}

	// Run until interrupted (Ctrl+C, or a service manager stopping
	// the process) instead of exiting after a fixed sleep.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	cancel()

	application.Shutdown()

}
