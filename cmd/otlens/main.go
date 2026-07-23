// Command otlens is OTLens's main entry point: loads the Linux sensor config file,
// wires up every engine via internal/app, and runs until interrupted
// (Ctrl+C / SIGTERM), flushing persisted state cleanly on the way
// out. See README.md for configuration and the API surface.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/zabojnikvlado/otlens_linux/internal/app"
	"github.com/zabojnikvlado/otlens_linux/internal/config"
	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"github.com/zabojnikvlado/otlens_linux/internal/oui"
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

	// Run until interrupted (Ctrl+C, or a service manager stopping
	// the process) instead of exiting after a fixed sleep.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	application.Shutdown()

}
