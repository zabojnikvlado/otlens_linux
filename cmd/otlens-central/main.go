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

	srv := &central.Server{Repo: repo, Token: cfg.Auth.Token}
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("OTLens Central listening on %s", addr)
	log.Printf("PostgreSQL: %s:%d database=%s user=%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.Name, cfg.Database.User)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(addr) }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatal(err)
		}
	case <-stop:
		log.Println("OTLens Central shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("central shutdown: %v", err)
		}
	}
}
