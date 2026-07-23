package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/central"
)

func main() {
	// PostgreSQL is intentionally colocated with OTLens Central in the
	// default deployment. Override the DSN when PostgreSQL is remote.
	dsn := os.Getenv("OTLENS_POSTGRES_DSN")
	if dsn == "" {
		dsn = "postgres://otlens:change-me@127.0.0.1:5432/otlens?sslmode=disable"
	}

	addr := os.Getenv("OTLENS_CENTRAL_ADDR")
	if addr == "" {
		addr = ":9090"
	}

	repo, err := central.OpenPostgres(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer repo.Close()

	srv := &central.Server{
		Repo:  repo,
		Token: os.Getenv("OTLENS_CENTRAL_TOKEN"),
	}

	log.Printf("OTLens Central listening on %s", addr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(addr)
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("central shutdown: %v", err)
		}
	}
}
