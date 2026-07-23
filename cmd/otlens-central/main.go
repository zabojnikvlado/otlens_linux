package main

import (
	"github.com/zabojnikvlado/otlens_linux/internal/central"
	"log"
	"os"
)

func main() {
	dsn := os.Getenv("OTLENS_POSTGRES_DSN")
	if dsn == "" {
		log.Fatal("OTLENS_POSTGRES_DSN is required")
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
	srv := &central.Server{Repo: repo, Token: os.Getenv("OTLENS_CENTRAL_TOKEN")}
	log.Printf("OTLens Central listening on %s", addr)
	if err := srv.Start(addr); err != nil {
		log.Fatal(err)
	}
}
