package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SentinelSIEM/sentinel-siem/internal/config"
	"github.com/SentinelSIEM/sentinel-siem/internal/ingest"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize/parsers"
	"github.com/SentinelSIEM/sentinel-siem/internal/store"
)

func main() {
	configPath := flag.String("config", "sentinel.toml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize parser registry with all known parsers.
	registry := normalize.NewRegistry()
	registry.Register(parsers.NewSentinelEDRParser())
	engine := normalize.NewEngine(registry)

	log.Printf("Registered parsers: %v", registry.SourceTypes())

	// Initialize Elasticsearch store.
	esStore, err := store.New(cfg.Elasticsearch)
	if err != nil {
		log.Fatalf("Failed to create Elasticsearch store: %v", err)
	}

	// Ensure index template exists.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := esStore.EnsureTemplate(ctx); err != nil {
		log.Printf("Warning: failed to ensure index template (ES may be unavailable): %v", err)
	} else {
		log.Println("Elasticsearch index template ensured")
	}

	// Build the ingest pipeline: HTTP → normalize → ES.
	pipeline := ingest.NewPipeline(engine, esStore, cfg.Elasticsearch.IndexPrefix)
	listener := ingest.NewHTTPListener(cfg.Ingest, pipeline.Handle)

	srv := &http.Server{
		Addr:         listener.ListenAddr(),
		Handler:      listener.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown.
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Printf("sentinel-ingest listening on %s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-done
	fmt.Println("\nShutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Shutdown error: %v", err)
	}
	fmt.Println("Stopped.")
}
