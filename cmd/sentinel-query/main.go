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

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
	"github.com/SentinelSIEM/sentinel-siem/internal/config"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize"
	"github.com/SentinelSIEM/sentinel-siem/internal/query"
	"github.com/SentinelSIEM/sentinel-siem/internal/sources"
	"github.com/SentinelSIEM/sentinel-siem/internal/store"
)

func main() {
	configPath := flag.String("config", "sentinel.toml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize Elasticsearch store.
	esStore, err := store.New(cfg.Elasticsearch)
	if err != nil {
		log.Fatalf("Failed to create Elasticsearch store: %v", err)
	}

	// Ensure dedicated indices exist.
	ctx := context.Background()
	if err := esStore.EnsureSourceIndex(ctx); err != nil {
		log.Printf("Warning: failed to ensure source index: %v", err)
	}

	// Initialize API key store.
	apiKeyIndex := esStore.Prefix() + "-api-keys"
	keyStore := common.NewAPIKeyStore(esStore, apiKeyIndex)
	if err := keyStore.LoadAll(ctx); err != nil {
		log.Printf("Warning: failed to load API keys: %v", err)
	}

	// Initialize normalization engine (for parser testing).
	registry := normalize.NewRegistry()
	engine := normalize.NewEngine(registry)

	// Initialize source service and handler.
	sourceService := sources.NewService(esStore, keyStore, esStore.SourceIndexName())
	sourceHandler := sources.NewAPIHandler(sourceService, engine)

	// Create store adapter that maps store.SearchRawResult → query.SearchRawResult.
	searcher := &storeAdapter{store: esStore}

	// Default index pattern from config prefix.
	defaultIndex := cfg.Elasticsearch.IndexPrefix + "-events-*"

	// Create query API handler.
	apiHandler := query.NewAPIHandler(searcher, defaultIndex)

	// Build router with middleware.
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.Query.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-API-Key"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Routes.
	r.Get("/api/v1/health", apiHandler.HandleHealth)
	r.Post("/api/v1/query", apiHandler.HandleQuery)

	// Source management routes.
	sourceHandler.Routes(r)

	// Server.
	addr := fmt.Sprintf("%s:%d", cfg.Query.Addr, cfg.Query.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown.
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Printf("sentinel-query listening on %s\n", addr)
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

// storeAdapter adapts store.Store to the query.Searcher interface,
// mapping store.SearchRawResult → query.SearchRawResult to avoid import cycles.
type storeAdapter struct {
	store *store.Store
}

func (a *storeAdapter) SearchRaw(ctx context.Context, index string, body map[string]any) (*query.SearchRawResult, error) {
	result, err := a.store.SearchRaw(ctx, index, body)
	if err != nil {
		return nil, err
	}
	return &query.SearchRawResult{
		Total:  result.Total,
		Hits:   result.Hits,
		Aggs:   result.Aggs,
		TookMs: result.TookMs,
	}, nil
}
