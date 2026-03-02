// DSSP Gateway — Reference Implementation
//
// Attestation verification is controlled by DSSP_ATTESTATION_MODE:
//   - "simulated" (default): accepts any attestation (dev/CI only)
//   - "verify": real SGX DCAP / Nitro quote verification
//
// Usage:
//
//	DSSP_PORT=8080 DSSP_LOG_LEVEL=info go run .
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dssp-protocol/gateway/internal/attestation"
	"github.com/dssp-protocol/gateway/internal/audit"
	"github.com/dssp-protocol/gateway/internal/handler"
	"github.com/dssp-protocol/gateway/internal/storage"
	"github.com/dssp-protocol/gateway/internal/store"
	"github.com/dssp-protocol/gateway/internal/types"
)

func main() {
	port := envOrDefault("DSSP_PORT", "8080")
	storageAdapter := envOrDefault("DSSP_STORAGE_ADAPTER", "memory")
	docStorageBackend := envOrDefault("DSSP_DOC_STORAGE", "noop")
	logLevel := envOrDefault("DSSP_LOG_LEVEL", "info")
	attestationMode := envOrDefault("DSSP_ATTESTATION_MODE", "simulated")

	logger := setupLogger(logLevel)
	slog.SetDefault(logger)

	logger.Info("DSSP Gateway starting",
		"dssp_version", types.DSPVersion,
		"port", port,
		"storage_adapter", storageAdapter,
		"doc_storage", docStorageBackend,
		"attestation_mode", attestationMode,
		"log_level", logLevel,
	)

	var dataStore store.Store
	switch storageAdapter {
	case "memory":
		dataStore = store.NewMemoryStore()
		logger.Info("using in-memory storage (data will not persist across restarts)")
	default:
		logger.Error("unsupported storage adapter", "adapter", storageAdapter)
		fmt.Fprintf(os.Stderr, "Unsupported storage adapter: %s. Supported: memory\n", storageAdapter)
		os.Exit(1)
	}

	var docStorage storage.Adapter
	switch docStorageBackend {
	case "noop", "":
		docStorage = storage.NewNoopAdapter()
		logger.Info("using noop document storage (no real storage backend)")
	case "minio":
		minioCfg := storage.MinIOConfig{
			Endpoint:  envOrDefault("MINIO_ENDPOINT", "localhost:9000"),
			AccessKey: envOrDefault("MINIO_ACCESS_KEY", ""),
			SecretKey: envOrDefault("MINIO_SECRET_KEY", ""),
			Bucket:    envOrDefault("MINIO_BUCKET", "dssp-documents"),
			Prefix:    envOrDefault("MINIO_PREFIX", ""),
			UseSSL:    envOrDefault("MINIO_USE_SSL", "false") == "true",
		}

		var err error
		docStorage, err = storage.NewMinIOAdapter(minioCfg)
		if err != nil {
			logger.Error("failed to create MinIO storage adapter", "error", err)
			fmt.Fprintf(os.Stderr, "Failed to create MinIO adapter: %v\n", err)
			os.Exit(1)
		}
		logger.Info("using MinIO document storage",
			"endpoint", minioCfg.Endpoint,
			"bucket", minioCfg.Bucket,
			"prefix", minioCfg.Prefix,
			"use_ssl", minioCfg.UseSSL,
		)
	default:
		logger.Error("unsupported document storage backend", "backend", docStorageBackend)
		fmt.Fprintf(os.Stderr, "Unsupported document storage backend: %s. Supported: noop, minio\n", docStorageBackend)
		os.Exit(1)
	}

	var attMode attestation.Mode
	switch attestationMode {
	case "verify":
		attMode = attestation.ModeVerify
		logger.Info("attestation verification ENABLED - real quote verification active")
	default:
		attMode = attestation.ModeSimulated
		logger.Warn("attestation verification SIMULATED - NOT suitable for production")
	}
	verifier := attestation.New(attMode, logger)

	chain := audit.NewChain()
	genesis, err := chain.NewEvent(
		"ledger.genesis",
		audit.SystemActor(),
		&types.AuditSubject{Type: "ledger"},
		map[string]interface{}{
			"reason":  "DSSP Gateway reference implementation started",
			"gateway": "reference-impl-go",
			"version": types.DSPVersion,
		},
		audit.SuccessOutcome(),
	)
	if err != nil {
		logger.Error("failed to create genesis event", "error", err)
		os.Exit(1)
	}
	if err := dataStore.AppendEvent(genesis); err != nil {
		logger.Error("failed to store genesis event", "error", err)
		os.Exit(1)
	}
	logger.Info("audit chain initialized",
		"genesis_event_id", genesis.EventID,
		"genesis_hash", genesis.EventHash.Value[:16]+"...",
	)

	h := handler.New(dataStore, chain, logger, docStorage, verifier)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      withMiddleware(mux, logger),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("HTTP server listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	<-done
	logger.Info("shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("shutdown error", "error", err)
	}

	logger.Info("DSSP Gateway stopped")
}

func withMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func envOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func setupLogger(level string) *slog.Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
}
