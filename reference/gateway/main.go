// DSP Gateway — Reference Implementation (Go)
//
// A minimal DSP Gateway that demonstrates the full protocol flow:
//
//  1. Register manifests and contracts (from document owner)
//  2. Handle agent sessions (attestation verification, token issuance)
//  3. Receive and validate results against contract rules
//  4. Enforce privacy budgets and numeric precision policies
//  5. Maintain an auditable Merkle-chained event log
//
// IMPORTANT: This is a REFERENCE IMPLEMENTATION for development and testing.
// Attestation verification is SIMULATED. Production deployments MUST use
// real hardware attestation (SGX, SEV-SNP, TDX, Nitro).
//
// Usage:
//
//	DSP_PORT=8080 DSP_LOG_LEVEL=info go run .
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

	"github.com/dsp-protocol/gateway/internal/audit"
	"github.com/dsp-protocol/gateway/internal/handler"
	"github.com/dsp-protocol/gateway/internal/storage"
	"github.com/dsp-protocol/gateway/internal/store"
	"github.com/dsp-protocol/gateway/internal/types"
)

func main() {
	// ── Configuration from environment ────────────────────────
	port := envOrDefault("DSP_PORT", "8080")
	storageAdapter := envOrDefault("DSP_STORAGE_ADAPTER", "memory")
	docStorageBackend := envOrDefault("DSP_DOC_STORAGE", "noop") // noop | minio
	logLevel := envOrDefault("DSP_LOG_LEVEL", "info")

	// ── Logger ────────────────────────────────────────────────
	logger := setupLogger(logLevel)
	slog.SetDefault(logger)

	logger.Info("DSP Gateway starting",
		"dsp_version", types.DSPVersion,
		"port", port,
		"storage_adapter", storageAdapter,
		"doc_storage", docStorageBackend,
		"log_level", logLevel,
	)

	// ── Storage ───────────────────────────────────────────────
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

	// ── Document storage adapter ─────────────────────────────
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
			Bucket:    envOrDefault("MINIO_BUCKET", "dsp-documents"),
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

	// ── Audit chain ───────────────────────────────────────────
	chain := audit.NewChain()

	// Emit genesis event.
	genesis, err := chain.NewEvent(
		"ledger.genesis",
		audit.SystemActor(),
		&types.AuditSubject{Type: "ledger"},
		map[string]interface{}{
			"reason":  "DSP Gateway reference implementation started",
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

	// ── HTTP handler ──────────────────────────────────────────
	h := handler.New(dataStore, chain, logger, docStorage)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Wrap with middleware.
	wrapped := withMiddleware(mux, logger)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      wrapped,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// ── Graceful shutdown ─────────────────────────────────────
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("HTTP server listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal.
	<-done
	logger.Info("shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("shutdown error", "error", err)
	}

	logger.Info("DSP Gateway stopped")
}

// ── Middleware ─────────────────────────────────────────────────

func withMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// CORS headers for development.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Wrap writer to capture status code.
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

// ── Helpers ───────────────────────────────────────────────────

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
