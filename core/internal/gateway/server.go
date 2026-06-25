package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"verilock/internal/config"

	"go.uber.org/zap"
)

// Server is the Verilock HTTP gateway.
// It owns the HTTP server lifecycle — start, route, and graceful shutdown.
type Server struct {
	cfg      *config.Config
	handler  http.Handler
	log      *zap.Logger
	shutdown []func() // cleanup hooks called after HTTP drain, in registration order
}

// NewServer constructs the HTTP server, wires all routes, and applies all middleware.
// deps carries every module the handlers need — see Deps in handlers.go.
func NewServer(cfg *config.Config, deps Deps, log *zap.Logger) *Server {
	mux := http.NewServeMux()

	// cfg is no longer stored on handlers — access via deps.Config.
	h := &handlers{deps: deps, log: log}

	// Register all routes.
	// Method enforcement is done inside each handler — not at the mux level,
	// because Go's default mux does not support per-method routing.
	mux.HandleFunc("/v1/action-check", h.actionCheck) // POST — agent financial requests
	mux.HandleFunc("/v1/decision/", h.decisionPoll)   // GET  — Tier 3 poll (trailing slash catches /:id)
	mux.HandleFunc("/v1/health", h.health)            // GET  — no auth required
	mux.HandleFunc("/v1/agent/revoke", h.revokeToken) // POST — token revocation

	// Apply middleware stack (outermost = first to run on ingress).
	// Order is security-critical — do not reorder.
	//
	//  1. recoverMiddleware      — catch panics before anything else
	//  2. requestSizeMiddleware  — reject oversized bodies before any I/O
	//  3. requestIDMiddleware    — assign trace ID before logging
	//  4. globalRateLimitMiddleware — global RPS cap (agent unknown at this point)
	//  5. loggingMiddleware      — structured log with timing and status code
	//
	// Per-agent rate limiting happens inside authenticateRequest() in handlers,
	// after agent identity is established.
	wrapped := chain(mux,
		recoverMiddleware(log),
		requestSizeMiddleware(cfg),
		requestIDMiddleware(),
		globalRateLimitMiddleware(deps),
		loggingMiddleware(log),
	)

	return &Server{
		cfg:     cfg,
		handler: wrapped,
		log:     log,
	}
}

// OnShutdown registers a cleanup function to call after HTTP requests are drained.
// Functions are called in registration order — register dependencies in the
// correct teardown sequence (e.g. audit DB last, rate limiter first).
func (s *Server) OnShutdown(fn func()) {
	s.shutdown = append(s.shutdown, fn)
}

// Start begins serving HTTP requests and blocks until the server shuts down.
// Shutdown is triggered by SIGTERM or SIGINT (Ctrl+C).
// In-flight requests are given 15 seconds to complete before force-close.
// Cleanup hooks registered via OnShutdown are called after HTTP drains.
func (s *Server) Start() error {
	srv := &http.Server{
		Addr:           fmt.Sprintf(":%d", s.cfg.ServerPort),
		Handler:        s.handler,
		ReadTimeout:    time.Duration(s.cfg.ServerReadTimeoutSeconds) * time.Second,
		WriteTimeout:   time.Duration(s.cfg.ServerWriteTimeoutSeconds) * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Bind port synchronously before starting the serve goroutine.
	// This means port-in-use / permission-denied errors surface immediately,
	// not after the "listening" log line is printed.
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("gateway: failed to bind port %d: %w", s.cfg.ServerPort, err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	serveErr := make(chan error, 1)
	go func() {
		s.log.Info("verilock notary listening",
			zap.String("address", listener.Addr().String()),
			zap.String("environment", s.cfg.Environment),
		)
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	// Block until shutdown signal or fatal serve error.
	select {
	case sig := <-quit:
		s.log.Info("shutdown signal received — draining in-flight requests",
			zap.String("signal", sig.String()),
		)
	case err := <-serveErr:
		return fmt.Errorf("gateway: serve error: %w", err)
	}

	// Phase 1: drain in-flight HTTP requests (15 second grace period).
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer drainCancel()

	if err := srv.Shutdown(drainCtx); err != nil {
		s.log.Error("HTTP drain incomplete — forcing close", zap.Error(err))
		_ = srv.Close()
	}

	// Phase 2: call cleanup hooks in registration order.
	// Each hook gets 5 seconds before we move on — a stuck dependency
	// should not block the rest of the shutdown sequence.
	s.log.Info("running shutdown hooks", zap.Int("count", len(s.shutdown)))
	for _, fn := range s.shutdown {
		done := make(chan struct{})
		go func(f func()) {
			f()
			close(done)
		}(fn)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			s.log.Warn("shutdown hook timed out — skipping")
		}
	}

	s.log.Info("verilock notary shut down cleanly")
	return nil
}

// chain applies middleware in order: chain(mux, a, b, c) → a(b(c(mux)))
// The first middleware in the list is outermost (runs first on ingress).
func chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
