// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Command content-filter runs the standalone MCP content-filter HTTP
// service. It terminates the wire contract defined in
// internal/contentfilter/wire and delegates each call to the Policy
// selected by the --config file (currently "eval" or "passthrough").
//
// The binary is stateless: configuration is loaded once at startup,
// and all per-request state (LLM credentials, ticket id overrides)
// comes from either the environment or the incoming request. Rolling
// restart is the supported reload mechanism.
//
// Flags:
//
//	--config  path to the ServerConfig JSON (default /etc/content-filter/config.json)
//	--addr    listen address override (defaults to config.addr)
//	--log-level  slog log level: debug, info, warn, error (default info)
//
// Typical deployment: one Deployment per policy kind per environment,
// fronted by a ClusterIP Service whose DNS name is referenced from
// the MCPGatewayRoute's contentFilter.url field.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/contentfilter"
)

const defaultConfigPath = "/etc/content-filter/config.json"

func main() {
	cfgPath := flag.String("config", defaultConfigPath,
		"path to the content-filter ServerConfig JSON")
	addrOverride := flag.String("addr", "",
		"listen address override; takes precedence over config.addr")
	logLevel := flag.String("log-level", "info",
		"slog log level (debug, info, warn, error)")
	flag.Parse()

	log := newLogger(*logLevel)
	slog.SetDefault(log)

	if err := run(*cfgPath, *addrOverride, log); err != nil {
		log.Error("content-filter exited with error", "err", err.Error())
		os.Exit(1)
	}
}

// run is the testable entrypoint. It loads config, builds the
// policy and server, starts HTTP, and waits for SIGINT/SIGTERM. The
// graceful shutdown window gives in-flight LLM calls up to 30s to
// complete; the gateway's own timeout keeps inflight work bounded so
// this is safely generous.
func run(cfgPath, addrOverride string, log *slog.Logger) error {
	cfg, err := contentfilter.LoadServerConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if addrOverride != "" {
		cfg.Addr = addrOverride
	}

	policy, err := cfg.BuildPolicy()
	if err != nil {
		return fmt.Errorf("build policy: %w", err)
	}
	log.Info("content-filter starting",
		"policy", policy.Name(),
		"addr", cfg.Addr,
		"timeoutSeconds", cfg.TimeoutSeconds,
	)

	srv, err := contentfilter.NewServer(policy, time.Duration(cfg.TimeoutSeconds)*time.Second, log)
	if err != nil {
		return fmt.Errorf("build server: %w", err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signalCh:
		log.Info("content-filter received signal, shutting down", "signal", sig.String())
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("content-filter stopped cleanly")
	return nil
}

// newLogger builds a slog.Logger at the requested level.  Falls back
// to info on any parsing failure so an operator typo never leaves
// the service without logging.
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h).With("component", "content-filter")
}
