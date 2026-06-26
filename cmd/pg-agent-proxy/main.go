// Command pg-agent-proxy is a PostgreSQL wire-protocol proxy that routes each
// agent connection to a registered upstream database, anonymizes PII columns,
// and gates mutations and oversized reads behind an approval step.
//
// Usage:
//
//	pg-agent-proxy serve        -config config.yaml          (default)
//	pg-agent-proxy connections  add|list|rotate|rm ...
//	pg-agent-proxy detect-pii   -upstream <conn-string>
//	pg-agent-proxy version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/kotisivukamu/pg-agent-proxy/internal/admin"
	"github.com/kotisivukamu/pg-agent-proxy/internal/approval"
	"github.com/kotisivukamu/pg-agent-proxy/internal/certs"
	"github.com/kotisivukamu/pg-agent-proxy/internal/config"
	"github.com/kotisivukamu/pg-agent-proxy/internal/proxy"
	"github.com/kotisivukamu/pg-agent-proxy/internal/store"
)

var version = "dev"

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "serve":
		runServe(args)
	case "connections", "conn":
		runConnections(args)
	case "detect-pii":
		runDetectPII(args)
	case "version":
		fmt.Println("pg-agent-proxy", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `pg-agent-proxy - a PII-anonymizing, approval-gating PostgreSQL proxy

Commands:
  serve         Run the proxy and admin UI (default)
  connections   Manage connections: add | list | rotate | rm
  detect-pii    Suggest PII columns for an upstream database
  version       Print the version
`)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "path to the configuration file")
	debug := fs.Bool("debug", false, "enable debug logging")
	_ = fs.Parse(args)

	log := newLogger(*debug)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("configuration error", "err", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.Database)
	if err != nil {
		log.Error("open registry failed", "err", err, "path", cfg.Database)
		os.Exit(1)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TLS provider shared by the proxy port and the admin HTTPS listener (which
	// also answers ACME challenges).
	certProvider, err := certs.New(cfg.TLS, log)
	if err != nil {
		log.Error("tls setup failed", "err", err)
		os.Exit(1)
	}
	proxyTLS := certProvider.ProxyTLSConfig()
	adminTLS := certProvider.AdminTLSConfig()

	// One approver shared by the proxy and the admin server, so dashboard-mode
	// approvals raised by the proxy can be resolved from the UI.
	approver := approval.New(cfg.Approval)
	broker, _ := approver.(*approval.Broker)
	if broker != nil {
		log.Info("approvals are resolved from the admin dashboard", "timeout", cfg.Approval.Timeout)
	}

	adminToken := os.Getenv("PGPROXY_ADMIN_TOKEN")
	startAdmin := true
	switch {
	case adminToken != "":
		log.Info("admin UI authentication enabled (PGPROXY_ADMIN_TOKEN)")
	case isLoopback(cfg.AdminListen):
		log.Warn("admin UI is UNAUTHENTICATED; set PGPROXY_ADMIN_TOKEN to require a token", "addr", cfg.AdminListen)
	default:
		log.Error("refusing to start admin UI on a non-loopback address without PGPROXY_ADMIN_TOKEN", "addr", cfg.AdminListen)
		startAdmin = false
	}

	var wg sync.WaitGroup
	if startAdmin {
		wg.Add(1)
		go func() {
			defer wg.Done()
			advertise := cfg.PublicAddr
			if advertise == "" {
				advertise = cfg.Listen
			}
			adminSrv := admin.New(st, advertise, adminToken, broker, adminTLS, log)
			if err := adminSrv.ListenAndServe(ctx, cfg.AdminListen); err != nil {
				log.Error("admin server stopped", "err", err)
			}
		}()
	}

	srv := proxy.New(cfg, st, approver, proxyTLS, log)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Error("proxy stopped", "err", err)
		stop()
	}
	wg.Wait()
}

// isLoopback reports whether a listen address binds only to the loopback
// interface (so an unauthenticated admin UI is not network-reachable).
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newLogger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
