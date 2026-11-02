// Package cli implements the "colimander db" commands.
package cli

import (
	"strings"
	"path/filepath"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/vepsala/colimander/internal/pgproxy/admin"
	"github.com/vepsala/colimander/internal/pgproxy/approval"
	"github.com/vepsala/colimander/internal/pgproxy/certs"
	"github.com/vepsala/colimander/internal/pgproxy/config"
	"github.com/vepsala/colimander/internal/pgproxy/proxy"
	"github.com/vepsala/colimander/internal/pgproxy/store"
)

// defaultConfigPath is the config the Colimander daemon runs the proxy with, so
// these commands manage the same connections as the app. A relative default would
// create a separate, empty registry in whatever directory they're run from.
func defaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".colimander", "db.yaml")
}

func hasConfigFlag(args []string) bool {
	for _, a := range args {
		if a == "-config" || a == "--config" || strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config=") {
			return true
		}
	}
	return false
}

// Run dispatches "colimander db" subcommands.
func Run(args []string) error {
	cmd := "help"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	if (cmd == "connections" || cmd == "conn" || cmd == "serve") && !hasConfigFlag(args) {
		if _, err := os.Stat(defaultConfigPath()); err != nil {
			return fmt.Errorf("%s doesn't exist yet. Run `colimander broker start` first, or pass -config", defaultConfigPath())
		}
	}
	switch cmd {
	case "serve":
		runServe(args)
	case "connections", "conn":
		runConnections(args)
	case "detect-pii":
		runDetectPII(args)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		return fmt.Errorf("unknown db command %q", cmd)
	}
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `colimander db - PII-masking, approval-gating PostgreSQL proxy

Commands:
  serve         Run the proxy and admin UI
  connections   Manage connections: add | list | rotate | resume | rm
  detect-pii    Suggest PII rules to review for an upstream database
`)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "path to the configuration file")
	debug := fs.Bool("debug", false, "enable debug logging")
	exitWithStdin := fs.Bool("exit-with-stdin", false, "exit when stdin closes, so a parent's death stops this process")
	_ = fs.Parse(args)

	log := newLogger(*debug)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("configuration error", "err", err)
		os.Exit(1)
	}

	adminToken := os.Getenv("PGPROXY_ADMIN_TOKEN")
	st, err := store.Open(store.Options{Path: cfg.Database, MasterKeyFile: cfg.MasterKeyFile, LegacySecret: adminToken})
	if err != nil {
		log.Error("open registry failed", "err", err, "path", cfg.Database)
		os.Exit(1)
	}
	defer st.Close()
	logStartup(log, st.Startup(), cfg.MasterKeyFile)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *exitWithStdin {
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			stop()
		}()
	}

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

	startAdmin := true
	switch {
	case cfg.AdminSocket != "":
		log.Info("admin UI on private socket", "path", cfg.AdminSocket)
	case adminToken != "":
		log.Info("admin UI authentication enabled (PGPROXY_ADMIN_TOKEN)")
	case isLoopback(cfg.AdminListen):
		log.Warn("admin UI is UNAUTHENTICATED; set PGPROXY_ADMIN_TOKEN to require a token", "addr", cfg.AdminListen)
	default:
		log.Error("refusing to start admin UI on a non-loopback address without PGPROXY_ADMIN_TOKEN", "addr", cfg.AdminListen)
		startAdmin = false
	}

	// Sweep expired connections and rotate due passwords periodically (and once
	// at startup). Expired credentials already fail auth via GetByUsername;
	// this reclaims the rows and performs scheduled rotations.
	sweep(st, log)
	go sweepLoop(ctx, st, log)

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
			if cfg.TLS.Mode == "self_signed" {
				adminSrv.UnverifiedTLS()
			}
			var err error
			if cfg.AdminSocket != "" {
				err = adminSrv.ServeSocket(ctx, cfg.AdminSocket)
			} else {
				err = adminSrv.ListenAndServe(ctx, cfg.AdminListen)
			}
			if err != nil {
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

// logStartup surfaces what opening the registry did to its secrets.
func logStartup(log *slog.Logger, r store.StartupReport, keyFile string) {
	if r.KeyCreated {
		log.Info("created master key; keep it out of backups alongside the database", "path", keyFile)
	}
	if r.BackupExcludeErr != nil {
		log.Warn("could not exclude master key from Time Machine", "path", keyFile, "err", r.BackupExcludeErr)
	}
	if r.PermsFixed {
		log.Warn("master key was readable by other users; restricted to owner. Treat it as exposed", "path", keyFile)
	}
	if r.Migrated > 0 {
		log.Info("encrypted existing connection secrets", "connections", r.Migrated)
	}
	if r.PasswordsCleared > 0 {
		log.Warn("some agent passwords could not be carried over; they still work but can't be displayed until rotated", "connections", r.PasswordsCleared)
	}
	if r.ScrubPending {
		log.Warn("old plaintext not yet purged from the database files; will retry on next start")
	}
}

// sweepLoop runs sweep once a minute until ctx is done.
func sweepLoop(ctx context.Context, st *store.Store, log *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep(st, log)
		}
	}
}

// sweep deletes expired connections, then rotates the password of every
// connection whose automatic rotation is due. In-flight proxied sessions are
// untouched; the old password simply stops authenticating new ones.
func sweep(st *store.Store, log *slog.Logger) {
	now := time.Now().UTC()
	if n, err := st.DeleteExpired(now); err != nil {
		log.Warn("expiry sweep failed", "err", err)
	} else if n > 0 {
		log.Info("swept expired connections", "count", n)
	}
	rotated, err := st.RotateDue(now)
	for _, r := range rotated {
		log.Info("connection password rotated automatically",
			"id", r.ID, "name", r.Name, "username", r.AgentUsername,
			"next_rotation", r.NextRotationAt.Format(time.RFC3339))
	}
	if err != nil {
		log.Warn("automatic rotation failed", "err", err)
	}
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
