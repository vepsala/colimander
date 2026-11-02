// Package proxy implements a PostgreSQL wire-protocol proxy. Clients connect
// with a generated agent username/password; the proxy routes each connection to
// the upstream database registered for that username, anonymizes configured PII
// columns, and gates mutations and oversized reads behind an approval step.
package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vepsala/colimander/internal/pgproxy/approval"
	"github.com/vepsala/colimander/internal/pgproxy/config"
	"github.com/vepsala/colimander/internal/pgproxy/store"
)

// Server accepts client connections and proxies them to upstream databases.
type Server struct {
	cfg       *config.Config
	store     *store.Store
	approver  approval.Approver
	tlsConfig *tls.Config
	log       *slog.Logger
	connSeq   atomic.Uint64

	mu       sync.Mutex
	sessions map[int64]map[*session]struct{} // live sessions by connection id
	strikes  map[int64][]time.Time           // recent blocked statements
	catalogs map[int64]*cachedCatalog
}

// New constructs a Server. The approver is shared with the admin server so the
// dashboard can resolve pending requests. tlsConfig enables TLS termination on
// the proxy port when non-nil.
func New(cfg *config.Config, st *store.Store, approver approval.Approver, tlsConfig *tls.Config, log *slog.Logger) *Server {
	return &Server{
		cfg:       cfg,
		store:     st,
		approver:  approver,
		tlsConfig: tlsConfig,
		log:       log,
		sessions:  map[int64]map[*session]struct{}{},
		strikes:   map[int64][]time.Time{},
		catalogs:  map[int64]*cachedCatalog{},
	}
}

// ListenAndServe binds the listen address and serves connections until ctx is
// cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.log.Info("postgres proxy listening", "addr", s.cfg.Listen)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.log.Warn("accept failed", "err", err)
				continue
			}
		}
		id := s.connSeq.Add(1)
		go func() {
			sess := &session{
				srv:        s,
				conn:       conn,
				id:         id,
				log:        s.log.With("conn", id, "client", conn.RemoteAddr().String()),
				statements: map[string]*preparedStmt{},
				portals:    map[string]*portal{},
			}
			sess.serve(ctx)
		}()
	}
}
