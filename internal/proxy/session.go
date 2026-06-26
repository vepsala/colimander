package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/kotisivukamu/pg-agent-proxy/internal/policy"
	"github.com/kotisivukamu/pg-agent-proxy/internal/store"
)

// preparedStmt is a client-prepared statement tracked for the extended protocol.
type preparedStmt struct {
	query     string
	kind      policy.Kind
	paramOIDs []uint32
	fields    []pgconn.FieldDescription // populated lazily on Describe
	described bool
	isSchema  bool
}

// portal is a bound statement ready to execute.
type portal struct {
	stmt          string
	paramFormats  []int16
	params        [][]byte
	resultFormats []int16
}

// session handles a single client connection for its whole lifetime.
type session struct {
	srv      *Server
	conn     net.Conn
	id       uint64
	log      *slog.Logger
	be       *pgproto3.Backend
	upstream *pgconn.PgConn
	policy   *policy.Policy
	connInfo *store.Connection

	statements map[string]*preparedStmt
	portals    map[string]*portal

	// batchFailed is set after an error in an extended-protocol batch; further
	// messages are ignored until the next Sync (per the PostgreSQL protocol).
	batchFailed bool
}

var parameterStatusKeys = []string{
	"server_version", "server_encoding", "client_encoding", "application_name",
	"DateStyle", "IntervalStyle", "TimeZone", "integer_datetimes",
	"standard_conforming_strings", "in_hot_standby",
}

func (s *session) serve(ctx context.Context) {
	defer s.conn.Close()
	s.be = pgproto3.NewBackend(s.conn, s.conn)

	if !s.startup(ctx) {
		return
	}
	defer func() {
		if s.upstream != nil {
			_ = s.upstream.Close(context.Background())
		}
	}()

	s.log.Info("session established", "connection", s.connInfo.Name)
	s.loop(ctx)
	s.log.Info("session closed")
}

// startup negotiates SSL, authenticates the client against the registry, routes
// to the matching upstream, and compiles that connection's policy.
func (s *session) startup(ctx context.Context) bool {
	var startupMsg *pgproto3.StartupMessage
	usedTLS := false
	for startupMsg == nil {
		msg, err := s.be.ReceiveStartupMessage()
		if err != nil {
			return false
		}
		switch m := msg.(type) {
		case *pgproto3.StartupMessage:
			if s.srv.tlsConfig != nil && s.srv.cfg.TLS.Required && !usedTLS {
				s.fatal("28000", "SSL connection is required")
				return false
			}
			startupMsg = m
		case *pgproto3.SSLRequest:
			if s.srv.tlsConfig == nil {
				if _, err := s.conn.Write([]byte("N")); err != nil {
					return false
				}
				continue
			}
			if _, err := s.conn.Write([]byte("S")); err != nil {
				return false
			}
			tlsConn := tls.Server(s.conn, s.srv.tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				s.log.Debug("tls handshake failed", "err", err)
				return false
			}
			s.conn = tlsConn
			s.be = pgproto3.NewBackend(tlsConn, tlsConn)
			usedTLS = true
		case *pgproto3.GSSEncRequest:
			// GSSAPI encryption is not supported; decline.
			if _, err := s.conn.Write([]byte("N")); err != nil {
				return false
			}
		default:
			return false // CancelRequest etc. are unsupported.
		}
	}

	conn := s.authenticate(startupMsg)
	if conn == nil {
		return false
	}
	s.connInfo = conn
	s.policy = conn.Policy(s.srv.cfg.HashSalt, s.srv.cfg.RedactString)
	s.log = s.log.With("connection", conn.Name)

	upstream, err := pgconn.Connect(ctx, conn.UpstreamURL)
	if err != nil {
		s.log.Error("upstream connect failed", "err", err)
		s.fatal("08006", "could not connect to upstream database")
		return false
	}
	s.upstream = upstream

	return s.completeStartup()
}

// authenticate validates the client's credentials against the registry and
// returns the matching connection, or nil on failure.
func (s *session) authenticate(startup *pgproto3.StartupMessage) *store.Connection {
	s.be.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := s.be.Flush(); err != nil {
		return nil
	}
	resp, err := s.be.Receive()
	if err != nil {
		return nil
	}
	pw, ok := resp.(*pgproto3.PasswordMessage)
	if !ok {
		s.fatal("28000", "expected password message")
		return nil
	}

	user := startup.Parameters["user"]
	conn, err := s.srv.store.GetByUsername(user)
	if err != nil || !store.VerifyPassword(conn, pw.Password) {
		s.log.Warn("authentication failed", "user", user)
		s.fatal("28P01", fmt.Sprintf("password authentication failed for user %q", user))
		return nil
	}
	return conn
}

func (s *session) completeStartup() bool {
	s.be.Send(&pgproto3.AuthenticationOk{})
	for _, key := range parameterStatusKeys {
		if val := s.upstream.ParameterStatus(key); val != "" {
			s.be.Send(&pgproto3.ParameterStatus{Name: key, Value: val})
		}
	}
	s.be.Send(&pgproto3.BackendKeyData{ProcessID: s.upstream.PID(), SecretKey: []byte{0, 0, 0, 0}})
	s.be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	return s.be.Flush() == nil
}

// loop dispatches client messages until termination. It handles both the simple
// query protocol (Query) and the extended protocol (Parse/Bind/Describe/
// Execute/Sync/Close/Flush) used by virtually all real drivers.
func (s *session) loop(ctx context.Context) {
	for {
		msg, err := s.be.Receive()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.log.Debug("receive failed", "err", err)
			}
			return
		}

		switch m := msg.(type) {
		case *pgproto3.Query:
			s.handleSimpleQuery(ctx, m.String)
		case *pgproto3.Parse:
			s.handleParse(m)
		case *pgproto3.Bind:
			s.handleBind(m)
		case *pgproto3.Describe:
			s.handleDescribe(ctx, m)
		case *pgproto3.Execute:
			s.handleExecute(ctx, m)
		case *pgproto3.Sync:
			s.batchFailed = false
			s.be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			_ = s.be.Flush()
		case *pgproto3.Close:
			s.handleClose(m)
		case *pgproto3.Flush:
			_ = s.be.Flush()
		case *pgproto3.Terminate:
			return
		default:
			s.log.Debug("ignoring unexpected message", "type", fmt.Sprintf("%T", msg))
		}
	}
}

// --- response helpers ---

func (s *session) ready() {
	s.be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	_ = s.be.Flush()
}

func (s *session) sendError(code, message string) {
	s.be.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: message})
}

func (s *session) sendQueryError(err error) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		s.be.Send(&pgproto3.ErrorResponse{
			Severity: "ERROR", Code: pgErr.Code, Message: pgErr.Message,
			Detail: pgErr.Detail, Hint: pgErr.Hint,
		})
		return
	}
	s.be.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "58000", Message: err.Error()})
}

func (s *session) fatal(code, message string) {
	s.be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: message})
	_ = s.be.Flush()
}
