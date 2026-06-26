// Package admin serves the management web UI and JSON API for creating and
// rotating proxy connections. It is unauthenticated by design — bind it to
// localhost or place it behind your own auth.
package admin

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kotisivukamu/pg-agent-proxy/internal/approval"
	"github.com/kotisivukamu/pg-agent-proxy/internal/policy"
	"github.com/kotisivukamu/pg-agent-proxy/internal/store"
)

//go:embed ui.html
var indexHTML []byte

//go:embed login.html
var loginHTML []byte

// cookieName is the session cookie holding the admin token for the web UI.
const cookieName = "pgproxy_admin"

// Server is the admin HTTP server.
type Server struct {
	store     *store.Store
	log       *slog.Logger
	advertise string           // host:port shown in connection strings
	token     string           // master token; empty means unauthenticated
	broker    *approval.Broker // dashboard approvals; nil unless mode=dashboard
}

// New constructs an admin Server. proxyListen is the proxy's PostgreSQL listen
// address, used to build the agent-facing connection strings. token is the
// master admin token; if empty the admin surface is unauthenticated. broker is
// the dashboard approval broker, or nil when approvals are not dashboard-backed.
func New(st *store.Store, proxyListen, token string, broker *approval.Broker, log *slog.Logger) *Server {
	return &Server{
		store:     st,
		log:       log,
		advertise: advertiseAddr(proxyListen),
		token:     token,
		broker:    broker,
	}
}

// Handler returns the HTTP handler for the admin surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.Handle("GET /api/connections", s.requireAuth(s.handleList))
	mux.Handle("POST /api/connections", s.requireAuth(s.handleCreate))
	mux.Handle("POST /api/connections/{id}/rotate", s.requireAuth(s.handleRotate))
	mux.Handle("DELETE /api/connections/{id}", s.requireAuth(s.handleDelete))
	mux.Handle("GET /api/approvals", s.requireAuth(s.handleApprovals))
	mux.Handle("POST /api/approvals/{id}", s.requireAuth(s.handleDecide))
	return mux
}

// authed reports whether the request carries a valid admin token, via either a
// Bearer Authorization header (automation) or the session cookie (web UI).
func (s *Server) authed(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	if h := r.Header.Get("Authorization"); h != "" {
		if t, ok := strings.CutPrefix(h, "Bearer "); ok && tokenEqual(t, s.token) {
			return true
		}
	}
	if c, err := r.Cookie(cookieName); err == nil && tokenEqual(c.Value, s.token) {
		return true
	}
	return false
}

// requireAuth wraps an API handler, returning 401 when unauthenticated.
func (s *Server) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		next(w, r)
	})
}

// handleLogin validates the submitted token and sets the session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.token == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	token := r.FormValue("token")
	if !tokenEqual(token, s.token) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(loginHTML)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s.token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isHTTPS(r),
		MaxAge:   7 * 24 * 3600,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLogout clears the session cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func tokenEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// ListenAndServe runs the admin server until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	s.log.Info("admin UI listening", "url", "http://"+advertiseAddr(addr))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !s.authed(r) {
		_, _ = w.Write(loginHTML)
		return
	}
	_, _ = w.Write(indexHTML)
}

// connectionDTO is the JSON shape returned for a connection. Secrets (password,
// upstream credentials) are only included where explicitly noted.
type connectionDTO struct {
	ID               int64            `json:"id"`
	Name             string           `json:"name"`
	AgentUsername    string           `json:"agent_username"`
	UpstreamURL      string           `json:"upstream_url"`
	MaxRows          int              `json:"max_rows"`
	GateMutations    bool             `json:"gate_mutations"`
	PIIRules         []policy.PIIRule `json:"pii_rules"`
	CreatedAt        time.Time        `json:"created_at"`
	ConnectionString string           `json:"connection_string"` // password placeholder
}

func (s *Server) toDTO(c store.Connection) connectionDTO {
	return connectionDTO{
		ID:               c.ID,
		Name:             c.Name,
		AgentUsername:    c.AgentUsername,
		UpstreamURL:      maskURLPassword(c.UpstreamURL),
		MaxRows:          c.MaxRows,
		GateMutations:    c.GateMutations,
		PIIRules:         c.PIIRules,
		CreatedAt:        c.CreatedAt,
		ConnectionString: s.connString(c.AgentUsername, "<password>"),
	}
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	conns, err := s.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]connectionDTO, 0, len(conns))
	for _, c := range conns {
		out = append(out, s.toDTO(c))
	}
	writeJSON(w, http.StatusOK, out)
}

type createRequest struct {
	Name          string           `json:"name"`
	UpstreamURL   string           `json:"upstream_url"`
	MaxRows       *int             `json:"max_rows"`
	GateMutations *bool            `json:"gate_mutations"`
	PIIRules      []policy.PIIRule `json:"pii_rules"`
}

type secretResponse struct {
	connectionDTO
	AgentPassword    string `json:"agent_password"`    // shown once
	ConnectionString string `json:"connection_string"` // includes the password
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	in := store.CreateInput{
		Name:          req.Name,
		UpstreamURL:   req.UpstreamURL,
		MaxRows:       1000,
		GateMutations: true,
		PIIRules:      req.PIIRules,
	}
	if req.MaxRows != nil {
		in.MaxRows = *req.MaxRows
	}
	if req.GateMutations != nil {
		in.GateMutations = *req.GateMutations
	}

	conn, password, err := s.store.Create(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.log.Info("connection created", "name", conn.Name, "username", conn.AgentUsername)

	writeJSON(w, http.StatusCreated, secretResponse{
		connectionDTO:    s.toDTO(*conn),
		AgentPassword:    password,
		ConnectionString: s.connString(conn.AgentUsername, password),
	})
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid id"))
		return
	}
	password, err := s.store.Rotate(id)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	conns, _ := s.store.List()
	var username string
	for _, c := range conns {
		if c.ID == id {
			username = c.AgentUsername
		}
	}
	s.log.Info("connection password rotated", "id", id)
	writeJSON(w, http.StatusOK, map[string]string{
		"agent_password":    password,
		"connection_string": s.connString(username, password),
	})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid id"))
		return
	}
	if err := s.store.Delete(id); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.log.Info("connection deleted", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// handleApprovals lists requests awaiting a dashboard decision.
func (s *Server) handleApprovals(w http.ResponseWriter, _ *http.Request) {
	if s.broker == nil {
		writeJSON(w, http.StatusOK, []approval.PendingView{})
		return
	}
	writeJSON(w, http.StatusOK, s.broker.Pending())
}

// handleDecide resolves a pending approval.
func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	if s.broker == nil {
		writeError(w, http.StatusNotFound, errors.New("dashboard approvals are not enabled"))
		return
	}
	id := r.PathValue("id")
	var body struct {
		Approved bool   `json:"approved"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.broker.Decide(id, body.Approved, body.Reason) {
		writeError(w, http.StatusNotFound, errors.New("no such pending approval (it may have timed out)"))
		return
	}
	s.log.Info("approval decided", "id", id, "approved", body.Approved)
	w.WriteHeader(http.StatusNoContent)
}

// connString builds the agent-facing connection string.
func (s *Server) connString(username, password string) string {
	return fmt.Sprintf("postgres://%s:%s@%s/postgres?sslmode=disable",
		url.QueryEscape(username), url.QueryEscape(password), s.advertise)
}

func (s *Server) writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// advertiseAddr normalizes a listen address into a host:port suitable for a
// connection string, replacing a wildcard/empty host with 127.0.0.1.
func advertiseAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "127.0.0.1:6432"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// maskURLPassword replaces the password in a postgres URL with "***".
func maskURLPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPw := u.User.Password(); hasPw {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.String()
}
