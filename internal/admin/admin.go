// Package admin serves the management web UI and JSON API for creating and
// rotating proxy connections. It is unauthenticated by design — bind it to
// localhost or place it behind your own auth.
package admin

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
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
	"github.com/kotisivukamu/pg-agent-proxy/internal/detect"
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
	tlsConfig *tls.Config      // when set, serve HTTPS (and answer ACME challenges)
	sslMode   string           // sslmode shown in agent connection strings
}

// New constructs an admin Server. proxyListen is the proxy's PostgreSQL listen
// address, used to build the agent-facing connection strings. token is the
// master admin token; if empty the admin surface is unauthenticated. broker is
// the dashboard approval broker, or nil when approvals are not dashboard-backed.
// tlsConfig, when non-nil, makes the admin server serve HTTPS and answer ACME
// TLS-ALPN-01 challenges.
func New(st *store.Store, proxyListen, token string, broker *approval.Broker, tlsConfig *tls.Config, log *slog.Logger) *Server {
	sslMode := "disable"
	if tlsConfig != nil {
		sslMode = "verify-full"
	}
	return &Server{
		store:     st,
		log:       log,
		advertise: advertiseAddr(proxyListen),
		token:     token,
		broker:    broker,
		tlsConfig: tlsConfig,
		sslMode:   sslMode,
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
	mux.Handle("POST /api/detect-pii", s.requireAuth(s.handleDetectPII))
	mux.Handle("PUT /api/connections/{id}", s.requireAuth(s.handleUpdate))
	mux.Handle("POST /api/connections/{id}/rotate", s.requireAuth(s.handleRotate))
	mux.Handle("POST /api/connections/{id}/detect-pii", s.requireAuth(s.handleDetectPIIForConn))
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
		TLSConfig:         s.tlsConfig,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	scheme := "http"
	serve := srv.ListenAndServe
	if s.tlsConfig != nil {
		scheme = "https"
		serve = func() error { return srv.ListenAndServeTLS("", "") }
	}
	s.log.Info("admin UI listening", "url", scheme+"://"+advertiseAddr(addr))
	if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// connectionDTO is the JSON shape returned for a connection. This admin API is
// token-gated; it returns the agent password and full connection strings so
// they can be copied to agents at any time (these credentials are revocable).
type connectionDTO struct {
	ID               int64            `json:"id"`
	Name             string           `json:"name"`
	AgentUsername    string           `json:"agent_username"`
	AgentPassword    string           `json:"agent_password"`
	UpstreamURL      string           `json:"upstream_url"`
	MaxRows          int              `json:"max_rows"`
	GateMutations    bool             `json:"gate_mutations"`
	PIIRules         []policy.PIIRule `json:"pii_rules"`
	CreatedAt        time.Time        `json:"created_at"`
	ConnectionString string           `json:"connection_string"`
}

func (s *Server) toDTO(c store.Connection) connectionDTO {
	// Connections created before plaintext storage have no password to show;
	// leave the string empty so the UI can prompt for a rotate.
	cs := ""
	if c.AgentPassword != "" {
		cs = s.connString(c.AgentUsername, c.AgentPassword)
	}
	return connectionDTO{
		ID:               c.ID,
		Name:             c.Name,
		AgentUsername:    c.AgentUsername,
		AgentPassword:    c.AgentPassword,
		UpstreamURL:      maskURLPassword(c.UpstreamURL),
		MaxRows:          c.MaxRows,
		GateMutations:    c.GateMutations,
		PIIRules:         c.PIIRules,
		CreatedAt:        c.CreatedAt,
		ConnectionString: cs,
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

	conn, _, err := s.store.Create(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.log.Info("connection created", "name", conn.Name, "username", conn.AgentUsername)

	// conn carries the freshly minted plaintext password, so toDTO renders the
	// full connection string just like a subsequent list call would.
	writeJSON(w, http.StatusCreated, s.toDTO(*conn))
}

// handleUpdate edits a connection's policy fields (not its credentials).
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid id"))
		return
	}
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}
	in := store.UpdateInput{
		Name:          req.Name,
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
	if err := s.store.Update(id, in); err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.log.Info("connection updated", "id", id, "name", in.Name)
	w.WriteHeader(http.StatusNoContent)
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

// piiSuggestion is a deduped detection result: one column, the suggested
// action, and the tables it was found in (for the reviewer's context).
type piiSuggestion struct {
	Name   string   `json:"name"`
	Action string   `json:"action"`
	Tables []string `json:"tables"`
}

// handleDetectPII scans an ad-hoc upstream URL (used by the create form before
// the connection exists) and returns suggested PII columns.
func (s *Server) handleDetectPII(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UpstreamURL string `json:"upstream_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.UpstreamURL) == "" {
		writeError(w, http.StatusBadRequest, errors.New("upstream_url is required"))
		return
	}
	s.detectAndRespond(w, r, req.UpstreamURL)
}

// handleDetectPIIForConn scans an existing connection's stored upstream, so the
// edit modal can suggest PII columns without re-entering credentials.
func (s *Server) handleDetectPIIForConn(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid id"))
		return
	}
	conns, err := s.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	upstream := ""
	for _, c := range conns {
		if c.ID == id {
			upstream = c.UpstreamURL // real (unmasked) upstream, server-side only
		}
	}
	if upstream == "" {
		writeError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	s.detectAndRespond(w, r, upstream)
}

// detectAndRespond runs a bounded schema scan and writes deduped suggestions.
func (s *Server) detectAndRespond(w http.ResponseWriter, r *http.Request, upstream string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	matches, err := detect.Scan(ctx, upstream)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("schema scan failed: %w", err))
		return
	}

	// Dedupe by column (matching is column-name based), preserving first-seen
	// order and collecting every table the column appears in.
	byCol := map[string]*piiSuggestion{}
	var order []string
	for _, m := range matches {
		sug, ok := byCol[m.Column]
		if !ok {
			sug = &piiSuggestion{Name: m.Column, Action: m.Action}
			byCol[m.Column] = sug
			order = append(order, m.Column)
		}
		if !containsString(sug.Tables, m.Table) {
			sug.Tables = append(sug.Tables, m.Table)
		}
	}
	out := make([]piiSuggestion, 0, len(order))
	for _, col := range order {
		out = append(out, *byCol[col])
	}
	writeJSON(w, http.StatusOK, out)
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
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

// maskURLPassword replaces the password in the upstream URL with "***" for
// display. Built by hand (not url.String()) so the mask is not percent-encoded.
func maskURLPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPw := u.User.Password(); !hasPw {
		return raw
	}
	masked := u.Scheme + "://" + u.User.Username() + ":***@" + u.Host + u.Path
	if u.RawQuery != "" {
		masked += "?" + u.RawQuery
	}
	return masked
}

// connString builds the agent-facing connection string.
func (s *Server) connString(username, password string) string {
	return fmt.Sprintf("postgres://%s:%s@%s/postgres?sslmode=%s",
		url.QueryEscape(username), url.QueryEscape(password), s.advertise, s.sslMode)
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
