package proxy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kotisivukamu/pg-agent-proxy/internal/guard"
	"github.com/kotisivukamu/pg-agent-proxy/internal/policy"
	"github.com/kotisivukamu/pg-agent-proxy/internal/scrub"
	"github.com/kotisivukamu/pg-agent-proxy/internal/store"
)

const (
	// catalogTTL is how long a schema snapshot is used before it's reloaded, so
	// a new table is classified soon after it appears.
	catalogTTL = time.Minute
	// catalogMinRefresh limits reloads triggered by an unknown table name.
	catalogMinRefresh = 5 * time.Second

	// tripStrikes blocked statements within tripWindow suspend the connection.
	// One block is an honest mistake; a long run of them looks like probing.
	tripStrikes = 10
	tripWindow  = 5 * time.Minute

	suspendedMessage = "pg-agent-proxy: connection suspended: "
)

type cachedCatalog struct {
	cat     guard.Catalog
	origins map[origin]columnOrigin
	loaded  time.Time
}

type origin struct {
	table uint32
	attr  uint16
}

type columnOrigin struct{ table, column string }

const catalogSQL = `
SELECT c.oid::text, c.relname, c.relkind::text, a.attnum::text, a.attname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.relkind IN ('r','p','v','m','f')
  AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
ORDER BY c.oid, a.attnum`

const userFuncsSQL = `
SELECT DISTINCT lower(p.proname)
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog','information_schema')`

// loadCatalog reads the schema over a separate connection, so it can't disturb
// the agent's transaction state.
func loadCatalog(ctx context.Context, upstreamURL string) (*cachedCatalog, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgconn.Connect(ctx, upstreamURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())

	results, err := conn.Exec(ctx, catalogSQL+"; "+userFuncsSQL).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(results) != 2 {
		return nil, errors.New("unexpected catalog result")
	}

	out := &cachedCatalog{
		cat: guard.Catalog{
			Known:     true,
			Relations: map[string][]guard.Relation{},
			UserFuncs: map[string]bool{},
		},
		origins: map[origin]columnOrigin{},
		loaded:  time.Now(),
	}
	type relKey struct{ oid uint32 }
	rels := map[relKey]*guard.Relation{}
	var order []relKey
	for _, row := range results[0].Rows {
		oid64, err := strconv.ParseUint(string(row[0]), 10, 32)
		if err != nil {
			return nil, err
		}
		attr, err := strconv.ParseUint(string(row[3]), 10, 16)
		if err != nil {
			return nil, err
		}
		key := relKey{uint32(oid64)}
		rel, ok := rels[key]
		if !ok {
			rel = &guard.Relation{Name: string(row[1]), Kind: row[2][0]}
			rels[key] = rel
			order = append(order, key)
		}
		column := string(row[4])
		rel.Columns = append(rel.Columns, column)
		out.origins[origin{key.oid, uint16(attr)}] = columnOrigin{rel.Name, column}
	}
	for _, key := range order {
		rel := rels[key]
		name := strings.ToLower(rel.Name)
		out.cat.Relations[name] = append(out.cat.Relations[name], *rel)
	}
	for _, row := range results[1].Rows {
		out.cat.UserFuncs[string(row[0])] = true
	}
	return out, nil
}

// catalogFor returns a schema snapshot for the connection. If the schema can't
// be read and nothing is cached, the zero catalog makes every statement strict.
func (srv *Server) catalogFor(ctx context.Context, conn *store.Connection, maxAge time.Duration) *cachedCatalog {
	srv.mu.Lock()
	cached := srv.catalogs[conn.ID]
	srv.mu.Unlock()
	if cached != nil && time.Since(cached.loaded) < maxAge {
		return cached
	}
	fresh, err := loadCatalog(ctx, conn.UpstreamURL)
	if err != nil {
		srv.log.Warn("could not read upstream schema", "connection", conn.Name, "err", err)
		if cached != nil {
			return cached
		}
		return &cachedCatalog{origins: map[origin]columnOrigin{}, loaded: time.Now()}
	}
	srv.mu.Lock()
	srv.catalogs[conn.ID] = fresh
	srv.mu.Unlock()
	return fresh
}

// prepareUpstream refuses connections that would make the controls pointless,
// and makes the session read-only until a write is approved.
func (s *session) prepareUpstream(ctx context.Context) error {
	results, err := s.upstream.Exec(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).ReadAll()
	if err != nil {
		return fmt.Errorf("could not check the upstream role: %w", err)
	}
	if len(results) > 0 && len(results[0].Rows) > 0 && string(results[0].Rows[0][0]) == "t" {
		return errors.New("the upstream role is a superuser, which can read server files and bypass these controls; use a limited role")
	}
	if s.policy.GateMutations() {
		if _, err := s.upstream.Exec(ctx, `SET default_transaction_read_only = on`).ReadAll(); err != nil {
			return fmt.Errorf("could not enable read-only mode: %w", err)
		}
	}
	return nil
}

// enableWrites lets an approved write through read-only mode, and returns a
// function that turns read-only back on.
func (s *session) enableWrites(ctx context.Context) (func(context.Context), error) {
	if s.upstream.TxStatus() != 'I' {
		// Inside a transaction, which began read-only. PostgreSQL only allows the
		// switch before the transaction's first query; its error says so.
		_, err := s.upstream.Exec(ctx, `SET LOCAL transaction_read_only = off`).ReadAll()
		return func(context.Context) {}, err
	}
	if _, err := s.upstream.Exec(ctx, `SET default_transaction_read_only = off`).ReadAll(); err != nil {
		return nil, err
	}
	return func(ctx context.Context) {
		// A statement that opened a transaction keeps its read-write state, and a
		// ROLLBACK would undo a SET made now, so wait for the transaction to end.
		s.readOnlyPending = true
		s.restoreReadOnly(ctx)
	}, nil
}

// restoreReadOnly turns read-only mode back on once no transaction is open.
func (s *session) restoreReadOnly(ctx context.Context) {
	if !s.readOnlyPending || s.upstream.TxStatus() != 'I' {
		return
	}
	if _, err := s.upstream.Exec(ctx, `SET default_transaction_read_only = on`).ReadAll(); err != nil {
		s.log.Error("could not restore read-only mode; closing session", "err", err)
		_ = s.conn.Close()
		return
	}
	s.readOnlyPending = false
}

// check runs the guard, reloading the schema if the statement names a relation
// the snapshot doesn't know about (it may be brand new).
func (s *session) check(ctx context.Context, sql string) guard.Decision {
	s.restoreReadOnly(ctx)
	rules := guard.Rules{Policy: s.policy, StrictAll: s.connInfo.StrictAll, SafeRelations: s.connInfo.SafeRelations}
	cached := s.srv.catalogFor(ctx, s.connInfo, catalogTTL)
	decision := guard.Check(sql, rules, cached.cat)
	if len(decision.Unknown) > 0 {
		cached = s.srv.catalogFor(ctx, s.connInfo, catalogMinRefresh)
		decision = guard.Check(sql, rules, cached.cat)
	}
	return decision
}

// allowed acts on a guard decision. It returns true if the statement may run;
// otherwise it has queued the error, and the caller just stops.
func (s *session) allowed(d guard.Decision, sql string) bool {
	if d.Severity == guard.Allow && d.UserFunction && !s.policy.GateMutations() {
		d.Severity = guard.Block
		d.Message = "custom functions need approval, and this connection has approvals turned off"
	}
	switch d.Severity {
	case guard.Allow:
		return true
	case guard.Trip:
		s.srv.suspend(s, d.Message, sql)
		return false
	default:
		s.log.Warn("statement blocked", "reason", d.Message)
		if err := s.srv.store.AddSecurityEvent(s.connInfo.ID, s.connInfo.AgentUsername, store.EventBlocked, d.Message, sql); err != nil {
			s.log.Error("could not record security event", "err", err)
		}
		if s.srv.strike(s.connInfo.ID) {
			s.srv.suspend(s, fmt.Sprintf("%d statements blocked within %s", tripStrikes, tripWindow), sql)
			return false
		}
		s.sendError("42501", "pg-agent-proxy: "+d.Message)
		return false
	}
}

// strike counts a blocked statement and reports whether the limit was reached.
func (srv *Server) strike(connID int64) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	cutoff := time.Now().Add(-tripWindow)
	kept := srv.strikes[connID][:0]
	for _, t := range srv.strikes[connID] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, time.Now())
	srv.strikes[connID] = kept
	return len(kept) >= tripStrikes
}

// suspend stops a connection: its password stops working, and every open
// session is closed, since the environment may be compromised. The offending
// session gets an explanation first.
func (srv *Server) suspend(s *session, reason, sql string) {
	id, username := s.connInfo.ID, s.connInfo.AgentUsername
	s.log.Error("connection suspended by tripwire", "reason", reason)
	if err := srv.store.Suspend(id, reason); err != nil {
		s.log.Error("could not persist suspension", "err", err)
	}
	if err := srv.store.AddSecurityEvent(id, username, store.EventSuspended, reason, sql); err != nil {
		s.log.Error("could not record security event", "err", err)
	}

	s.terminated = true
	s.fatal("57P01", suspendedMessage+reason)

	srv.mu.Lock()
	sessions := make([]*session, 0, len(srv.sessions[id]))
	for other := range srv.sessions[id] {
		sessions = append(sessions, other)
	}
	delete(srv.strikes, id)
	srv.mu.Unlock()
	for _, other := range sessions {
		_ = other.conn.Close()
	}
}

func (srv *Server) register(s *session) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.sessions[s.connInfo.ID] == nil {
		srv.sessions[s.connInfo.ID] = map[*session]struct{}{}
	}
	srv.sessions[s.connInfo.ID][s] = struct{}{}
}

func (srv *Server) unregister(s *session) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.sessions[s.connInfo.ID], s)
}

// actionForField picks the mask for a result column. PostgreSQL reports where a
// plain column came from, even through aliases and subqueries, so the source
// decides. Computed columns have no source, so their name decides.
func (s *session) actionForField(fd pgconn.FieldDescription) policy.Action {
	if fd.TableOID != 0 {
		cached := s.srv.catalogFor(context.Background(), s.connInfo, catalogTTL)
		if src, ok := cached.origins[origin{fd.TableOID, fd.TableAttributeNumber}]; ok {
			return s.policy.ActionForOrigin(src.table, src.column)
		}
	}
	return s.policy.ActionFor(fd.Name)
}

// Types that can't hold free text, so the scanner skips them.
var unscannedOIDs = map[uint32]bool{
	16: true, 17: true, 20: true, 21: true, 23: true, 26: true, 700: true, 701: true,
	790: true, 1082: true, 1083: true, 1114: true, 1184: true, 1186: true, 1266: true,
	1700: true, 2950: true,
}

const (
	jsonOID  = 114
	jsonbOID = 3802
)

// scrubValue runs the scanner over one value. Text and JSON are safe to rewrite
// in either wire format. Other binary values have internal lengths that an edit
// would corrupt, so a match replaces the whole value with NULL.
func scrubValue(fd pgconn.FieldDescription, value []byte) ([]byte, []string) {
	if unscannedOIDs[fd.DataTypeOID] {
		return value, nil
	}
	out, kinds := scrub.Text(value)
	if len(kinds) == 0 {
		return value, nil
	}
	rewritable := fd.Format == 0 || policy.IsTextFamilyOID(fd.DataTypeOID) || fd.DataTypeOID == jsonOID || fd.DataTypeOID == jsonbOID
	if !rewritable {
		return nil, kinds
	}
	return out, kinds
}

func mergeKinds(into, from []string) []string {
	for _, k := range from {
		found := false
		for _, existing := range into {
			if existing == k {
				found = true
				break
			}
		}
		if !found {
			into = append(into, k)
		}
	}
	return into
}

// recordScrubbed notes that the scanner fired. This is routine, not a sign of
// compromise: it usually means a column needs a rule.
func (s *session) recordScrubbed(kinds []string, query string) {
	detail := "replaced in results: " + strings.Join(kinds, ", ")
	s.log.Warn("sensitive values replaced by scanner", "kinds", strings.Join(kinds, ","))
	if err := s.srv.store.AddSecurityEvent(s.connInfo.ID, s.connInfo.AgentUsername, store.EventScrubbed, detail, query); err != nil {
		s.log.Error("could not record security event", "err", err)
	}
}
