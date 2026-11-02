package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/vepsala/colimander/internal/pgproxy/approval"
	"github.com/vepsala/colimander/internal/pgproxy/config"
	"github.com/vepsala/colimander/internal/pgproxy/policy"
	"github.com/vepsala/colimander/internal/pgproxy/store"
)

// These tests run real queries through the proxy against a real PostgreSQL. Set
// PGPROXY_TEST_ADMIN_URL to a superuser URL on a throwaway database:
//
//	docker run --rm -d -e POSTGRES_PASSWORD=x -p 127.0.0.1:15439:5432 postgres:16
//	PGPROXY_TEST_ADMIN_URL=postgres://postgres:x@127.0.0.1:15439/postgres go test ./internal/proxy

const fixture = `
DROP SEQUENCE IF EXISTS s1;
DROP TABLE IF EXISTS users, products CASCADE;
DROP FUNCTION IF EXISTS get_email(int);
DROP VIEW IF EXISTS renamed_v;
DROP ROLE IF EXISTS agent_test;
CREATE ROLE agent_test LOGIN PASSWORD 'agentpw';
CREATE TABLE users(id int primary key, email text, name text, notes text, birth date, status text);
INSERT INTO users VALUES
  (1,'alice@example.com','Alice Fake','call +358401234567 or bob@leak.example','1990-01-02','active'),
  (2,'bobby@example.com','Bob Fake','ok','1985-05-06','active');
CREATE TABLE products(id int primary key, sku text, info text);
INSERT INTO products VALUES (1,'SKU-1','contact sales@shop.example');
CREATE VIEW renamed_v AS SELECT id, email AS contact_x FROM users;
CREATE FUNCTION get_email(i int) RETURNS text LANGUAGE sql AS 'SELECT email FROM users WHERE id = i';
GRANT ALL ON ALL TABLES IN SCHEMA public TO agent_test;
GRANT EXECUTE ON FUNCTION get_email(int) TO agent_test;
`

type fakeApprover struct{ approve atomic.Bool }

func (f *fakeApprover) Approve(context.Context, approval.Request) approval.Decision {
	if f.approve.Load() {
		return approval.Decision{Approved: true, Reason: "test"}
	}
	return approval.Decision{Approved: false, Reason: "test denied"}
}

type harness struct {
	t        *testing.T
	st       *store.Store
	addr     string
	approver *fakeApprover
	conn     *store.Connection
	password string
}

func setup(t *testing.T, input store.CreateInput) *harness {
	t.Helper()
	adminURL := os.Getenv("PGPROXY_TEST_ADMIN_URL")
	if adminURL == "" {
		t.Skip("PGPROXY_TEST_ADMIN_URL not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	admin, err := pgconn.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, fixture).ReadAll(); err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse(adminURL)
	u.User = url.UserPassword("agent_test", "agentpw")
	q := u.Query()
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()

	dir := t.TempDir()
	st, err := store.Open(store.Options{Path: filepath.Join(dir, "r.db"), MasterKeyFile: filepath.Join(dir, "master.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	input.Name = "t"
	input.UpstreamURL = u.String()
	input.GateMutations = true
	conn, password, err := st.Create(input)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	approver := &fakeApprover{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(&config.Config{Listen: addr, HashSalt: "s", RedactString: "[REDACTED]", SchemaFunction: "pgproxy_schema"}, st, approver, nil, log)
	go func() { _ = srv.ListenAndServe(ctx) }()
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return &harness{t: t, st: st, addr: addr, approver: approver, conn: conn, password: password}
}

func (h *harness) connect() (*pgconn.PgConn, error) {
	host, port, _ := net.SplitHostPort(h.addr)
	return pgconn.Connect(context.Background(), "host="+host+" port="+port+" user="+h.conn.AgentUsername+
		" password="+h.password+" dbname=postgres sslmode=disable")
}

func (h *harness) mustConnect() *pgconn.PgConn {
	h.t.Helper()
	c, err := h.connect()
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// run returns all result text, or the error text.
func run(c *pgconn.PgConn, sql string) (string, error) {
	results, err := c.Exec(context.Background(), sql).ReadAll()
	var b strings.Builder
	for _, r := range results {
		for _, row := range r.Rows {
			for _, v := range row {
				b.Write(v)
				b.WriteByte('|')
			}
		}
	}
	return b.String(), err
}

// secrets are the real values that must never come back.
var secrets = []string{"alice@", "ALICE@", "bobby@", "BOBBY@", "bob@leak", "Alice Fake", "Bob Fake", "358401234567", "1990-01-02"}

func assertNoSecrets(t *testing.T, label, text string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(text, s) {
			t.Errorf("%s leaked %q: %s", label, s, text)
		}
	}
}

// piiRules are the rules most of these tests run with. Nothing is masked without one.
var piiRules = []policy.PIIRule{
	{Name: "email", Table: "users", Action: "redact"},
	{Name: "name", Table: "users", Action: "redact"},
	{Name: "notes", Table: "users", Action: "redact"},
	{Name: "birth", Table: "users", Action: "redact"},
}

// TestPreviouslyLeakingQueries is the table that showed name matching wasn't
// enough. None of these may return a real value, by rows or by error.
func TestPreviouslyLeakingQueries(t *testing.T) {
	h := setup(t, store.CreateInput{PIIRules: piiRules})
	c := h.mustConnect()
	for _, sql := range []string{
		"select email, name, birth, notes from users",
		"select * from users",
		"select email as e from users",
		"select x from (select email as x from users) s",
		"with c as (select email as x from users) select x from c",
		"select email || '' from users",
		"select upper(email) from users",
		"select birth::text from users",
		"select u from users u",
		"select u::text from users u",
		"select to_jsonb(u) from users u",
		"select string_agg(email, ',') from users",
		"select cast(email as int) from users",
		"select notes from users",
		"select name from users",
		"select email as x from users union select 'a'",
		"select (select email from users limit 1) as x",
		"select contact_x from renamed_v", // gap in column rules; scanner catches it
	} {
		text, err := run(c, sql)
		if err != nil {
			text += " ERROR: " + err.Error()
		}
		assertNoSecrets(t, sql, text)
	}
}

func TestUsefulQueriesStillWork(t *testing.T) {
	h := setup(t, store.CreateInput{PIIRules: piiRules})
	c := h.mustConnect()
	cases := map[string]string{
		"select count(*) from users":                          "2|",
		"select count(email) from users":                      "2|",
		"select id from users where email like 'alice%'":      "1|",
		"select id, status from users order by id limit 1":    "1|active|",
		"select max(id), lower(status) from users group by 2": "2|active|",
		"select sku from products":                            "SKU-1|",
		"select md5(sku) from products":                       "",
		"select to_jsonb(p)->>'sku' from products p":          "SKU-1|",
	}
	for sql, want := range cases {
		got, err := run(c, sql)
		if err != nil {
			t.Errorf("%s: %v", sql, err)
			continue
		}
		if want != "" && got != want {
			t.Errorf("%s = %q, want %q", sql, got, want)
		}
	}
}

func TestScannerCoversTablesWithoutPIIColumns(t *testing.T) {
	h := setup(t, store.CreateInput{})
	c := h.mustConnect()
	got, err := run(c, "select info from products")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "sales@shop") || !strings.Contains(got, "[REDACTED:email]") {
		t.Errorf("got %q", got)
	}
	events, _ := h.st.SecurityEvents(10)
	if len(events) == 0 || events[0].Kind != store.EventScrubbed {
		t.Errorf("events = %+v", events)
	}
}

func TestPreparedStatementsAreGuarded(t *testing.T) {
	h := setup(t, store.CreateInput{PIIRules: piiRules})
	c := h.mustConnect()
	ctx := context.Background()

	r := c.ExecParams(ctx, "select to_jsonb(u) from users u where id = $1", [][]byte{[]byte("1")}, nil, nil, nil).Read()
	if r.Err == nil || !strings.Contains(r.Err.Error(), "select explicit columns") {
		t.Errorf("err = %v", r.Err)
	}
	for _, format := range []int16{0, 1} {
		r = c.ExecParams(ctx, "select email as e, notes from users where id = $1", [][]byte{[]byte("1")}, nil, nil, []int16{format}).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		for _, v := range r.Rows[0] {
			assertNoSecrets(t, "prepared", string(v))
		}
	}
}

func TestWritesNeedApprovalAndSessionStaysReadOnly(t *testing.T) {
	h := setup(t, store.CreateInput{})
	c := h.mustConnect()

	if _, err := run(c, "update products set sku = 'x'"); err == nil {
		t.Error("write should be denied")
	}
	// A write can't hide behind a leading read.
	if _, err := run(c, "select 1; delete from products"); err == nil {
		t.Error("multi-statement write should be denied")
	}
	if got, _ := run(c, "select count(*) from products"); got != "1|" {
		t.Errorf("row was changed: %q", got)
	}
	if _, err := run(c, "select nextval('x')"); err == nil {
		t.Error("expected an error")
	}

	h.approver.approve.Store(true)
	if _, err := run(c, "update products set sku = 'approved'"); err != nil {
		t.Fatalf("approved write: %v", err)
	}
	if got, _ := run(c, "select sku from products"); got != "approved|" {
		t.Errorf("got %q", got)
	}
	if got, _ := run(c, "show default_transaction_read_only"); got != "on|" {
		t.Errorf("read-only should return after an approved write: %q", got)
	}

	// An approved write in a transaction that rolls back restores it too.
	if _, err := run(c, "begin"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(c, "update products set sku = 'rolled back'"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(c, "rollback"); err != nil {
		t.Fatal(err)
	}
	run(c, "select 1")
	if got, _ := run(c, "show default_transaction_read_only"); got != "on|" {
		t.Errorf("read-only should return after a rollback: %q", got)
	}
}

func TestReadOnlyStopsAWriteTheClassifierMisses(t *testing.T) {
	h := setup(t, store.CreateInput{})
	c := h.mustConnect()
	// setval looks like a read, so nothing asks for approval. Read-only mode stops it.
	admin, err := pgconn.Connect(context.Background(), os.Getenv("PGPROXY_TEST_ADMIN_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	if _, err := admin.Exec(context.Background(), "DROP SEQUENCE IF EXISTS s1; CREATE SEQUENCE s1; GRANT ALL ON s1 TO agent_test").ReadAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := run(c, "select setval('s1', 5)"); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("err = %v", err)
	}
}

func TestCustomFunctionNeedsApproval(t *testing.T) {
	h := setup(t, store.CreateInput{PIIRules: piiRules})
	c := h.mustConnect()
	if _, err := run(c, "select get_email(1)"); err == nil {
		t.Error("custom function should need approval")
	}
	h.approver.approve.Store(true)
	got, err := run(c, "select get_email(1)")
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "custom function", got)
}

func TestSuperuserUpstreamIsRefused(t *testing.T) {
	h := setup(t, store.CreateInput{})
	conn, password, err := h.st.Create(store.CreateInput{Name: "su", UpstreamURL: os.Getenv("PGPROXY_TEST_ADMIN_URL") + "?sslmode=disable", GateMutations: true})
	if err != nil {
		t.Fatal(err)
	}
	h.conn, h.password = conn, password
	_, err = h.connect()
	if err == nil || !strings.Contains(err.Error(), "superuser") {
		t.Errorf("err = %v", err)
	}
}

func TestTripwireSuspendsAllSessionsUntilResumed(t *testing.T) {
	h := setup(t, store.CreateInput{})
	first, second := h.mustConnect(), h.mustConnect()

	_, err := run(first, "select pg_read_file('/etc/passwd')")
	if err == nil || !strings.Contains(err.Error(), "suspended") {
		t.Fatalf("err = %v", err)
	}
	// The other open session is gone too.
	if _, err := run(second, "select 1"); err == nil {
		t.Error("second session should be closed")
	}
	if _, err := h.connect(); err == nil || !strings.Contains(err.Error(), "suspended") {
		t.Errorf("reconnect err = %v", err)
	}

	// The query is kept for investigation, but encrypted.
	events, _ := h.st.SecurityEvents(5)
	if len(events) == 0 || events[0].Kind != store.EventSuspended || !strings.Contains(events[0].Query, "pg_read_file") {
		t.Errorf("events = %+v", events)
	}

	oldPassword := h.password
	newPassword, err := h.st.Resume(h.conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.connect(); err == nil {
		t.Error("old password must stay dead after resume")
	}
	h.password = newPassword
	c := h.mustConnect()
	if _, err := run(c, "select 1"); err != nil {
		t.Errorf("resumed connection: %v", err)
	}
	_ = oldPassword
}

func TestRepeatedBlocksTrip(t *testing.T) {
	h := setup(t, store.CreateInput{PIIRules: piiRules})
	c := h.mustConnect()
	var err error
	for i := 0; i < tripStrikes-1; i++ {
		if _, err = run(c, "select to_jsonb(u) from users u"); err == nil || strings.Contains(err.Error(), "suspended") {
			t.Fatalf("attempt %d: err = %v", i, err)
		}
	}
	if _, err = run(c, "select to_jsonb(u) from users u"); err == nil || !strings.Contains(err.Error(), "suspended") {
		t.Errorf("final attempt err = %v", err)
	}
}

func TestColumnsAreOnlyMaskedByARule(t *testing.T) {
	h := setup(t, store.CreateInput{})
	c := h.mustConnect()
	got, err := run(c, "select name, status from users where id = 1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Alice Fake|active|" {
		t.Errorf("got %q", got)
	}
}

func TestStrictAllAndSafeRelations(t *testing.T) {
	h := setup(t, store.CreateInput{StrictAll: true})
	c := h.mustConnect()
	if _, err := run(c, "select to_jsonb(p) from products p"); err == nil {
		t.Error("strict_all should block JSON on an unreviewed table")
	}

	h2 := setup(t, store.CreateInput{StrictAll: true, SafeRelations: []string{"products"}})
	c2 := h2.mustConnect()
	if _, err := run(c2, "select to_jsonb(p) from products p"); err != nil {
		t.Errorf("safe table: %v", err)
	}
}
