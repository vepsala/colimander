package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"github.com/vepsala/colimander/internal/vault"
	"os"
	"path/filepath"
	"testing"
)

const testUpstream = "postgres://dbuser:s3cret-upstream-pw@db.example.com:5433/app"

func openAt(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := Open(Options{Path: filepath.Join(dir, "r.db"), MasterKeyFile: filepath.Join(dir, "master.key")})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// assertAbsent fails if needle appears in the database or its sidecar files.
func assertAbsent(t *testing.T, dir, needle string) {
	t.Helper()
	for _, name := range []string{"r.db", "r.db-wal", "r.db-shm"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(needle)) {
			t.Errorf("%s contains plaintext %q", name, needle)
		}
	}
}

func TestMasterKeyCreatedOnFirstOpenAndReused(t *testing.T) {
	dir := t.TempDir()
	st := openAt(t, dir)
	if !st.Startup().KeyCreated {
		t.Error("first open should report a created key")
	}
	st.Close()

	keyPath := filepath.Join(dir, "master.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o, want 600", info.Mode().Perm())
	}
	before, _ := os.ReadFile(keyPath)

	st = openAt(t, dir)
	defer st.Close()
	if st.Startup().KeyCreated {
		t.Error("second open must reuse the key")
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(before, after) {
		t.Error("key changed between opens")
	}
}

func TestSecretsEncryptedAtRestAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := openAt(t, dir)
	conn, password, err := st.Create(CreateInput{Name: "x", UpstreamURL: testUpstream})
	if err != nil {
		t.Fatal(err)
	}
	if conn.UpstreamTarget != "dbuser@db.example.com:5433/app" {
		t.Errorf("target = %q", conn.UpstreamTarget)
	}
	st.Close()

	assertAbsent(t, dir, "s3cret-upstream-pw")
	assertAbsent(t, dir, password)

	st = openAt(t, dir)
	defer st.Close()
	got, err := st.GetByUsername(conn.AgentUsername)
	if err != nil {
		t.Fatal(err)
	}
	if got.UpstreamURL != testUpstream {
		t.Errorf("upstream = %q", got.UpstreamURL)
	}
	if !VerifyPassword(got, password) {
		t.Error("password should verify")
	}
	conns, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if conns[0].UpstreamURL != testUpstream || conns[0].AgentPassword != password {
		t.Errorf("List did not decrypt secrets: %+v", conns[0])
	}
}

func TestMissingKeyRefusesAndDoesNotRegenerate(t *testing.T) {
	dir := t.TempDir()
	st := openAt(t, dir)
	st.Close()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}

	_, err := Open(Options{Path: filepath.Join(dir, "r.db"), MasterKeyFile: keyPath})
	if !errors.Is(err, ErrMasterKeyMissing) {
		t.Fatalf("err = %v, want ErrMasterKeyMissing", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Error("a replacement key must not be generated")
	}
}

func TestWrongKeyRefuses(t *testing.T) {
	dir := t.TempDir()
	st := openAt(t, dir)
	st.Close()
	other := filepath.Join(t.TempDir(), "other.key")
	if _, err := vault.CreateKey(other); err != nil {
		t.Fatal(err)
	}
	_, err := Open(Options{Path: filepath.Join(dir, "r.db"), MasterKeyFile: other})
	if !errors.Is(err, ErrMasterKeyWrong) {
		t.Fatalf("err = %v, want ErrMasterKeyWrong", err)
	}
}

func TestMalformedKeyRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "master.key"), []byte("too-short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Path: filepath.Join(dir, "r.db"), MasterKeyFile: filepath.Join(dir, "master.key")}); err == nil {
		t.Fatal("expected a malformed key to be refused")
	}
}

func TestOpenKeyPermissionsAreRestricted(t *testing.T) {
	dir := t.TempDir()
	st := openAt(t, dir)
	st.Close()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	st = openAt(t, dir)
	defer st.Close()
	if !st.Startup().PermsFixed {
		t.Error("should report fixed permissions")
	}
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCiphertextCannotMoveBetweenConnections(t *testing.T) {
	dir := t.TempDir()
	st := openAt(t, dir)
	defer st.Close()
	a, _, err := st.Create(CreateInput{Name: "a", UpstreamURL: "postgres://u:pa@h/a"})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := st.Create(CreateInput{Name: "b", UpstreamURL: "postgres://u:pb@h/b"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE connections SET upstream_enc = (SELECT upstream_enc FROM connections WHERE id = ?) WHERE id = ?`, a.ID, b.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := st.GetByUsername(b.AgentUsername); err == nil {
		t.Error("a swapped ciphertext must fail closed")
	}
	conns, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if conns[0].UpstreamURL == "" || conns[1].UpstreamURL != "" {
		t.Errorf("List should keep the good row and blank the damaged one: %+v", conns)
	}
}

// writeLegacyDB builds a registry as the previous version left it: plaintext
// upstream_url and an agent password encrypted under the admin token.
func writeLegacyDB(t *testing.T, dir, adminToken, password string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "r.db")+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`
CREATE TABLE connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, agent_username TEXT NOT NULL UNIQUE,
  agent_password_hash TEXT NOT NULL, agent_password_enc TEXT NOT NULL DEFAULT '',
  upstream_url TEXT NOT NULL, max_rows INTEGER NOT NULL DEFAULT 1000, gate_mutations INTEGER NOT NULL DEFAULT 1,
  pii_rules TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, expires_at TEXT NOT NULL DEFAULT '',
  rotate_every INTEGER NOT NULL DEFAULT 0, rotated_at TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte("pgproxy:agent-password:v1:" + adminToken))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	enc := base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(password), nil))

	if _, err := db.Exec(`INSERT INTO connections (name, agent_username, agent_password_hash, agent_password_enc, upstream_url, created_at)
VALUES ('old', 'old_abc', 'unused-hash', ?, ?, '2026-01-01T00:00:00Z')`, enc, testUpstream); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyRegistryIsMigrated(t *testing.T) {
	dir := t.TempDir()
	writeLegacyDB(t, dir, "admin-token", "legacy-agent-password")

	st, err := Open(Options{Path: filepath.Join(dir, "r.db"), MasterKeyFile: filepath.Join(dir, "master.key"), LegacySecret: "admin-token"})
	if err != nil {
		t.Fatal(err)
	}
	r := st.Startup()
	if r.Migrated != 1 || r.PasswordsCleared != 0 || r.ScrubPending {
		t.Errorf("report = %+v", r)
	}
	st.Close()

	assertAbsent(t, dir, "s3cret-upstream-pw")

	// The admin token is no longer needed, and a reopen migrates nothing.
	st = openAt(t, dir)
	defer st.Close()
	if st.Startup().Migrated != 0 {
		t.Error("migration should only run once")
	}
	conns, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if conns[0].UpstreamURL != testUpstream || conns[0].AgentPassword != "legacy-agent-password" {
		t.Errorf("migrated row = %+v", conns[0])
	}
	if conns[0].UpstreamTarget != "dbuser@db.example.com:5433/app" {
		t.Errorf("target = %q", conns[0].UpstreamTarget)
	}

	// Older schemas declare upstream_url NOT NULL with no default.
	if _, _, err := st.Create(CreateInput{Name: "new", UpstreamURL: testUpstream}); err != nil {
		t.Errorf("create after migration: %v", err)
	}
}

func TestLegacyPasswordWithoutTokenIsClearedAndReported(t *testing.T) {
	dir := t.TempDir()
	writeLegacyDB(t, dir, "admin-token", "legacy-agent-password")

	st := openAt(t, dir) // no LegacySecret
	defer st.Close()
	r := st.Startup()
	if r.Migrated != 1 || r.PasswordsCleared != 1 {
		t.Errorf("report = %+v", r)
	}
	conns, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if conns[0].AgentPassword != "" || conns[0].UpstreamURL != testUpstream {
		t.Errorf("row = %+v", conns[0])
	}
}

func TestSecurityEventQueriesAreEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	st := openAt(t, dir)
	conn, _, err := st.Create(CreateInput{Name: "x", UpstreamURL: testUpstream})
	if err != nil {
		t.Fatal(err)
	}
	const query = "select 'unique-event-query-marker'"
	if err := st.AddSecurityEvent(conn.ID, conn.AgentUsername, EventBlocked, "blocked", query); err != nil {
		t.Fatal(err)
	}
	events, err := st.SecurityEvents(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Query != query {
		t.Errorf("events = %+v", events)
	}
	st.Close()
	assertAbsent(t, dir, "unique-event-query-marker")
}

func TestSuspensionSurvivesReopenAndResumeRotates(t *testing.T) {
	dir := t.TempDir()
	st := openAt(t, dir)
	conn, oldPassword, err := st.Create(CreateInput{Name: "x", UpstreamURL: testUpstream})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Suspend(conn.ID, "tripped"); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st = openAt(t, dir)
	defer st.Close()
	got, err := st.GetByUsername(conn.AgentUsername)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Suspended() || got.SuspendReason != "tripped" {
		t.Errorf("connection = %+v", got)
	}

	newPassword, err := st.Resume(conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err = st.GetByUsername(conn.AgentUsername)
	if err != nil {
		t.Fatal(err)
	}
	if got.Suspended() {
		t.Error("should be active after resume")
	}
	if VerifyPassword(got, oldPassword) || !VerifyPassword(got, newPassword) {
		t.Error("resume must replace the password")
	}
}
