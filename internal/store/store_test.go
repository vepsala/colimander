package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kotisivukamu/pg-agent-proxy/internal/policy"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestCreateAndAuthenticate(t *testing.T) {
	st := openTest(t)

	conn, password, err := st.Create(CreateInput{
		Name:          "Billing DB",
		UpstreamURL:   "postgres://u:p@host/db",
		MaxRows:       500,
		GateMutations: true,
		PIIRules:      []policy.PIIRule{{Name: "email", Action: "hash"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if conn.AgentUsername == "" || password == "" {
		t.Fatal("expected generated username and password")
	}
	if conn.AgentUsername[:7] != "billing" {
		t.Errorf("username should derive from name, got %q", conn.AgentUsername)
	}

	// Routing lookup + password verification.
	got, err := st.GetByUsername(conn.AgentUsername)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(got, password) {
		t.Error("correct password should verify")
	}
	if VerifyPassword(got, "wrong") {
		t.Error("wrong password must not verify")
	}
	if got.MaxRows != 500 || !got.GateMutations || len(got.PIIRules) != 1 {
		t.Errorf("connection fields not round-tripped: %+v", got)
	}
}

func TestRotateInvalidatesOldPassword(t *testing.T) {
	st := openTest(t)
	conn, oldPassword, err := st.Create(CreateInput{Name: "x", UpstreamURL: "postgres://u:p@h/d"})
	if err != nil {
		t.Fatal(err)
	}
	newPassword, err := st.Rotate(conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByUsername(conn.AgentUsername)
	if VerifyPassword(got, oldPassword) {
		t.Error("old password must stop working after rotate")
	}
	if !VerifyPassword(got, newPassword) {
		t.Error("new password should verify")
	}
}

func TestDeleteAndMissing(t *testing.T) {
	st := openTest(t)
	conn, _, err := st.Create(CreateInput{Name: "x", UpstreamURL: "postgres://u:p@h/d"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(conn.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(conn.ID); err != ErrNotFound {
		t.Errorf("deleting a missing connection should return ErrNotFound, got %v", err)
	}
	if _, err := st.GetByUsername(conn.AgentUsername); err != ErrNotFound {
		t.Errorf("missing username should return ErrNotFound, got %v", err)
	}
}

func TestAgentPasswordEncryptedDisplay(t *testing.T) {
	st := openTest(t)
	st.UseSecret("admin-token-1")

	conn, password, err := st.Create(CreateInput{Name: "x", UpstreamURL: "postgres://u:p@h/d"})
	if err != nil {
		t.Fatal(err)
	}

	// With the right secret, List re-displays the plaintext password.
	conns, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1 || conns[0].AgentPassword != password {
		t.Fatalf("expected decrypted password %q, got %q", password, conns[0].AgentPassword)
	}

	// Rotating the admin token makes the stored password unrecoverable, but the
	// agent credential itself still authenticates (bcrypt hash is untouched).
	st.UseSecret("admin-token-2")
	conns, err = st.List()
	if err != nil {
		t.Fatal(err)
	}
	if conns[0].AgentPassword != "" {
		t.Errorf("password should be unrecoverable after token change, got %q", conns[0].AgentPassword)
	}
	got, _ := st.GetByUsername(conn.AgentUsername)
	if !VerifyPassword(got, password) {
		t.Error("agent credential must keep working after admin token change")
	}
}

func TestAgentPasswordHiddenWithoutSecret(t *testing.T) {
	st := openTest(t) // no UseSecret
	_, _, err := st.Create(CreateInput{Name: "x", UpstreamURL: "postgres://u:p@h/d"})
	if err != nil {
		t.Fatal(err)
	}
	conns, _ := st.List()
	if conns[0].AgentPassword != "" {
		t.Errorf("no password should be displayed without a secret, got %q", conns[0].AgentPassword)
	}
}

func TestUpdatePolicyFields(t *testing.T) {
	st := openTest(t)
	conn, _, err := st.Create(CreateInput{
		Name: "billing", UpstreamURL: "postgres://u:p@h/d",
		MaxRows: 1000, GateMutations: true,
		PIIRules: []policy.PIIRule{{Name: "email", Action: "hash"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = st.Update(conn.ID, UpdateInput{
		Name: "billing-prod", MaxRows: 50, GateMutations: false,
		PIIRules: []policy.PIIRule{{Name: "ssn", Table: "users", Action: "redact"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, _ := st.GetByUsername(conn.AgentUsername)
	if got.Name != "billing-prod" || got.MaxRows != 50 || got.GateMutations {
		t.Errorf("fields not updated: %+v", got)
	}
	if len(got.PIIRules) != 1 || got.PIIRules[0].Name != "ssn" || got.PIIRules[0].Action != "redact" {
		t.Errorf("pii rules not updated: %+v", got.PIIRules)
	}
	// The agent username (credential identity) must not change on edit.
	if got.AgentUsername != conn.AgentUsername {
		t.Error("update must not change the agent username")
	}

	if err := st.Update(9999, UpdateInput{Name: "x"}); err != ErrNotFound {
		t.Errorf("updating a missing connection should return ErrNotFound, got %v", err)
	}
	if err := st.Update(conn.ID, UpdateInput{Name: "  "}); err == nil {
		t.Error("blank name should error")
	}
}

func TestExpiryFailsClosedAndSweeps(t *testing.T) {
	st := openTest(t)
	now := time.Now().UTC()

	// A connection that expired a minute ago.
	expired, _, err := st.Create(CreateInput{Name: "temp", UpstreamURL: "postgres://u:p@h/d", ExpiresAt: now.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	// A connection expiring in an hour, and one that never expires.
	live, _, err := st.Create(CreateInput{Name: "live", UpstreamURL: "postgres://u:p@h/d", ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	forever, _, err := st.Create(CreateInput{Name: "forever", UpstreamURL: "postgres://u:p@h/d"})
	if err != nil {
		t.Fatal(err)
	}

	// Auth fails closed for the expired one, even before sweeping.
	if _, err := st.GetByUsername(expired.AgentUsername); err != ErrNotFound {
		t.Errorf("expired connection should not authenticate, got %v", err)
	}
	if _, err := st.GetByUsername(live.AgentUsername); err != nil {
		t.Errorf("live connection should authenticate, got %v", err)
	}

	// Sweep removes only the expired row.
	n, err := st.DeleteExpired(now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 swept, got %d", n)
	}
	conns, _ := st.List()
	if len(conns) != 2 {
		t.Errorf("expected 2 remaining connections, got %d", len(conns))
	}
	// The never-expiring one has a zero ExpiresAt and is not swept.
	if _, err := st.GetByUsername(forever.AgentUsername); err != nil {
		t.Errorf("never-expiring connection should survive, got %v", err)
	}
}

func TestUpdateExpiryKeepClearSet(t *testing.T) {
	st := openTest(t)
	now := time.Now().UTC()
	conn, _, err := st.Create(CreateInput{Name: "x", UpstreamURL: "postgres://u:p@h/d", ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	// SetExpiry=false leaves the existing expiry untouched.
	if err := st.Update(conn.ID, UpdateInput{Name: "x2"}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByUsername(conn.AgentUsername)
	if got.ExpiresAt.IsZero() {
		t.Error("expiry should be preserved when SetExpiry is false")
	}

	// SetExpiry with zero time clears it (never expires).
	if err := st.Update(conn.ID, UpdateInput{Name: "x3", SetExpiry: true}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetByUsername(conn.AgentUsername)
	if !got.ExpiresAt.IsZero() {
		t.Errorf("expiry should be cleared, got %v", got.ExpiresAt)
	}

	// SetExpiry with a future time sets it.
	future := now.Add(2 * time.Hour)
	if err := st.Update(conn.ID, UpdateInput{Name: "x4", SetExpiry: true, ExpiresAt: future}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetByUsername(conn.AgentUsername)
	if got.ExpiresAt.IsZero() || got.ExpiresAt.Before(now.Add(time.Hour)) {
		t.Errorf("expiry should be set to the future, got %v", got.ExpiresAt)
	}
}

func TestValidationErrors(t *testing.T) {
	st := openTest(t)
	if _, _, err := st.Create(CreateInput{UpstreamURL: "x"}); err == nil {
		t.Error("missing name should error")
	}
	if _, _, err := st.Create(CreateInput{Name: "x"}); err == nil {
		t.Error("missing upstream should error")
	}
}
