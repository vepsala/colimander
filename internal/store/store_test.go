package store

import (
	"path/filepath"
	"testing"

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

func TestValidationErrors(t *testing.T) {
	st := openTest(t)
	if _, _, err := st.Create(CreateInput{UpstreamURL: "x"}); err == nil {
		t.Error("missing name should error")
	}
	if _, _, err := st.Create(CreateInput{Name: "x"}); err == nil {
		t.Error("missing upstream should error")
	}
}
