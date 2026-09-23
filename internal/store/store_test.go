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

func TestRotateDue(t *testing.T) {
	st := openTest(t)
	st.UseSecret("admin-token")
	now := time.Now().UTC()

	hourly, hourlyPw, err := st.Create(CreateInput{Name: "hourly", UpstreamURL: "postgres://u:p@h/d", RotateEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	daily, dailyPw, err := st.Create(CreateInput{Name: "daily", UpstreamURL: "postgres://u:p@h/d", RotateEvery: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	manual, manualPw, err := st.Create(CreateInput{Name: "manual", UpstreamURL: "postgres://u:p@h/d"})
	if err != nil {
		t.Fatal(err)
	}
	if hourly.RotateEvery != time.Hour || hourly.RotatedAt.IsZero() {
		t.Errorf("create should record the interval and rotated_at: %+v", hourly)
	}
	if got := hourly.NextRotation(); !got.Equal(hourly.RotatedAt.Add(time.Hour)) {
		t.Errorf("next rotation should be rotated_at + interval, got %v", got)
	}
	if !manual.NextRotation().IsZero() {
		t.Error("a connection without an interval has no next rotation")
	}

	// Nothing is due right after creation.
	rotated, err := st.RotateDue(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated) != 0 {
		t.Fatalf("nothing should be due yet, got %+v", rotated)
	}

	// Two hours on, only the hourly connection is due.
	later := now.Add(2 * time.Hour)
	rotated, err = st.RotateDue(later)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated) != 1 || rotated[0].ID != hourly.ID || rotated[0].Name != "hourly" || rotated[0].AgentUsername != hourly.AgentUsername {
		t.Fatalf("expected only the hourly connection to rotate, got %+v", rotated)
	}
	if !rotated[0].NextRotationAt.Equal(later.Add(time.Hour)) {
		t.Errorf("next rotation should be now+interval, got %v", rotated[0].NextRotationAt)
	}

	// rotated_at moved to the sweep time; old password is dead, new one works
	// and is re-displayable.
	got, err := st.GetByUsername(hourly.AgentUsername)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RotatedAt.Equal(later.Truncate(time.Nanosecond)) {
		t.Errorf("rotated_at should be updated to %v, got %v", later, got.RotatedAt)
	}
	if got.RotateEvery != time.Hour {
		t.Errorf("interval must survive rotation, got %v", got.RotateEvery)
	}
	if VerifyPassword(got, hourlyPw) {
		t.Error("old password must stop working after automatic rotation")
	}
	conns, _ := st.List()
	var newPw string
	for _, c := range conns {
		if c.ID == hourly.ID {
			newPw = c.AgentPassword
		}
	}
	if newPw == "" || newPw == hourlyPw {
		t.Fatalf("List should decrypt the new password, got %q", newPw)
	}
	if !VerifyPassword(got, newPw) {
		t.Error("decrypted password should verify against the new hash")
	}

	// The others are untouched.
	for _, tc := range []struct {
		conn *Connection
		pw   string
	}{{daily, dailyPw}, {manual, manualPw}} {
		g, err := st.GetByUsername(tc.conn.AgentUsername)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyPassword(g, tc.pw) {
			t.Errorf("%s: password must not change when not due", tc.conn.Name)
		}
		if !g.RotatedAt.Equal(tc.conn.RotatedAt.Truncate(time.Nanosecond)) {
			t.Errorf("%s: rotated_at must not move when not due", tc.conn.Name)
		}
	}

	// Running again at the same instant rotates nothing more.
	rotated, err = st.RotateDue(later)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated) != 0 {
		t.Errorf("already-rotated connection must not rotate twice, got %+v", rotated)
	}
}

func TestManualRotateResetsRotatedAt(t *testing.T) {
	st := openTest(t)
	conn, _, err := st.Create(CreateInput{Name: "x", UpstreamURL: "postgres://u:p@h/d", RotateEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	// Backdate the last rotation so a manual rotate has something to move.
	past := time.Now().UTC().Add(-30 * time.Minute)
	if _, err := st.db.Exec(`UPDATE connections SET rotated_at = ? WHERE id = ?`, formatTimestamp(past), conn.ID); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	if _, err := st.Rotate(conn.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByUsername(conn.AgentUsername)
	if got.RotatedAt.Before(before.Truncate(time.Second)) {
		t.Errorf("manual rotate should reset rotated_at to now, got %v", got.RotatedAt)
	}
}

func TestUpdateRotateEveryKeepClearSet(t *testing.T) {
	st := openTest(t)
	conn, _, err := st.Create(CreateInput{Name: "x", UpstreamURL: "postgres://u:p@h/d", RotateEvery: 8 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	// SetRotateEvery=false leaves the interval untouched.
	if err := st.Update(conn.ID, UpdateInput{Name: "x2"}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByUsername(conn.AgentUsername)
	if got.RotateEvery != 8*time.Hour {
		t.Errorf("interval should be preserved when SetRotateEvery is false, got %v", got.RotateEvery)
	}

	// SetRotateEvery with zero turns automatic rotation off.
	if err := st.Update(conn.ID, UpdateInput{Name: "x3", SetRotateEvery: true}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetByUsername(conn.AgentUsername)
	if got.RotateEvery != 0 || !got.NextRotation().IsZero() {
		t.Errorf("interval should be cleared, got %v", got.RotateEvery)
	}
	if n, _ := st.RotateDue(time.Now().UTC().Add(1000 * time.Hour)); len(n) != 0 {
		t.Errorf("connection with rotation off must never be due, got %+v", n)
	}

	// SetRotateEvery with a value sets it; rotated_at is not touched.
	if err := st.Update(conn.ID, UpdateInput{Name: "x4", SetRotateEvery: true, RotateEvery: 2 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetByUsername(conn.AgentUsername)
	if got.RotateEvery != 2*time.Hour {
		t.Errorf("interval should be set, got %v", got.RotateEvery)
	}
	if !got.RotatedAt.Equal(conn.RotatedAt.Truncate(time.Nanosecond)) {
		t.Errorf("changing the interval must not move rotated_at: %v vs %v", got.RotatedAt, conn.RotatedAt)
	}
}

func TestRotatedAtFallsBackToCreatedAt(t *testing.T) {
	st := openTest(t)
	conn, _, err := st.Create(CreateInput{Name: "old", UpstreamURL: "postgres://u:p@h/d"})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a row from before the column existed.
	if _, err := st.db.Exec(`UPDATE connections SET rotated_at = '' WHERE id = ?`, conn.ID); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetByUsername(conn.AgentUsername)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RotatedAt.Equal(got.CreatedAt) || got.RotatedAt.IsZero() {
		t.Errorf("blank rotated_at should fall back to created_at, got %v (created %v)", got.RotatedAt, got.CreatedAt)
	}
	// The migration backfills the blank on the next open.
	if err := st.migrate(); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := st.db.QueryRow(`SELECT rotated_at FROM connections WHERE id = ?`, conn.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "" {
		t.Error("migrate should backfill rotated_at from created_at")
	}
}
