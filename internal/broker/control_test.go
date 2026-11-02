package broker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// shortHome avoids the Unix socket path limit that t.TempDir can exceed.
func shortHome(t *testing.T) {
	t.Helper()
	home, err := os.MkdirTemp("", "cm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("HOME", home)
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestSuspendRefusesBothAuthSchemes(t *testing.T) {
	shortHome(t)
	if err := os.MkdirAll(profileDir("demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SavePolicy("demo", &Policy{Version: PolicyVersion, Handle: "h1"}); err != nil {
		t.Fatal(err)
	}
	b := &broker{auditPath: auditFile()}
	basic := httptest.NewRequest("GET", "/api/x", nil)
	basic.SetBasicAuth("demo", "h1")
	bearer := httptest.NewRequest("GET", "/fly/x", nil)
	bearer.Header.Set("Authorization", "Bearer demo:h1")

	if _, _, err := b.authProfile(basic); err != nil {
		t.Fatalf("basic before suspend: %v", err)
	}
	if _, _, err := b.authProfileFromBearer(bearer); err != nil {
		t.Fatalf("bearer before suspend: %v", err)
	}
	if err := Suspend("demo", "unexpected query"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.authProfile(basic); err == nil || !strings.Contains(err.Error(), "unexpected query") {
		t.Errorf("basic while suspended: %v", err)
	}
	if _, _, err := b.authProfileFromBearer(bearer); err == nil {
		t.Error("bearer while suspended should fail")
	}
}

func TestSuspendRejectsPathEscape(t *testing.T) {
	shortHome(t)
	for _, name := range []string{"", "..", "../x", "a/b"} {
		if err := Suspend(name, "x"); err == nil {
			t.Errorf("Suspend(%q) should fail", name)
		}
	}
}

func TestControlSocketIsPrivateAndWorks(t *testing.T) {
	shortHome(t)
	b := &broker{auditPath: auditFile()}
	stop, err := b.serveControl()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	info, err := os.Stat(ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %o", perm)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", ControlSocket())
	}}}
	resp, err := client.Post("http://x/v1/sandboxes/demo/suspend", "application/json", strings.NewReader(`{"reason":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || SuspendedReason("demo") != "test" {
		t.Errorf("suspend: status %d, reason %q", resp.StatusCode, SuspendedReason("demo"))
	}
	resp, err = client.Get("http://x/v1/events?limit=5")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var events []auditEntry
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "SUSPEND" {
		t.Errorf("events = %+v", events)
	}
}
