package appui

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIGoesToTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "ui")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Method + " " + r.URL.RequestURI()
		w.Write([]byte("[]"))
	})}
	go srv.Serve(ln)
	defer srv.Close()

	ui := httptest.NewServer(Handler(sock, "/nonexistent.sock"))
	defer ui.Close()
	resp, err := http.Post(ui.URL+"/api/sandboxes/a/suspend?x=1", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "POST /v1/sandboxes/a/suspend?x=1" {
		t.Errorf("daemon got %q", got)
	}
}

func TestDaemonDownIsReported(t *testing.T) {
	ui := httptest.NewServer(Handler("/nonexistent.sock", "/nonexistent.sock"))
	defer ui.Close()
	resp, err := http.Get(ui.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestPageIsServed(t *testing.T) {
	ui := httptest.NewServer(Handler("/nonexistent.sock", "/nonexistent.sock"))
	defer ui.Close()
	resp, err := http.Get(ui.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type = %q", ct)
	}
}

func TestDatabasePathsGoToTheirSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "ui")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.URL.Path })}
	go srv.Serve(ln)
	defer srv.Close()
	ui := httptest.NewServer(Handler("/nonexistent.sock", sock))
	defer ui.Close()
	resp, err := http.Get(ui.URL + "/db/api/connections")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "/api/connections" {
		t.Errorf("admin got %q", got)
	}
}

func TestPageIsNativeAndHasNoBlockedDialogs(t *testing.T) {
	s := string(page)
	for _, bad := range []string{"<iframe", "confirm(\"", "alert("} {
		if strings.Contains(s, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
}

func TestCopyHandlerOnlyClaimsWhatItVerified(t *testing.T) {
	var clip string
	set := func(s string) error { clip = s; return nil }
	get := func() (string, error) { return clip, nil }
	run := func(h http.Handler, body string) (int, string) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/native/copy", strings.NewReader(body)))
		return w.Code, w.Body.String()
	}
	if code, body := run(CopyHandler(set, get), "secret"); code != 200 || !strings.Contains(body, "true") || clip != "secret" {
		t.Errorf("ok: %d %s", code, body)
	}
	wrong := func() (string, error) { return "something else", nil }
	if code, body := run(CopyHandler(set, wrong), "secret"); code == 200 || !strings.Contains(body, "false") || strings.Contains(body, "secret") {
		t.Errorf("read-back mismatch: %d %s", code, body)
	}
	if code, body := run(CopyHandler(func(string) error { return os.ErrPermission }, get), "secret"); code == 200 || strings.Contains(body, "secret") {
		t.Errorf("set failed: %d %s", code, body)
	}
	if code, _ := run(CopyHandler(set, get), ""); code == 200 {
		t.Error("empty body claimed success")
	}
}
