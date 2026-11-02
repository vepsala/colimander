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
