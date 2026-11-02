// Package appui is the Mac app's interface: one page, plus /api, which passes
// requests to the daemon's control socket. The page never gets a TCP port.
package appui

import (
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

//go:embed index.html
var page []byte

func toSocket(socket string, path func(string) string) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL = &url.URL{Scheme: "http", Host: "daemon", Path: path(r.In.URL.Path), RawQuery: r.In.URL.RawQuery}
			r.Out.Host = "daemon"
		},
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "daemon not running", http.StatusServiceUnavailable)
		},
	}
}

// Handler serves the app, reaching the daemon and the database proxy's admin
// server through their sockets.
func Handler(socket, dbSocket string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", toSocket(socket, func(p string) string { return "/v1" + strings.TrimPrefix(p, "/api") }))
	mux.Handle("/db/", toSocket(dbSocket, func(p string) string { return strings.TrimPrefix(p, "/db") }))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	return mux
}

// CopyHandler puts the request body on the clipboard, for the app's /native/copy.
// It reads the clipboard back and only then reports "copied": the page's catch-all
// answers 200 to unknown paths, so the page trusts this field and not the status.
// Neither the text nor an error reaches the response or a log: the text is a token.
func CopyHandler(set func(string) error, get func() (string, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		copied := err == nil && len(body) > 0 && set(string(body)) == nil
		if copied {
			back, err := get()
			copied = err == nil && strings.TrimRight(back, "\r\n") == strings.TrimRight(string(body), "\r\n")
		}
		if !copied {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"copied": copied})
	})
}
