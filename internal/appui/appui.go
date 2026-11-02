// Package appui is the Mac app's interface: one page, plus /api, which passes
// requests to the daemon's control socket. The page never gets a TCP port.
package appui

import (
	"context"
	_ "embed"
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
