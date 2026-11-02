package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// ControlSocket is where the app and CLI reach the daemon. It's a Unix socket on
// the Mac with mode 0600: VMs can reach loopback TCP ports, but not this.
func ControlSocket() string { return filepath.Join(stateDir(), "control.sock") }

func (b *broker) serveControl() (stop func(), err error) {
	path := ControlSocket()
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	old := syscall.Umask(0o177) // no window where the socket is open to others
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: b.controlHandler()}
	go srv.Serve(ln)
	return func() { srv.Close() }, nil
}

func (b *broker) controlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"version": Version, "pid": os.Getpid()})
	})
	mux.HandleFunc("GET /v1/events", b.controlEvents)
	mux.HandleFunc("GET /v1/egress", func(w http.ResponseWriter, r *http.Request) {
		summary, err := egressSummary(r.URL.Query().Get("profile"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, summary)
	})
	mux.HandleFunc("GET /v1/sandboxes/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := validProfile(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"name": name, "suspended_reason": SuspendedReason(name)})
	})
	mux.HandleFunc("POST /v1/sandboxes/{name}/suspend", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var body struct {
			Reason string `json:"reason"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
		}
		if err := Suspend(name, body.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b.audit(auditEntry{Profile: name, Surface: "CONTROL", Method: r.Method, Path: "suspend", Action: "SUSPEND", Detail: body.Reason})
		writeJSON(w, map[string]any{"name": name, "suspended_reason": SuspendedReason(name)})
	})
	return mux
}

func (b *broker) controlEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			http.Error(w, fmt.Sprintf("invalid limit %q", v), http.StatusBadRequest)
			return
		}
		limit = n
	}
	entries, _, err := readAuditFrom(b.auditPath, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	if entries == nil {
		entries = []auditEntry{}
	}
	writeJSON(w, entries)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
