// colimanderd — the host-side credential broker.
//
// Listens on a single port (default 8765) for HTTP requests from managed
// Colima VMs. Identifies the calling profile by source IP, looks up that
// profile's policy, enforces it, then forwards allowed requests to GitHub
// after injecting the host's real PAT (sourced via `gh auth token`).
//
// Two surfaces are exposed:
//
//	/api/...           proxied to https://api.github.com/...
//	/git/<o>/<r>.git/* proxied to https://github.com/<o>/<r>.git/*
//
// Inside the VM, git is configured with:
//
//	url."http://host.lima.internal:8765/git/".insteadOf "https://github.com/"
//
// so clone/fetch/push all flow through here. API tools that respect
// GITHUB_API_URL (octokit, gh-for-GHE, many SDKs) use http://host.lima.internal:8765/api.
//
// Source-IP based identity is deliberately simple. Loopback is rejected
// unless --dev-allow-loopback is passed (used only for unit tests).

package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultBrokerPort = 8765
	gitHubAPIBase     = "https://api.github.com"
	gitHubGitBase     = "https://github.com"
)

// ----------------------------- daemon state ---------------------------------

type broker struct {
	auditPath  string
	auditMu    sync.Mutex
	devLoop    bool
	devProfile string // when devLoop, every loopback request is attributed to this profile

	// gh token cache.
	tokenMu sync.Mutex
	token   string
	tokenAt time.Time
}

func stateDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".colimander")
}

// ----------------------------- gh token ------------------------------------

func (b *broker) githubToken() (string, error) {
	b.tokenMu.Lock()
	defer b.tokenMu.Unlock()
	if b.token != "" && time.Since(b.tokenAt) < 60*time.Second {
		return b.token, nil
	}
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return "", fmt.Errorf("gh auth token failed: %w (run `gh auth login` on the host)", err)
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		return "", errors.New("gh auth token returned an empty string")
	}
	b.token = tok
	b.tokenAt = time.Now()
	return tok, nil
}

// ----------------------------- profile identity -----------------------------
//
// We can't use source IP — lima/vz forwards the VM's outbound
// `host.lima.internal` connections via a host-side socket, so requests arrive
// at the broker as loopback. Instead, the VM presents HTTP Basic auth where
// username = profile name and password = the handle stored in that profile's
// policy.json. The wizard injects the credential into git config and the
// `GITHUB_API_URL` env var so every outbound rewrite carries it transparently.

// authProfile reads Basic auth from the request, verifies the handle matches
// the named profile's stored handle, and returns the profile name and its
// policy. Constant-time compare to avoid trivial timing distinguishers
// between "wrong profile" and "wrong handle".
func (b *broker) authProfile(r *http.Request) (string, *Policy, error) {
	if b.devLoop {
		if pol, err := loadPolicyForProfile(b.devProfile); err == nil {
			return b.devProfile, pol, nil
		}
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" {
		return "", nil, errors.New("no basic-auth credential (broker expects username=profile, password=handle)")
	}
	pol, err := loadPolicyForProfile(user)
	if err != nil {
		return user, nil, fmt.Errorf("unknown profile %q (%v)", user, err)
	}
	if pol.Handle == "" {
		return user, nil, fmt.Errorf("profile %q has no handle configured; run `colimander broker rewire %s`", user, user)
	}
	if subtle.ConstantTimeCompare([]byte(pol.Handle), []byte(pass)) != 1 {
		return user, nil, errors.New("handle mismatch")
	}
	return user, pol, nil
}

// ----------------------------- audit ----------------------------------------

type auditEntry struct {
	Time    time.Time `json:"time"`
	Profile string    `json:"profile"`
	Surface string    `json:"surface"` // "API" | "GIT"
	Method  string    `json:"method"`
	Path    string    `json:"path"`
	Action  string    `json:"action"` // "ALLOW" | "DENY"
	Detail  string    `json:"detail"`
}

func (b *broker) audit(e auditEntry) {
	e.Time = time.Now().UTC()
	data, _ := json.Marshal(e)
	b.auditMu.Lock()
	defer b.auditMu.Unlock()
	f, err := os.OpenFile(b.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit write: %v", err)
		return
	}
	defer f.Close()
	f.Write(data)
	f.Write([]byte("\n"))
	// Also mirror to stderr for live observation.
	log.Printf("%s %s %s %s — %s (%s)", e.Profile, e.Surface, e.Method, e.Path, e.Action, e.Detail)
}

// ----------------------------- handlers -------------------------------------

func (b *broker) denyResponse(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{
		"error":  "colimander policy denied this operation",
		"reason": reason,
	})
}

func (b *broker) errorResponse(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (b *broker) handleAPI(w http.ResponseWriter, r *http.Request) {
	upstreamPath := strings.TrimPrefix(r.URL.Path, "/api")
	if upstreamPath == "" {
		upstreamPath = "/"
	}

	profile, policy, err := b.authProfile(r)
	if err != nil {
		b.errorResponse(w, http.StatusForbidden, "broker: "+err.Error())
		return
	}

	if ok, reason := policy.checkAPI(r.Method, upstreamPath); !ok {
		b.audit(auditEntry{Profile: profile, Surface: "API", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: reason})
		b.denyResponse(w, reason)
		return
	}

	upstream := gitHubAPIBase + upstreamPath
	if r.URL.RawQuery != "" {
		upstream += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequest(r.Method, upstream, r.Body)
	if err != nil {
		b.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	copyHeadersExceptAuth(req.Header, r.Header)
	tokn, err := b.githubToken()
	if err != nil {
		b.errorResponse(w, http.StatusBadGateway, err.Error())
		return
	}
	req.Header.Set("Authorization", "token "+tokn)
	req.Header.Set("User-Agent", "colimander-broker/"+version)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.errorResponse(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	b.audit(auditEntry{Profile: profile, Surface: "API", Method: r.Method, Path: upstreamPath, Action: "ALLOW", Detail: fmt.Sprintf("upstream=%d", resp.StatusCode)})
}

func (b *broker) handleGit(w http.ResponseWriter, r *http.Request) {
	// Path shape: /git/<owner>/<repo>.git/<endpoint>...
	rest := strings.TrimPrefix(r.URL.Path, "/git/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 || !strings.HasSuffix(parts[1], ".git") {
		b.errorResponse(w, http.StatusBadRequest, fmt.Sprintf("git path must look like /git/<owner>/<repo>.git/<endpoint>, got %q", r.URL.Path))
		return
	}
	owner := parts[0]
	repo := parts[1]
	endpoint := parts[2]
	upstreamPath := "/" + owner + "/" + repo + "/" + endpoint

	profile, policy, err := b.authProfile(r)
	if err != nil {
		b.errorResponse(w, http.StatusForbidden, "broker: "+err.Error())
		return
	}

	if ok, reason := policy.checkGitOwner(owner); !ok {
		b.audit(auditEntry{Profile: profile, Surface: "GIT", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: reason})
		b.denyResponse(w, reason)
		return
	}

	// On a push body, inspect the pkt-line ref commands and apply the
	// git-delete-ref rules. We buffer the whole request body — fine for
	// the command portion + small packfile of typical pushes; for very
	// large pushes this is memory-heavy but predictable.
	var bodyBuf []byte
	if r.Method == http.MethodPost && endpoint == "git-receive-pack" {
		bodyBuf, err = io.ReadAll(r.Body)
		if err != nil {
			b.errorResponse(w, http.StatusBadRequest, "read push body: "+err.Error())
			return
		}
		updates := parseReceivePackCommands(bodyBuf)
		for _, u := range updates {
			if !u.isDelete() {
				continue
			}
			if ok, reason := policy.checkGitDelete(u.Ref); !ok {
				b.audit(auditEntry{Profile: profile, Surface: "GIT", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: reason})
				b.denyResponse(w, reason)
				return
			}
		}
	}

	upstream := gitHubGitBase + upstreamPath
	if r.URL.RawQuery != "" {
		upstream += "?" + r.URL.RawQuery
	}
	var upstreamBody io.Reader = r.Body
	if bodyBuf != nil {
		upstreamBody = bytes.NewReader(bodyBuf)
	}
	req, err := http.NewRequest(r.Method, upstream, upstreamBody)
	if err != nil {
		b.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	copyHeadersExceptAuth(req.Header, r.Header)
	token, err := b.githubToken()
	if err != nil {
		b.errorResponse(w, http.StatusBadGateway, err.Error())
		return
	}
	// GitHub git smart-HTTP wants HTTP Basic; the magic username "x-access-token"
	// is the documented form for OAuth/PAT-style tokens.
	req.SetBasicAuth("x-access-token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.errorResponse(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	b.audit(auditEntry{Profile: profile, Surface: "GIT", Method: r.Method, Path: upstreamPath, Action: "ALLOW", Detail: fmt.Sprintf("upstream=%d", resp.StatusCode)})
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func copyHeadersExceptAuth(dst, src http.Header) {
	for k, vs := range src {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// ----------------------------- daemon lifecycle -----------------------------

func pidFile() string { return filepath.Join(stateDir(), "broker.pid") }
func logFile() string { return filepath.Join(stateDir(), "broker.log") }
func auditFile() string {
	return filepath.Join(stateDir(), "audit.log")
}

func readPid() (int, bool) {
	data, err := os.ReadFile(pidFile())
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return n, true
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0: no-op probe; returns nil if the process exists and we can signal it.
	return proc.Signal(syscall.Signal(0)) == nil
}

func cmdBroker(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: colimander broker {run|start|stop|status|tail|rewire <profile>}")
	}
	switch args[0] {
	case "run":
		return brokerRun(args[1:])
	case "start":
		return brokerStartBg(args[1:])
	case "stop":
		return brokerStop(args[1:])
	case "status":
		return brokerStatus(args[1:])
	case "tail":
		return brokerTail(args[1:])
	case "rewire":
		return brokerRewire(args[1:])
	default:
		return fmt.Errorf("unknown broker subcommand %q", args[0])
	}
}

// brokerRewire regenerates the per-profile Basic-auth handle and re-applies
// the VM-side git/api routing. Use it when:
//   - upgrading an existing profile to the handle-based identity (older
//     profiles created before this landed have policy.Handle == "");
//   - you suspect the handle has leaked and want to rotate it.
//
// The VM keeps running — only its `git config` and `/etc/profile.d` are
// rewritten over SSH. The broker reloads policy per request, so no daemon
// restart is required.
func brokerRewire(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: colimander broker rewire <profile>")
	}
	name := args[0]
	pol, err := loadPolicy(name)
	if err != nil {
		return err
	}
	pol.Handle = generateHandle()
	if err := savePolicy(name, pol); err != nil {
		return err
	}
	if err := wireBrokerInVM(name, pol.Handle); err != nil {
		return err
	}
	fmt.Printf("Rewired %q. New handle is in %s.\n", name, policyPath(name))
	return nil
}

func brokerRun(args []string) error {
	fs := flag.NewFlagSet("broker run", flag.ExitOnError)
	port := fs.Int("port", defaultBrokerPort, "TCP port to listen on (0.0.0.0)")
	devLoop := fs.Bool("dev-allow-loopback", false, "TESTING: accept loopback requests and treat them as --dev-profile")
	devProfile := fs.String("dev-profile", "", "TESTING: profile name to attribute loopback requests to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *devLoop && *devProfile == "" {
		return errors.New("--dev-allow-loopback requires --dev-profile")
	}

	if err := os.MkdirAll(stateDir(), 0o755); err != nil {
		return err
	}
	if pid, ok := readPid(); ok && processAlive(pid) {
		return fmt.Errorf("broker already running (pid %d)", pid)
	}
	if err := os.WriteFile(pidFile(), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		return err
	}
	defer os.Remove(pidFile())

	b := &broker{
		auditPath:  auditFile(),
		devLoop:    *devLoop,
		devProfile: *devProfile,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/", b.handleAPI)
	mux.HandleFunc("/api", b.handleAPI)
	mux.HandleFunc("/git/", b.handleGit)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b.errorResponse(w, http.StatusNotFound, "broker: unknown path "+r.URL.Path)
	})

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	log.Printf("colimander broker listening on %s (audit: %s)", addr, b.auditPath)
	return http.ListenAndServe(addr, mux)
}

func brokerStartBg(args []string) error {
	fs := flag.NewFlagSet("broker start", flag.ExitOnError)
	port := fs.Int("port", defaultBrokerPort, "TCP port to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if pid, ok := readPid(); ok && processAlive(pid) {
		fmt.Printf("Broker already running (pid %d).\n", pid)
		return nil
	}
	if err := os.MkdirAll(stateDir(), 0o755); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(logFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "broker", "run", "--port", strconv.Itoa(*port))
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		f.Close()
		return err
	}
	// brokerRun writes the pidfile itself; wait briefly for it.
	for i := 0; i < 25; i++ {
		time.Sleep(80 * time.Millisecond)
		if pid, ok := readPid(); ok && processAlive(pid) {
			fmt.Printf("Broker started (pid %d). Logs: %s\n", pid, logFile())
			return nil
		}
	}
	return fmt.Errorf("broker did not come up; check %s", logFile())
}

func brokerStop(args []string) error {
	if len(args) > 0 {
		return errors.New("broker stop takes no arguments")
	}
	pid, ok := readPid()
	if !ok {
		fmt.Println("Broker not running.")
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	for i := 0; i < 25; i++ {
		time.Sleep(80 * time.Millisecond)
		if !processAlive(pid) {
			fmt.Printf("Broker stopped (was pid %d).\n", pid)
			os.Remove(pidFile())
			return nil
		}
	}
	return fmt.Errorf("broker (pid %d) didn't exit after SIGTERM", pid)
}

func brokerStatus(args []string) error {
	if len(args) > 0 {
		return errors.New("broker status takes no arguments")
	}
	pid, ok := readPid()
	if !ok || !processAlive(pid) {
		fmt.Println("Broker not running.")
		return nil
	}
	fmt.Printf("Broker running (pid %d).\n", pid)
	fmt.Printf("  audit log:   %s\n", auditFile())
	fmt.Printf("  process log: %s\n", logFile())
	// Try to read recent audit lines (last 5).
	data, err := os.ReadFile(auditFile())
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	from := len(lines) - 5
	if from < 0 {
		from = 0
	}
	if from < len(lines) && lines[from] != "" {
		fmt.Println("  recent audit:")
		for _, l := range lines[from:] {
			fmt.Println("   ", l)
		}
	}
	return nil
}

func brokerTail(args []string) error {
	fs := flag.NewFlagSet("broker tail", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Simple cat — user can `tail -f` from shell for live following.
	data, err := os.ReadFile(auditFile())
	if err != nil {
		return err
	}
	os.Stdout.Write(data)
	return nil
}
