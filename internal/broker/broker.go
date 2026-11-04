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

package broker

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

	"github.com/vepsala/colimander/internal/sandbox"
)

// Version is reported in the broker's User-Agent.
var Version = "dev"

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

	summaries egressTotals
	other     otherTraffic

	jobsOnce sync.Once
	jobsMgr  *sandbox.Jobs
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
	return refuseSuspended(b.verifyBasic(r))
}

func (b *broker) verifyBasic(r *http.Request) (string, *Policy, error) {
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

	// Egress only.
	BytesOut int64 `json:"bytes_out,omitempty"`
	BytesIn  int64 `json:"bytes_in,omitempty"`
}

func (b *broker) audit(e auditEntry) {
	e.Time = time.Now().UTC()
	data, _ := json.Marshal(e)
	b.auditMu.Lock()
	defer b.auditMu.Unlock()
	rotateAudit(b.auditPath)
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

// Responses explain themselves to the agent in the VM. Agents tend to read a
// 403 as GitHub (or Fly, or Doppler) refusing, then retry, hunt for another
// token or rewrite the remote URL. So every refusal says it came from the
// Colimander broker and what to do instead. Each surface uses the field its
// client actually prints: git shows a text/plain body as "remote: ...", gh
// shows "message", flyctl "error", and the Doppler CLI "messages".

const brokerNotice = "This sandbox doesn't talk to %s directly: requests go through the Colimander broker on the user's Mac (host.lima.internal:8765), which holds the credentials and blocks some operations."

// surfaceHint returns the service name and what to do instead, by path.
func surfaceHint(path string) (service, hint string) {
	switch {
	case strings.HasPrefix(path, "/fly"):
		return "Fly.io", "Retrying or changing settings won't help. For this operation, ask the user for a short-lived Fly token (they can create one in the Colimander app under Fly tokens) and use it with flyctl directly."
	case strings.HasPrefix(path, "/doppler"):
		return "Doppler", "Retrying or changing settings won't help. Ask the user to do this on their Mac."
	default:
		return "GitHub", "There is no GitHub token in this VM, and retrying, using a different token or changing the remote URL won't help. Leave remotes as https://github.com/<owner>/<repo>.git so they go through the broker. If this operation is really needed, ask the user to do it on their Mac."
	}
}

// denyResponse refuses a request that policy doesn't allow.
func (b *broker) denyResponse(w http.ResponseWriter, r *http.Request, reason string) {
	service, hint := surfaceHint(r.URL.Path)
	msg := fmt.Sprintf("Denied by the Colimander broker, not by %s: %s. %s %s", service, reason, fmt.Sprintf(brokerNotice, service), hint)
	b.writeBrokerError(w, r, http.StatusForbidden, msg, reason)
}

// errorResponse reports a broker-side failure, such as a failed handle check or
// an upstream that couldn't be reached.
func (b *broker) errorResponse(w http.ResponseWriter, r *http.Request, status int, msg string) {
	service, _ := surfaceHint(r.URL.Path)
	full := fmt.Sprintf("Colimander broker error (not from %s): %s. %s", service, strings.TrimPrefix(msg, "broker: "), fmt.Sprintf(brokerNotice, service))
	if status == http.StatusForbidden {
		full += " The sandbox's broker credentials didn't match, which usually means the sandbox needs `colimander broker rewire <name>` run on the Mac; ask the user."
	}
	b.writeBrokerError(w, r, status, full, msg)
}

func (b *broker) writeBrokerError(w http.ResponseWriter, r *http.Request, status int, msg, reason string) {
	if strings.HasPrefix(r.URL.Path, "/git/") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		fmt.Fprintln(w, msg)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"message":  msg,           // gh and other GitHub clients
		"error":    msg,           // flyctl
		"messages": []string{msg}, // Doppler CLI
		"reason":   reason,
		"broker":   "colimander",
	})
}

// authFailProfile labels the profile column of an auth-failure audit entry:
// the *claimed* (unverified) username marked with a trailing "?", or a bare
// "?" when the request carried no username at all.
func authFailProfile(claimed string) string {
	if claimed == "" {
		return "?"
	}
	return claimed + "?"
}

// checkGraphQLRequest checks a request to /graphql and returns the body to
// forward. Only a plain JSON POST is accepted: a compressed body or a query in
// the URL would be read differently by GitHub than by the check.
func checkGraphQLRequest(policy *Policy, r *http.Request) (bool, string, io.Reader) {
	if r.Method != http.MethodPost {
		return false, "graphql: only POST is allowed", nil
	}
	if r.URL.RawQuery != "" {
		return false, "graphql: query parameters aren't allowed", nil
	}
	if enc := r.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return false, "graphql: encoded bodies can't be checked", nil
	}
	body, err := readGraphQLBody(r.Body)
	if err != nil {
		return false, "graphql: " + err.Error(), nil
	}
	if ok, reason := policy.checkGraphQL(body); !ok {
		return false, reason, nil
	}
	return true, "", bytes.NewReader(body)
}

func (b *broker) handleAPI(w http.ResponseWriter, r *http.Request) {
	upstreamPath := strings.TrimPrefix(r.URL.Path, "/api")
	if upstreamPath == "" {
		upstreamPath = "/"
	}

	profile, policy, err := b.authProfile(r)
	if err != nil {
		b.audit(auditEntry{Profile: authFailProfile(profile), Surface: "API", Method: r.Method, Path: upstreamPath, Action: "AUTH", Detail: err.Error()})
		b.errorResponse(w, r, http.StatusForbidden, "broker: "+err.Error())
		return
	}

	var body io.Reader = r.Body
	ok, reason := false, ""
	if strings.EqualFold(upstreamPath, "/graphql") {
		ok, reason, body = checkGraphQLRequest(policy, r)
	} else {
		ok, reason = policy.checkAPI(r.Method, upstreamPath)
	}
	if !ok {
		b.audit(auditEntry{Profile: profile, Surface: "API", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: reason})
		b.denyResponse(w, r, reason)
		return
	}

	upstream := gitHubAPIBase + upstreamPath
	if r.URL.RawQuery != "" {
		upstream += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequest(r.Method, upstream, body)
	if err != nil {
		b.errorResponse(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	copyHeadersExceptAuth(req.Header, r.Header)
	tokn, err := b.githubToken()
	if err != nil {
		b.errorResponse(w, r, http.StatusBadGateway, err.Error())
		return
	}
	req.Header.Set("Authorization", "token "+tokn)
	req.Header.Set("User-Agent", "colimander-broker/"+Version)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.errorResponse(w, r, http.StatusBadGateway, err.Error())
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
	if len(parts) < 3 {
		b.errorResponse(w, r, http.StatusBadRequest, fmt.Sprintf("git path must look like /git/<owner>/<repo>[.git]/<endpoint>, got %q", r.URL.Path))
		return
	}
	// GitHub accepts clone URLs with or without the .git suffix, and some
	// tools (pi, go get) build them without it — normalize to the .git form.
	if !strings.HasSuffix(parts[1], ".git") {
		parts[1] += ".git"
	}
	owner := parts[0]
	repo := parts[1]
	endpoint := parts[2]
	upstreamPath := "/" + owner + "/" + repo + "/" + endpoint

	profile, policy, err := b.authProfile(r)
	if err != nil {
		b.audit(auditEntry{Profile: authFailProfile(profile), Surface: "GIT", Method: r.Method, Path: upstreamPath, Action: "AUTH", Detail: err.Error()})
		b.errorResponse(w, r, http.StatusForbidden, "broker: "+err.Error())
		return
	}

	if ok, reason := policy.checkGitOwner(owner); !ok {
		b.audit(auditEntry{Profile: profile, Surface: "GIT", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: reason})
		b.denyResponse(w, r, reason)
		return
	}

	// On a push body, inspect the pkt-line ref commands and apply the
	// git-delete-ref rules. We buffer the whole request body — fine for
	// the command portion + small packfile of typical pushes; for very
	// large pushes this is memory-heavy but predictable.
	var bodyBuf []byte
	if r.Method == http.MethodPost && endpoint == "git-receive-pack" {
		if ok, reason := policy.checkGitPush("/" + owner + "/" + repo); !ok {
			b.audit(auditEntry{Profile: profile, Surface: "GIT", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: reason})
			b.denyResponse(w, r, reason)
			return
		}
		bodyBuf, err = io.ReadAll(r.Body)
		if err != nil {
			b.errorResponse(w, r, http.StatusBadRequest, "read push body: "+err.Error())
			return
		}
		updates := parseReceivePackCommands(bodyBuf)
		for _, u := range updates {
			if !u.isDelete() {
				continue
			}
			if ok, reason := policy.checkGitDelete(u.Ref); !ok {
				b.audit(auditEntry{Profile: profile, Surface: "GIT", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: reason})
				b.denyResponse(w, r, reason)
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
		b.errorResponse(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	copyHeadersExceptAuth(req.Header, r.Header)
	token, err := b.githubToken()
	if err != nil {
		b.errorResponse(w, r, http.StatusBadGateway, err.Error())
		return
	}
	// GitHub git smart-HTTP wants HTTP Basic; the magic username "x-access-token"
	// is the documented form for OAuth/PAT-style tokens.
	req.SetBasicAuth("x-access-token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.errorResponse(w, r, http.StatusBadGateway, err.Error())
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

func CmdBroker(args []string) error {
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
	pol, err := LoadPolicy(name)
	if err != nil {
		return err
	}
	pol.Handle = GenerateHandle()
	if err := SavePolicy(name, pol); err != nil {
		return err
	}
	if err := wireBrokerInVM(name, pol, os.Stdout, os.Stderr); err != nil {
		return err
	}
	fmt.Printf("Rewired %q. New handle is in %s.\n", name, PolicyPath(name))
	return nil
}

func brokerRun(args []string) error {
	fs := flag.NewFlagSet("broker run", flag.ExitOnError)
	port := fs.Int("port", defaultBrokerPort, "TCP port to listen on (loopback only)")
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

	// VMs reach the Mac's loopback through Lima's host address, so nothing needs
	// a wider bind, and a wider bind would expose the broker to the local network.
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	stopControl, err := b.serveControl()
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	defer stopControl()
	stopEgress := b.serveEgress()
	defer stopEgress()
	stopOther := b.other.watch()
	defer stopOther()
	stopDB := startDBProxy()
	defer stopDB()
	log.Printf("colimander broker listening on %s (audit: %s)", addr, b.auditPath)
	return http.ListenAndServe(addr, b.vmHandler())
}

// vmHandler is everything a VM can reach. Admin routes never go here: they belong on
// the control socket.
func (b *broker) vmHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", b.handleAPI)
	mux.HandleFunc("/api", b.handleAPI)
	mux.HandleFunc("/git/", b.handleGit)
	mux.HandleFunc("/fly/", b.handleFly)
	mux.HandleFunc("/fly", b.handleFly)
	mux.HandleFunc("/doppler/", b.handleDoppler)
	mux.HandleFunc("/doppler", b.handleDoppler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b.errorResponse(w, r, http.StatusNotFound, "broker: unknown path "+r.URL.Path)
	})
	return mux
}

func brokerStartBg(args []string) error {
	fs := flag.NewFlagSet("broker start", flag.ExitOnError)
	port := fs.Int("port", defaultBrokerPort, "TCP port to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if pid, ok := readPid(); ok && processAlive(pid) {
		fmt.Printf("broker already running (pid %d).\n", pid)
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
			fmt.Printf("broker started (pid %d). Logs: %s\n", pid, logFile())
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
		fmt.Println("broker not running.")
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
			fmt.Printf("broker stopped (was pid %d).\n", pid)
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
		fmt.Println("broker not running.")
		return nil
	}
	fmt.Printf("broker running (pid %d).\n", pid)
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
