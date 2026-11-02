package broker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vepsala/colimander/internal/sandbox"
)

// fakeTools puts stand-ins for everything setup shells out to on PATH.
func fakeTools(t *testing.T) {
	t.Helper()
	bin := filepath.Join(os.Getenv("HOME"), "bin")
	os.MkdirAll(bin, 0o755)
	for name, script := range map[string]string{
		"colima":  `exit 0`,
		"limactl": `exit 0`,
		"docker":  `echo docker`,
		"git":     `echo git`,
		"gh":      `case "$2" in user) echo me;; user/orgs) echo acme;; esac`,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
}

func TestAbsentDenyRulesMeansAll(t *testing.T) {
	all := len(DefaultDenyRules())
	got, err := ResolveDenyRuleIDs(nil)
	if err != nil || len(got) != all {
		t.Errorf("nil: %d rules, %v", len(got), err)
	}
	if got, _ := ResolveDenyRuleIDs([]string{}); len(got) != 0 {
		t.Errorf("empty is an explicit choice, got %d", len(got))
	}
	if _, err := ResolveDenyRuleIDs([]string{"not-a-rule"}); err == nil {
		t.Error("unknown id should be refused")
	}
}

func TestPolicyForSpec(t *testing.T) {
	p := PolicyForSpec(sandbox.Spec{Login: "me", Orgs: []string{"acme"}, DenyRules: []string{"delete-org"}, Fly: true, FlyApps: []string{"*"}})
	if p.AllowedOwners[0] != "me" || p.AllowedOwners[1] != "acme" || len(p.DenyRules) != 1 || p.Handle == "" {
		t.Errorf("%+v", p)
	}
	if p.FlyPolicy == nil || p.DopplerPolicy != nil {
		t.Errorf("%+v", p)
	}
}

func post(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
	return w
}

func TestSetupAPI(t *testing.T) {
	shortHome(t)
	fakeTools(t)
	// The test process stands in for the running daemon. Without this, activating
	// the broker would start one by re-running this test binary.
	if err := os.WriteFile(pidFile(), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	b := &broker{auditPath: auditFile()}
	h := b.controlHandler()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/setup/options", nil))
	var opts struct {
		Deps   []sandbox.DepStatus `json:"deps"`
		GitHub struct {
			Login string   `json:"login"`
			Orgs  []string `json:"orgs"`
		} `json:"github"`
		DenyRules []denyRuleOption `json:"deny_rules"`
		Packages  []packageOption  `json:"packages"`
		Defaults  struct {
			Egress bool   `json:"egress"`
			CPU    string `json:"cpu"`
		} `json:"defaults"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &opts); err != nil {
		t.Fatal(err)
	}
	if opts.GitHub.Login != "me" || opts.GitHub.Orgs[0] != "acme" || len(opts.DenyRules) != len(DefaultDenyRules()) || len(opts.Packages) != 4 || opts.Defaults.CPU != "2" || opts.Defaults.Egress != sandbox.DefaultEgressMonitoring {
		t.Errorf("options: %s", w.Body)
	}
	for _, d := range opts.Deps {
		if !d.OK {
			t.Errorf("dep %+v", d)
		}
	}

	w = post(t, h, "/v1/setup/validate", `{"fields":{"name":"Bad Name","cpu":"0","import_path":"relative/dir"}}`)
	var v struct {
		Errors map[string]string `json:"errors"`
	}
	json.Unmarshal(w.Body.Bytes(), &v)
	if v.Errors["name"] == "" || v.Errors["cpu"] == "" || !strings.Contains(v.Errors["import_path"], "full path") {
		t.Errorf("validate: %s", w.Body)
	}

	const token = "fly-very-secret"
	bad := `{"name":"demo","cpu":"2","memory":"4","disk":"20","swap":"0","start_broker":true,"enable_fly":true,"fly_token":"` + token + `","orgs":["evil-corp"]}`
	w = post(t, h, "/v1/setup/jobs", bad)
	if w.Code != http.StatusUnprocessableEntity || strings.Contains(w.Body.String(), token) || !strings.Contains(w.Body.String(), "evil-corp") {
		t.Errorf("foreign org: %d %s", w.Code, w.Body)
	}
	w = post(t, h, "/v1/setup/jobs", `{"name":`+token)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), token) {
		t.Errorf("bad JSON: %d %s", w.Code, w.Body)
	}

	// No deny_rule_ids: every rule, not none.
	good := strings.Replace(bad, `,"orgs":["evil-corp"]`, `,"orgs":["acme"]`, 1)
	w = post(t, h, "/v1/setup/jobs", good)
	if w.Code != 200 || strings.Contains(w.Body.String(), token) {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	var job sandbox.Job
	json.Unmarshal(w.Body.Bytes(), &job)
	deadline := time.Now().Add(10 * time.Second)
	for job.State != sandbox.JobSucceeded && job.State != sandbox.JobFailed && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/setup/jobs/"+job.ID, nil))
		if strings.Contains(w.Body.String(), token) {
			t.Fatal("status holds the token")
		}
		json.Unmarshal(w.Body.Bytes(), &job)
	}
	if job.State != sandbox.JobSucceeded {
		t.Fatalf("job: %+v", job)
	}
	pol, err := LoadPolicy("demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.DenyRules) != len(DefaultDenyRules()) || pol.AllowedOwners[0] != "me" || pol.AllowedOwners[1] != "acme" || pol.FlyPolicy == nil {
		t.Errorf("policy: %+v", pol)
	}
	data, _ := os.ReadFile(PolicyPath("demo"))
	if strings.Contains(string(data), token) {
		t.Error("policy.json holds the token")
	}
	stored, err := getProfileTokens("demo")
	if err != nil || stored.Fly != token {
		t.Errorf("vault: %q %v", stored.Fly, err)
	}
	audit, _ := os.ReadFile(auditFile())
	if !strings.Contains(string(audit), "CREATE-SANDBOX") || strings.Contains(string(audit), token) {
		t.Errorf("audit: %s", audit)
	}

	// The name is now taken; the API says so.
	w = post(t, h, "/v1/setup/jobs", good)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "already exists") {
		t.Errorf("duplicate: %d %s", w.Code, w.Body)
	}
}

func TestGitHubProblemBlocksCreation(t *testing.T) {
	shortHome(t)
	fakeTools(t)
	gh := filepath.Join(os.Getenv("HOME"), "bin", "gh")
	os.WriteFile(gh, []byte("#!/bin/sh\nexit 1\n"), 0o755)
	b := &broker{auditPath: auditFile()}
	w := post(t, b.controlHandler(), "/v1/setup/jobs", `{"name":"demo","cpu":"2","memory":"4","disk":"20","swap":"0"}`)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "gh api user") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(sandbox.ProfileDir("demo")); err == nil {
		t.Error("nothing should have been created")
	}
}

func TestWireErrorsDoNotHoldTheHandle(t *testing.T) {
	shortHome(t)
	bin := filepath.Join(os.Getenv("HOME"), "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "colima"), []byte("#!/bin/sh\nexit 1\n"), 0o755)
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	err := wireBrokerInVM("demo", &Policy{Handle: "handle-secret"}, os.Stdout, os.Stderr)
	if err == nil || strings.Contains(err.Error(), "handle-secret") {
		t.Errorf("%v", err)
	}
}
