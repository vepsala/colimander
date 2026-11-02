package broker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const fakeFlyValue = "FlyV1 fm2_FAKESECRETVALUE"

// fakeFly puts a recording stand-in for fly on a PATH that excludes the real one.
// Its output follows flyctl's help and source. FAKE_FLY_MODE picks a failure.
func fakeFly(t *testing.T) (argsLog string) {
	t.Helper()
	shortHome(t)
	flyOrgCache.Lock()
	flyOrgCache.orgs = nil
	flyOrgCache.Unlock()
	bin := filepath.Join(os.Getenv("HOME"), "bin")
	os.MkdirAll(bin, 0o755)
	argsLog = filepath.Join(os.Getenv("HOME"), "args.log")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$HOME/args.log"
mode=$(cat "$HOME/mode" 2>/dev/null)
if [ "$mode" = loggedout ]; then echo "Error: no access token available. Please login with 'flyctl auth login'" >&2; exit 1; fi
if [ "$mode" = leaky ]; then echo "boom ` + fakeFlyValue + `" >&2; exit 1; fi
case "$1 $2" in
"orgs list") echo '{"acme":"Acme Inc","beta-org":"Beta"}';;
"tokens create") echo '{"token":"` + fakeFlyValue + `"}';;
"tokens list") n=$(cat "$HOME/lastname" 2>/dev/null); echo "ID  Name  Created By  Expires At  Revoked At"; echo "tok123  $n  me@x  2030-01-01";;
"tokens revoke") if [ "$mode" = norevoke ]; then echo "failed to revoke token $3: nope" >&2; exit 0; fi; echo "Revoked $3"; echo "1 tokens revoked";;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "fly"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	return argsLog
}

func setFlyMode(t *testing.T, mode string) {
	t.Helper()
	os.WriteFile(filepath.Join(os.Getenv("HOME"), "mode"), []byte(mode), 0o600)
}

func TestFlyArgsAreFixed(t *testing.T) {
	name := "claude-temp-20261102145254-ab12"
	// The form used by hand: fly tokens create org acme-org --expiry 8h --name claude-temp
	// with a distinct name, and --json so the value can be read without parsing text.
	got, err := flyArgs(flyOp{kind: "create", org: "acme-org", typ: "org", lifetime: "8h", name: name})
	want := []string{"tokens", "create", "org", "acme-org", "--expiry", "8h", "--name", name, "--json"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("create: %q %v", got, err)
	}
	if got, _ := flyArgs(flyOp{kind: "create", org: "acme", typ: "readonly", lifetime: "1h", name: name}); got[2] != "readonly" || got[3] != "acme" {
		t.Errorf("readonly: %v", got)
	}
	for _, l := range []string{"4h", "8h"} {
		if _, ok := lookupFlyLifetime(l); !ok {
			t.Errorf("%s isn't offered", l)
		}
	}
	if flyDefaultLifetime != "4h" {
		t.Errorf("default %s", flyDefaultLifetime)
	}
	bad := []flyOp{
		{kind: "create", org: "--access-token=x", typ: "org", lifetime: "4h", name: name},
		{kind: "create", org: "acme;rm -rf", typ: "org", lifetime: "4h", name: name},
		{kind: "create", org: "acme\n", typ: "org", lifetime: "4h", name: name},
		{kind: "create", org: "-o", typ: "org", lifetime: "4h", name: name},
		{kind: "create", org: "acme", typ: "--debug", lifetime: "4h", name: name},
		{kind: "create", org: "acme", typ: "deploy", lifetime: "4h", name: name},
		{kind: "create", org: "acme", typ: "org", lifetime: "87600h", name: name},
		{kind: "create", org: "acme", typ: "org", lifetime: "4h --debug", name: name},
		{kind: "create", org: "acme", typ: "org", lifetime: "4h", name: "--debug"},
		{kind: "create", org: "acme", typ: "org", lifetime: "4h", name: "my free-form name"},
		{kind: "list", org: "-x"},
		{kind: "revoke", id: "--help"},
		{kind: "revoke", id: "a b"},
		{kind: "apps destroy"},
		{},
	}
	for _, op := range bad {
		if got, err := flyArgs(op); err == nil {
			t.Errorf("%+v built %v", op, got)
		}
	}
}

func TestFlyEnvDropsTokensAndDebug(t *testing.T) {
	keys := []string{"FLY_API_TOKEN", "FLY_ACCESS_TOKEN", "FLY_ORG", "LOG_LEVEL"}
	for _, k := range keys {
		t.Setenv(k, "x")
	}
	for _, kv := range flyEnv() {
		for _, k := range keys {
			if strings.HasPrefix(kv, k+"=") {
				t.Errorf("leaked %s", kv)
			}
		}
	}
}

func createReq(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	return post(t, h, "/v1/fly/tokens", body)
}

func TestCreateTokenKeepsOnlyMetadata(t *testing.T) {
	log := fakeFly(t)
	b := &broker{auditPath: auditFile()}
	h := b.controlHandler()
	w := createReq(t, h, `{"org":"acme","type":"org","lifetime":"4h"}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("token response may be cached")
	}
	var resp struct {
		Token string   `json:"token"`
		Meta  FlyToken `json:"meta"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Token != fakeFlyValue || resp.Meta.Org != "acme" {
		t.Fatalf("%+v", resp)
	}
	if d := time.Until(resp.Meta.ExpiresAt); d < 3*time.Hour+59*time.Minute || d > 4*time.Hour {
		t.Errorf("expiry %v", d)
	}
	args, _ := os.ReadFile(log)
	if !strings.Contains(string(args), "tokens create org acme --expiry 4h --name "+resp.Meta.Name+" --json") {
		t.Errorf("args: %s", args)
	}
	// Nothing under the state directory holds the value, whatever the file.
	filepath.Walk(stateDir(), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if data, _ := os.ReadFile(p); strings.Contains(string(data), "fm2_FAKE") {
				t.Errorf("%s holds the token", p)
			}
		}
		return nil
	})
	l := httptest.NewRecorder()
	h.ServeHTTP(l, httptest.NewRequest("GET", "/v1/fly/tokens", nil))
	if strings.Contains(l.Body.String(), "fm2_FAKE") || !strings.Contains(l.Body.String(), "acme") {
		t.Errorf("list: %s", l.Body)
	}
	ev, _ := readAuditTail(auditFile())
	if len(ev) != 1 || ev[0].Action != "CREATE" || ev[0].Surface != "FLY-TOKEN" {
		t.Errorf("audit: %+v", ev)
	}
}

func TestBadRequestsNeverRunACreate(t *testing.T) {
	log := fakeFly(t)
	h := (&broker{auditPath: auditFile()}).controlHandler()
	for _, body := range []string{
		`{"org":"--debug","type":"org","lifetime":"4h"}`,
		`{"org":"acme;id","type":"org","lifetime":"4h"}`,
		`{"org":"not-my-org","type":"org","lifetime":"4h"}`,
		`{"org":"acme","type":"deploy","lifetime":"4h"}`,
		`{"org":"acme","type":"org","lifetime":"999h"}`,
		`{"org":"acme","type":"org","lifetime":"-x 1h"}`,
	} {
		if w := createReq(t, h, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, w.Code)
		} else if strings.Contains(w.Body.String(), "--debug") || strings.Contains(w.Body.String(), "not-my-org") {
			t.Errorf("echoed the request: %s", w.Body)
		}
	}
	args, _ := os.ReadFile(log)
	if strings.Contains(string(args), "tokens create") {
		t.Errorf("ran: %s", args)
	}
}

func TestFlyOutputStaysOutOfErrors(t *testing.T) {
	fakeFly(t)
	b := &broker{auditPath: auditFile()}
	h := b.controlHandler()
	setFlyMode(t, "leaky")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/fly/orgs", nil))
	if strings.Contains(w.Body.String(), "fm2_FAKE") {
		t.Errorf("orgs: %s", w.Body)
	}
	setFlyMode(t, "")
	createReq(t, h, `{"org":"acme","type":"org","lifetime":"4h"}`) // caches the org list
	setFlyMode(t, "leaky")
	c := createReq(t, h, `{"org":"acme","type":"org","lifetime":"4h"}`)
	if c.Code != http.StatusBadGateway || strings.Contains(c.Body.String(), "fm2_FAKE") {
		t.Errorf("create: %d %s", c.Code, c.Body)
	}
	if data, _ := os.ReadFile(auditFile()); strings.Contains(string(data), "fm2_FAKE") {
		t.Errorf("audit: %s", data)
	}
}

func TestLoggedOutAndMissingFly(t *testing.T) {
	fakeFly(t)
	h := (&broker{auditPath: auditFile()}).controlHandler()
	setFlyMode(t, "loggedout")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/fly/orgs", nil))
	if !strings.Contains(w.Body.String(), "fly auth login") {
		t.Errorf("%s", w.Body)
	}
	t.Setenv("PATH", "/usr/bin:/bin")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/fly/orgs", nil))
	if !strings.Contains(w.Body.String(), "brew install flyctl") {
		t.Errorf("%s", w.Body)
	}
}

func createOne(t *testing.T, h http.Handler) FlyToken {
	t.Helper()
	w := createReq(t, h, `{"org":"acme","type":"org","lifetime":"1h"}`)
	var resp struct {
		Meta FlyToken `json:"meta"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	os.WriteFile(filepath.Join(os.Getenv("HOME"), "lastname"), []byte(resp.Meta.Name), 0o600)
	return resp.Meta
}

func TestRevoke(t *testing.T) {
	log := fakeFly(t)
	h := (&broker{auditPath: auditFile()}).controlHandler()
	m := createOne(t, h)

	// fly exits 0 when a revoke fails, so its words decide.
	setFlyMode(t, "norevoke")
	w := post(t, h, "/v1/fly/tokens/"+m.ID+"/revoke", "")
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "still valid") {
		t.Errorf("failed revoke: %d %s", w.Code, w.Body)
	}
	flyTokensMu.Lock()
	if l, _ := loadFlyTokens(); len(l) != 1 {
		t.Error("a failed revoke dropped the token")
	}
	flyTokensMu.Unlock()

	setFlyMode(t, "")
	if w := post(t, h, "/v1/fly/tokens/"+m.ID+"/revoke", ""); w.Code != 200 {
		t.Errorf("revoke: %d %s", w.Code, w.Body)
	}
	args, _ := os.ReadFile(log)
	if !strings.Contains(string(args), "tokens list -s org -o acme") || !strings.Contains(string(args), "tokens revoke tok123") {
		t.Errorf("%s", args)
	}
	flyTokensMu.Lock()
	if l, _ := loadFlyTokens(); len(l) != 0 {
		t.Errorf("still listed: %+v", l)
	}
	flyTokensMu.Unlock()
	if w := post(t, h, "/v1/fly/tokens/"+m.ID+"/revoke", ""); w.Code != http.StatusNotFound {
		t.Errorf("again: %d", w.Code)
	}
}

func TestRevokeSaysWhenFlyDoesntListIt(t *testing.T) {
	fakeFly(t)
	h := (&broker{auditPath: auditFile()}).controlHandler()
	m := createOne(t, h)
	os.Remove(filepath.Join(os.Getenv("HOME"), "lastname"))
	w := post(t, h, "/v1/fly/tokens/"+m.ID+"/revoke", "")
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "can't be revoked from here") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

func TestExpiredTokensDropOffAndSurviveRestart(t *testing.T) {
	fakeFly(t)
	now := time.Now()
	saveFlyTokens([]FlyToken{
		{ID: "old", Org: "acme", ExpiresAt: now.Add(-time.Minute)},
		{ID: "new", Org: "acme", ExpiresAt: now.Add(time.Hour)},
	})
	// A new broker reads the file: that's all a restart changes.
	w := httptest.NewRecorder()
	(&broker{auditPath: auditFile()}).controlHandler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/fly/tokens", nil))
	if strings.Contains(w.Body.String(), `"old"`) || !strings.Contains(w.Body.String(), `"new"`) {
		t.Errorf("%s", w.Body)
	}
}

func TestTokenRoutesAreNotOnTheVMPort(t *testing.T) {
	log := fakeFly(t)
	h := (&broker{auditPath: auditFile()}).vmHandler()
	for _, p := range []string{"/v1/fly/tokens", "/v1/fly/orgs", "/fly/tokens", "/fly/v1/fly/tokens"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", p, strings.NewReader(`{"org":"acme","type":"org","lifetime":"4h"}`))
		h.ServeHTTP(w, r)
		if w.Code == 200 {
			t.Errorf("%s answered 200", p)
		}
	}
	if args, _ := os.ReadFile(log); len(args) != 0 {
		t.Errorf("the VM port ran fly: %s", args)
	}
}

func TestFindFlyTokenIDFromTable(t *testing.T) {
	name := "claude-temp-20261102145254-ab12"
	for _, table := range []string{
		"Tokens for organization \"acme\":\nID   Name  Created By\nabc123   " + name + "   me@x   2030\n",
		"| ID | Name |\n|---|---|\n| abc123 | " + name + " | me@x |\n",
	} {
		if got := findFlyTokenID(table, name); got != "abc123" {
			t.Errorf("%q: %q", table, got)
		}
	}
	if got := findFlyTokenID("--flag "+name+" x", name); got != "" {
		t.Errorf("flag-like id accepted: %q", got)
	}
}
