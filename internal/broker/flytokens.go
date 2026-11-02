// Short-lived Fly tokens the person creates in the app and pastes by hand. The
// daemon uses the Mac's full `fly` login here, which is the risk: every use goes
// through runFly, with fixed commands, validated values and no shell. Token values
// pass through to the one response that returns them and are never stored or logged.
// None of this is reachable from a VM: the routes are on the control socket only.

package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// flyLifetime is one allowed choice. Flag is what `fly --expiry` is given; a request
// only ever selects a row by ID, so nothing it sends reaches the command line.
type flyLifetime struct {
	ID    string        `json:"id"`
	Label string        `json:"label"`
	Flag  string        `json:"-"`
	D     time.Duration `json:"-"`
}

var flyLifetimes = []flyLifetime{
	{"1h", "1 hour", "1h", time.Hour},
	{"4h", "4 hours", "4h", 4 * time.Hour},
	{"8h", "8 hours", "8h", 8 * time.Hour},
	{"24h", "24 hours", "24h", 24 * time.Hour},
}

const flyDefaultLifetime = "4h"

// flySubcommands maps a token type to its `fly tokens create` subcommand.
var flySubcommands = map[string]string{"org": "org", "readonly": "readonly"}

var (
	flyOrgRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	flyNameRE = regexp.MustCompile(`^claude-temp-[0-9]{14}-[0-9a-f]{4}$`)
	flyIDRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_=+/.-]{0,127}$`)
)

// flyOp is one command the daemon may run. Its fields are checked by flyArgs.
type flyOp struct {
	kind     string // orgs, create, list or revoke
	org      string
	typ      string
	lifetime string
	name     string
	id       string
}

// flyArgs is the complete list of what the daemon runs with the person's login.
// The org is positional, the form used by hand. `fly tokens create org --help` lists
// only -o, but flyctl takes the first argument when -o and FLY_ORG are unset, and
// flyEnv drops FLY_ORG. The regexp means an org can't look like a flag.
func flyArgs(op flyOp) ([]string, error) {
	switch op.kind {
	case "orgs":
		return []string{"orgs", "list", "--json"}, nil
	case "create":
		sub, ok := flySubcommands[op.typ]
		lt, okLife := lookupFlyLifetime(op.lifetime)
		if !ok || !okLife || !flyOrgRE.MatchString(op.org) || !flyNameRE.MatchString(op.name) {
			return nil, errors.New("invalid fly token request")
		}
		return []string{"tokens", "create", sub, op.org, "--expiry", lt.Flag, "--name", op.name, "--json"}, nil
	case "list":
		if !flyOrgRE.MatchString(op.org) {
			return nil, errors.New("invalid fly org")
		}
		return []string{"tokens", "list", "-s", "org", "-o", op.org}, nil
	case "revoke":
		if !flyIDRE.MatchString(op.id) {
			return nil, errors.New("invalid fly token id")
		}
		return []string{"tokens", "revoke", op.id}, nil
	}
	return nil, errors.New("unknown fly command")
}

func lookupFlyLifetime(id string) (flyLifetime, bool) {
	for _, l := range flyLifetimes {
		if l.ID == id {
			return l, true
		}
	}
	return flyLifetime{}, false
}

// flyEnv passes only what fly needs. Leaving out FLY_API_TOKEN and FLY_ACCESS_TOKEN
// means the Mac's login is used, leaving out FLY_ORG means the org argument decides,
// and leaving out LOG_LEVEL keeps tokens out of debug output.
func flyEnv() []string {
	env := []string{"FLY_NO_UPDATE_CHECK=1", "NO_COLOR=1"}
	for _, k := range []string{"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

var errFlyMissing = errors.New("The fly command isn't on the daemon's PATH. Install it with: brew install flyctl. Then restart the daemon.")

// runFly is the only place the daemon runs fly. Its errors are fixed sentences,
// because fly's output can hold tokens: raw output never leaves this file.
func runFly(op flyOp) (stdout, stderr string, err error) {
	args, err := flyArgs(op)
	if err != nil {
		return "", "", err
	}
	bin, err := exec.LookPath("fly")
	if err != nil {
		if bin, err = exec.LookPath("flyctl"); err != nil {
			return "", "", errFlyMissing
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env, cmd.Dir, cmd.Stdout, cmd.Stderr = flyEnv(), stateDir(), &out, &errOut
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		return "", "", flyFailure(op.kind, out.String()+errOut.String(), ctx.Err() != nil)
	}
	return out.String(), errOut.String(), nil
}

// flyFailure says what went wrong without quoting any of fly's output.
func flyFailure(kind, output string, timedOut bool) error {
	o := strings.ToLower(output)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(o, w) {
				return true
			}
		}
		return false
	}
	switch {
	case timedOut:
		return errors.New("fly took too long to answer. Check your connection and try again.")
	case has("no access token", "not logged in", "auth login", "unauthorized", "not authorized"):
		return errors.New("fly isn't logged in. Run fly auth login in Terminal, then try again.")
	case has("no such host", "connection refused", "network is unreachable", "i/o timeout", "tls handshake"):
		return errors.New("fly couldn't reach Fly.io. Check your connection and try again.")
	}
	switch kind {
	case "create":
		return errors.New("fly couldn't create the token. Try the same command in Terminal to see why.")
	case "orgs":
		return errors.New("fly couldn't list your organizations.")
	}
	return errors.New("fly couldn't do that for this token.")
}

// FlyOrg is one organization the Mac's login can see.
type FlyOrg struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

var flyOrgCache struct {
	sync.Mutex
	orgs []FlyOrg
	at   time.Time
}

// flyOrgs asks fly. `fly orgs list --json` is a map of slug to name. A slug that
// doesn't fit the pattern is left out, so it can't reach a later command.
func flyOrgs() ([]FlyOrg, error) {
	out, _, err := runFly(flyOp{kind: "orgs"})
	if err != nil {
		return nil, err
	}
	var bySlug map[string]string
	if json.Unmarshal([]byte(out), &bySlug) != nil {
		return nil, errors.New("fly's list of organizations wasn't in the expected form.")
	}
	orgs := make([]FlyOrg, 0, len(bySlug))
	for slug, name := range bySlug {
		if flyOrgRE.MatchString(slug) {
			orgs = append(orgs, FlyOrg{slug, name})
		}
	}
	sort.Slice(orgs, func(a, b int) bool { return strings.ToLower(orgs[a].Name) < strings.ToLower(orgs[b].Name) })
	flyOrgCache.Lock()
	flyOrgCache.orgs, flyOrgCache.at = orgs, time.Now()
	flyOrgCache.Unlock()
	return orgs, nil
}

// flyOrgListed checks an org against fly's list, reusing the list the page was just
// given so one click doesn't cost two fly calls. A miss always asks fly again.
func flyOrgListed(slug string) (bool, error) {
	flyOrgCache.Lock()
	orgs, at := flyOrgCache.orgs, flyOrgCache.at
	flyOrgCache.Unlock()
	for _, o := range orgs {
		if o.Slug == slug && time.Since(at) < time.Minute {
			return true, nil
		}
	}
	orgs, err := flyOrgs()
	if err != nil {
		return false, err
	}
	for _, o := range orgs {
		if o.Slug == slug {
			return true, nil
		}
	}
	return false, nil
}

// FlyToken is what's remembered about a created token. It never holds the value.
type FlyToken struct {
	ID        string    `json:"id"`
	Org       string    `json:"org"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	FlyID     string    `json:"fly_id,omitempty"` // found when revoking: creating doesn't report it
}

var flyTokensMu sync.Mutex

func flyTokensPath() string { return filepath.Join(stateDir(), "fly-tokens.json") }

// loadFlyTokens returns unexpired tokens, oldest first. Callers hold flyTokensMu.
func loadFlyTokens() ([]FlyToken, error) {
	list := []FlyToken{}
	data, err := os.ReadFile(flyTokensPath())
	if errors.Is(err, os.ErrNotExist) {
		return list, nil
	}
	if err != nil {
		return nil, err
	}
	var all []FlyToken
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, errors.New("the list of created Fly tokens can't be read")
	}
	for _, t := range all {
		if time.Now().Before(t.ExpiresAt) {
			list = append(list, t)
		}
	}
	return list, nil
}

func saveFlyTokens(list []FlyToken) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := flyTokensPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, flyTokensPath())
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// createFlyToken returns the value once, with what's kept about it.
func createFlyToken(org, typ, lifetime string) (string, FlyToken, error) {
	lt, ok := lookupFlyLifetime(lifetime)
	if _, typeOK := flySubcommands[typ]; !ok || !typeOK || !flyOrgRE.MatchString(org) {
		return "", FlyToken{}, errFlyBadRequest
	}
	listed, err := flyOrgListed(org)
	if err != nil {
		return "", FlyToken{}, err
	}
	if !listed {
		return "", FlyToken{}, errFlyBadRequest
	}
	suffix, err := randomHex(2)
	if err != nil {
		return "", FlyToken{}, err
	}
	id, err := randomHex(8)
	if err != nil {
		return "", FlyToken{}, err
	}
	created := time.Now().UTC()
	// Never from the request. Distinct, because revoking finds the token by its name.
	name := "claude-temp-" + created.Format("20060102150405") + "-" + suffix
	out, _, err := runFly(flyOp{kind: "create", org: org, typ: typ, lifetime: lt.ID, name: name})
	if err != nil {
		return "", FlyToken{}, err
	}
	var parsed struct {
		Token string `json:"token"`
	}
	// The parse error isn't kept: it can quote the input.
	if json.Unmarshal([]byte(out), &parsed) != nil || strings.TrimSpace(parsed.Token) == "" {
		return "", FlyToken{}, errors.New("fly's answer wasn't in the expected form, so no token can be shown. If one was created, it expires by itself.")
	}
	meta := FlyToken{ID: id, Org: org, Type: typ, Name: name, CreatedAt: created, ExpiresAt: created.Add(lt.D)}
	flyTokensMu.Lock()
	defer flyTokensMu.Unlock()
	list, err := loadFlyTokens()
	if err == nil {
		err = saveFlyTokens(append(list, meta))
	}
	if err != nil { // the token still works and it's still the person's: say the list is wrong
		return "", FlyToken{}, errors.New("the token was created, but couldn't be recorded here, so it isn't shown. It expires by itself. Revoke it with fly tokens list and fly tokens revoke if needed.")
	}
	return strings.TrimSpace(parsed.Token), meta, nil
}

var errFlyBadRequest = errors.New("That organization, token type or lifetime isn't available.")

// findFlyTokenID reads `fly tokens list`, which has no JSON form: a table whose
// first two columns are ID and Name. Names here are unique and have no spaces.
func findFlyTokenID(listOutput, name string) string {
	for _, line := range strings.Split(listOutput, "\n") {
		f := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == '|' || r == '│' })
		if len(f) >= 2 && f[1] == name && flyIDRE.MatchString(f[0]) {
			return f[0]
		}
	}
	return ""
}

// revokedOK is needed because `fly tokens revoke` exits 0 even when it failed.
func revokedOK(stdout, id string) bool {
	for _, line := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(line) == "Revoked "+id {
			return true
		}
	}
	return false
}

func revokeFlyToken(id string) (FlyToken, error) {
	flyTokensMu.Lock()
	list, err := loadFlyTokens()
	flyTokensMu.Unlock()
	if err != nil {
		return FlyToken{}, err
	}
	var t *FlyToken
	for i := range list {
		if list[i].ID == id {
			t = &list[i]
		}
	}
	if t == nil {
		return FlyToken{}, os.ErrNotExist
	}
	until := t.ExpiresAt.Local().Format("15:04 on Jan 2")
	flyID := t.FlyID
	if flyID == "" {
		out, _, err := runFly(flyOp{kind: "list", org: t.Org})
		if err != nil {
			return FlyToken{}, err
		}
		if flyID = findFlyTokenID(out, t.Name); flyID == "" {
			return FlyToken{}, fmt.Errorf("This token can't be revoked from here: fly's list doesn't show it. It's still valid until %s. Check with: fly tokens list -o %s", until, t.Org)
		}
	}
	out, _, err := runFly(flyOp{kind: "revoke", id: flyID})
	if err != nil {
		return FlyToken{}, err
	}
	if !revokedOK(out, flyID) {
		return FlyToken{}, fmt.Errorf("Fly didn't revoke this token. It's still valid until %s. Try: fly tokens revoke %s", until, flyID)
	}
	flyTokensMu.Lock()
	defer flyTokensMu.Unlock()
	list, err = loadFlyTokens()
	if err != nil {
		return FlyToken{}, err
	}
	kept := list[:0]
	var gone FlyToken
	for _, x := range list {
		if x.ID == id {
			gone = x
			gone.FlyID = flyID
			continue
		}
		kept = append(kept, x)
	}
	return gone, saveFlyTokens(kept)
}

// flyAuditProfile labels these entries: they belong to the Mac, not to a sandbox.
const flyAuditProfile = "(mac)"

func (b *broker) flyTokenRoutes(mux *http.ServeMux) {
	record := func(action, org, detail string) {
		b.audit(auditEntry{Profile: flyAuditProfile, Surface: "FLY-TOKEN", Method: "POST", Path: org, Action: action, Detail: detail})
	}
	mux.HandleFunc("GET /v1/fly/orgs", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{"lifetimes": flyLifetimes, "default_lifetime": flyDefaultLifetime, "orgs": []FlyOrg{}}
		if orgs, err := flyOrgs(); err != nil {
			resp["error"] = err.Error()
		} else {
			resp["orgs"] = orgs
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("GET /v1/fly/tokens", func(w http.ResponseWriter, r *http.Request) {
		flyTokensMu.Lock()
		list, err := loadFlyTokens()
		flyTokensMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, list)
	})
	mux.HandleFunc("POST /v1/fly/tokens", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Org      string `json:"org"`
			Type     string `json:"type"`
			Lifetime string `json:"lifetime"`
		}
		if !readBody(w, r, &body) {
			return
		}
		value, meta, err := createFlyToken(body.Org, body.Type, body.Lifetime)
		if errors.Is(err, errFlyBadRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err != nil {
			record("CREATE-FAILED", body.Org, err.Error())
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		record("CREATE", meta.Org, fmt.Sprintf("%s token %s, expires %s", meta.Type, meta.Name, meta.ExpiresAt.Format(time.RFC3339)))
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"token": value, "meta": meta})
	})
	mux.HandleFunc("POST /v1/fly/tokens/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		t, err := revokeFlyToken(r.PathValue("id"))
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "That token is no longer listed.", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		record("REVOKE", t.Org, fmt.Sprintf("%s token %s, fly id %s", t.Type, t.Name, t.FlyID))
		writeJSON(w, map[string]string{"id": t.ID})
	})
}
