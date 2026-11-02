package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vepsala/colimander/internal/sandbox"
)

// DenyRuleLabel renders a deny rule as one line. API rules show as "METHOD path-glob
// — reason"; git rules show as "git push delete <ref> — reason". Truncated at ~110
// chars to keep a list scannable.
func DenyRuleLabel(r DenyRule) string {
	head := denyRuleHead(r)
	reason := r.Reason
	if reason == "" {
		reason = r.ID
	}
	label := head + "  —  " + reason
	if len(label) > 110 {
		label = label[:107] + "..."
	}
	return label
}

func denyRuleHead(r DenyRule) string {
	switch r.Kind {
	case "api":
		return fmt.Sprintf("%-6s %s", r.Method, r.PathGlob)
	case "git-delete-ref":
		return "git push delete " + r.RefGlob
	}
	return r.ID
}

// ResolveDenyRuleIDs turns a request's choice into the ids to enforce. Absent means
// all of them. An id that isn't a real rule is refused rather than quietly dropped.
func ResolveDenyRuleIDs(ids []string) ([]string, error) {
	all := DefaultDenyRules()
	known := make(map[string]bool, len(all))
	out := make([]string, 0, len(all))
	for _, r := range all {
		known[r.ID] = true
		if ids == nil {
			out = append(out, r.ID)
		}
	}
	for _, id := range ids {
		if !known[id] {
			return nil, fmt.Errorf("unknown deny rule %q", id)
		}
		out = append(out, id)
	}
	return out, nil
}

func filterRulesByID(all []DenyRule, ids []string) []DenyRule {
	keep := make(map[string]bool, len(ids))
	for _, id := range ids {
		keep[id] = true
	}
	out := make([]DenyRule, 0, len(ids))
	for _, r := range all {
		if keep[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

// PolicyForSpec builds a new sandbox's policy.
func PolicyForSpec(s sandbox.Spec) *Policy {
	p := &Policy{
		Version:       PolicyVersion,
		Handle:        GenerateHandle(),
		AllowedOwners: append([]string{s.Login}, s.Orgs...),
		DenyRules:     filterRulesByID(DefaultDenyRules(), s.DenyRules),
	}
	if s.Fly {
		p.FlyPolicy = &FlyPolicy{AllowedApps: s.FlyApps, AllowedEndpoints: DefaultFlyEndpoints()}
	}
	if s.Doppler {
		p.DopplerPolicy = &DopplerPolicy{AllowedProjects: s.Projects, AllowedEndpoints: DefaultDopplerEndpoints()}
	}
	return p
}

// SetupHooks are the broker's parts of creating a sandbox.
func SetupHooks() sandbox.Hooks {
	return sandbox.Hooks{
		SaveConfig: func(s sandbox.Spec, sec sandbox.Secrets) error {
			if err := SavePolicy(s.Name, PolicyForSpec(s)); err != nil {
				return fmt.Errorf("save policy: %w", err)
			}
			if s.Fly || s.Doppler {
				if err := SetProfileTokens(s.Name, ProfileTokens{Fly: sec.Fly, Doppler: sec.Doppler}); err != nil {
					return fmt.Errorf("save upstream tokens: %w", err)
				}
			}
			return nil
		},
		Forget: clearProfileTokens,
		ActivateBroker: func(name string, o sandbox.IO) error {
			return activateBroker(name, o.Out, o.Err)
		},
		EnableEgress: func(name string, _ sandbox.IO) error { return enableEgressOrUndo(name) },
	}
}

// enableEgressOrUndo leaves a new sandbox's monitoring plainly on or plainly off, so
// the app can't say "on" about a VM whose rules never went in.
func enableEgressOrUndo(name string) error {
	err := enableEgress(name)
	if err == nil {
		return nil
	}
	if undo := disableEgress(name); undo != nil {
		return fmt.Errorf("monitoring may be partly on. Check with `colimander egress status %s`, and run `colimander egress disable %s` if the VM has no web access: %w", name, name, err)
	}
	return fmt.Errorf("monitoring stayed off: %w", err)
}

func (b *broker) jobs() *sandbox.Jobs {
	b.jobsOnce.Do(func() {
		b.jobsMgr = sandbox.NewJobs(filepath.Join(stateDir(), "sandbox-jobs"), SetupHooks(), func(name, action, detail string) {
			b.audit(auditEntry{Profile: name, Surface: "CONTROL", Method: "POST", Path: "setup", Action: action, Detail: detail})
		})
	})
	return b.jobsMgr
}

type setupOptions struct {
	Deps   []sandbox.DepStatus `json:"deps"`
	GitHub struct {
		Login     string   `json:"login"`
		Error     string   `json:"error,omitempty"`
		Orgs      []string `json:"orgs"`
		OrgsError string   `json:"orgs_error,omitempty"`
	} `json:"github"`
	DenyRules []denyRuleOption `json:"deny_rules"`
	Packages  []packageOption  `json:"packages"`
	Defaults  any              `json:"defaults"`
}

type denyRuleOption struct {
	ID     string `json:"id"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

type packageOption struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

func getSetupOptions() setupOptions {
	var o setupOptions
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		o.Deps = sandbox.CheckDeps()
	}()
	go func() {
		defer wg.Done()
		login, err := sandbox.GHCurrentLogin()
		if err != nil {
			o.GitHub.Error = err.Error()
			return
		}
		o.GitHub.Login = login
		orgs, err := sandbox.GHOrgs()
		if err != nil {
			o.GitHub.OrgsError = err.Error() // the CLI carries on without orgs too
		}
		o.GitHub.Orgs = orgs
	}()
	wg.Wait()
	if o.GitHub.Orgs == nil {
		o.GitHub.Orgs = []string{}
	}
	for _, r := range DefaultDenyRules() {
		o.DenyRules = append(o.DenyRules, denyRuleOption{r.ID, strings.Join(strings.Fields(denyRuleHead(r)), " "), r.Reason})
	}
	for _, p := range sandbox.Packages {
		o.Packages = append(o.Packages, packageOption{p.ID, p.Label, p.Description})
	}
	o.Defaults = sandbox.Defaults
	return o
}

// validateFields checks the answers one wizard page has so far.
func validateFields(fields map[string]string) map[string]string {
	errs := map[string]string{}
	for field, v := range fields {
		var err error
		switch field {
		case "name":
			err = sandbox.ValidateName(v)
		case "cpu", "memory", "disk":
			err = sandbox.ValidatePositiveInt(v)
		case "swap":
			err = sandbox.ValidateNonNegativeInt(v)
		case "import_path":
			err = sandbox.ValidateImportPathFromApp(v)
		case "fly_token", "doppler_token", "doppler_projects":
			err = sandbox.ValidateNonEmpty(v)
		case "fly_apps":
		default:
			err = errors.New("unknown field")
		}
		if err != nil {
			errs[field] = err.Error()
		}
	}
	return errs
}

// specFromRequest does every check `colimander setup` does before creating anything,
// on the daemon's side, so the page isn't trusted for any of them.
func specFromRequest(r sandbox.Request) (sandbox.Spec, sandbox.Secrets, map[string]string) {
	fail := func(field, msg string) (sandbox.Spec, sandbox.Secrets, map[string]string) {
		return sandbox.Spec{}, sandbox.Secrets{}, map[string]string{field: msg}
	}
	if errs := r.Validate(true); len(errs) > 0 {
		return sandbox.Spec{}, sandbox.Secrets{}, errs
	}
	for _, d := range sandbox.CheckDeps() {
		if !d.OK {
			return fail("deps", fmt.Sprintf("%s is missing. Install with: %s", d.Bin, d.Install))
		}
	}
	login, err := sandbox.GHCurrentLogin()
	if err != nil {
		return fail("github", err.Error())
	}
	if len(r.Orgs) > 0 {
		orgs, err := sandbox.GHOrgs()
		if err != nil {
			return fail("orgs", err.Error())
		}
		for _, picked := range r.Orgs {
			if !ContainsFold(orgs, picked) {
				return fail("orgs", fmt.Sprintf("%q isn't one of your GitHub orgs", picked))
			}
		}
	}
	deny, err := ResolveDenyRuleIDs(r.DenyRuleIDs)
	if err != nil {
		return fail("deny_rules", err.Error())
	}
	s, sec, err := r.Spec(Version, login, deny)
	if err != nil {
		return fail("form", err.Error())
	}
	return s, sec, nil
}

func (b *broker) setupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/setup/options", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, getSetupOptions())
	})
	mux.HandleFunc("POST /v1/setup/validate", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Fields map[string]string `json:"fields"`
		}
		if !readBody(w, r, &body) {
			return
		}
		writeJSON(w, map[string]any{"errors": validateFields(body.Fields)})
	})
	mux.HandleFunc("GET /v1/setup/jobs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, b.jobs().List())
	})
	mux.HandleFunc("POST /v1/setup/jobs", func(w http.ResponseWriter, r *http.Request) {
		var req sandbox.Request
		if !readBody(w, r, &req) {
			return
		}
		spec, sec, errs := specFromRequest(req)
		if errs != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			writeJSON(w, map[string]any{"errors": errs})
			return
		}
		job, err := b.jobs().Start(spec, sec)
		if err != nil {
			if errors.Is(err, sandbox.ErrBusy) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
			writeJSON(w, map[string]any{"errors": map[string]string{"name": err.Error()}})
			return
		}
		writeJSON(w, job)
	})
	mux.HandleFunc("GET /v1/setup/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		job, ok := b.jobs().Get(r.PathValue("id"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, job)
	})
	jobAction := func(action string, run func(string) (sandbox.Job, error)) {
		mux.HandleFunc("POST /v1/setup/jobs/{id}/"+action, func(w http.ResponseWriter, r *http.Request) {
			job, err := run(r.PathValue("id"))
			if err != nil {
				writeJobError(w, err)
				return
			}
			writeJSON(w, job)
		})
	}
	jobAction("retry", func(id string) (sandbox.Job, error) { return b.jobs().Retry(id) })
	jobAction("cleanup", func(id string) (sandbox.Job, error) { return b.jobs().Cleanup(id) })
	mux.HandleFunc("POST /v1/setup/jobs/{id}/dismiss", func(w http.ResponseWriter, r *http.Request) {
		if err := b.jobs().Dismiss(r.PathValue("id")); err != nil {
			writeJobError(w, err)
			return
		}
		writeJSON(w, map[string]string{"id": r.PathValue("id")})
	})
}

func writeJobError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		http.Error(w, "no such job", http.StatusNotFound)
	case errors.Is(err, sandbox.ErrBusy), errors.Is(err, sandbox.ErrNotAllowed):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// readBody decodes a request. Its errors never quote the body, which can hold tokens.
func readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}
