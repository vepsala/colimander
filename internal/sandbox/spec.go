package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultEgressMonitoring is whether a new sandbox's egress monitoring starts on.
// The CLI question and the app's checkbox both default to this.
const DefaultEgressMonitoring = true

// Defaults are the starting answers to setup's questions.
var Defaults = struct {
	CPU         string `json:"cpu"`
	Memory      string `json:"memory"`
	Disk        string `json:"disk"`
	Swap        string `json:"swap"`
	StartBroker bool   `json:"start_broker"`
	Egress      bool   `json:"egress"`
}{"2", "4", "20", "4", true, DefaultEgressMonitoring}

// Request is the answers to setup's questions, as typed. It holds tokens, so it
// must never be stored or marshalled: Spec and Secrets are what comes out of it.
type Request struct {
	Name   string `json:"name"`
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Disk   string `json:"disk"`
	Swap   string `json:"swap"`

	Import     bool   `json:"import"`
	ImportPath string `json:"import_path"`

	Packages []string `json:"packages"`
	Orgs     []string `json:"orgs"`
	// DenyRuleIDs is what to enforce. Absent means every rule, so a client that
	// forgets the field can't turn the guardrails off. An empty list means none.
	DenyRuleIDs []string `json:"deny_rule_ids"`

	EnableFly bool   `json:"enable_fly"`
	FlyToken  string `json:"fly_token"`
	FlyApps   string `json:"fly_apps"`

	EnableDoppler   bool   `json:"enable_doppler"`
	DopplerToken    string `json:"doppler_token"`
	DopplerProjects string `json:"doppler_projects"`

	StartBroker bool `json:"start_broker"`
	Egress      bool `json:"egress"`
}

// Validate returns what's wrong, by field. fromApp selects the stricter path rule
// for a path that wasn't typed relative to any directory the person knows about.
func (r Request) Validate(fromApp bool) map[string]string {
	errs := map[string]string{}
	check := func(field string, err error) {
		if err != nil {
			errs[field] = err.Error()
		}
	}
	check("name", ValidateName(r.Name))
	check("cpu", ValidatePositiveInt(r.CPU))
	check("memory", ValidatePositiveInt(r.Memory))
	check("disk", ValidatePositiveInt(r.Disk))
	check("swap", ValidateNonNegativeInt(r.Swap))
	if r.Import {
		if fromApp {
			check("import_path", ValidateImportPathFromApp(r.ImportPath))
		} else {
			check("import_path", ValidateImportPath(r.ImportPath))
		}
	}
	for _, id := range r.Packages {
		if len(PackagesFromIDs([]string{id})) == 0 {
			errs["packages"] = fmt.Sprintf("unknown package %q", id)
		}
	}
	if r.EnableFly {
		check("fly_token", ValidateNonEmpty(r.FlyToken))
	}
	if r.EnableDoppler {
		check("doppler_token", ValidateNonEmpty(r.DopplerToken))
		check("doppler_projects", ValidateNonEmpty(r.DopplerProjects))
	}
	if r.Egress && !r.StartBroker {
		errs["egress"] = "egress monitoring needs the broker"
	}
	return errs
}

// ValidateName is the whole check on a new sandbox's name.
func ValidateName(name string) error {
	if err := ValidateProfileName(name); err != nil {
		return err
	}
	return EnsureNameAvailable(name)
}

// Spec is what to create. It's kept in job records and shown to the app, so it
// never holds a token. Everything in it has been validated.
type Spec struct {
	Name       string    `json:"name"`
	CPU        int       `json:"cpu"`
	Memory     int       `json:"memory"`
	Disk       int       `json:"disk"`
	Swap       int       `json:"swap"`
	ImportPath string    `json:"import_path,omitempty"`
	Packages   []string  `json:"packages,omitempty"`
	Login      string    `json:"login"`
	Orgs       []string  `json:"orgs,omitempty"`
	DenyRules  []string  `json:"deny_rule_ids"`
	Fly        bool      `json:"fly"`
	FlyApps    []string  `json:"fly_apps,omitempty"`
	Doppler    bool      `json:"doppler"`
	Projects   []string  `json:"doppler_projects,omitempty"`
	Broker     bool      `json:"start_broker"`
	Egress     bool      `json:"egress"`
	Version    string    `json:"version"`
	CreatedAt  time.Time `json:"created_at"`
}

// Secrets are the upstream tokens. They reach the vault in the first step and
// aren't kept after it. Printing or marshalling them shows nothing.
type Secrets struct{ Fly, Doppler string }

func (Secrets) String() string               { return "[redacted]" }
func (Secrets) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// Spec turns validated answers into what to create. denyIDs is the resolved rule
// list: the broker owns the rules, including what an absent list means.
func (r Request) Spec(version, login string, denyIDs []string) (Spec, Secrets, error) {
	nums := map[string]int{}
	for k, v := range map[string]string{"cpu": r.CPU, "memory": r.Memory, "disk": r.Disk, "swap": r.Swap} {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return Spec{}, Secrets{}, fmt.Errorf("%s: must be an integer", k)
		}
		nums[k] = n
	}
	s := Spec{
		Name: r.Name, CPU: nums["cpu"], Memory: nums["memory"], Disk: nums["disk"], Swap: nums["swap"],
		Packages: r.Packages, Login: login, Orgs: r.Orgs, DenyRules: denyIDs,
		Broker: r.StartBroker, Egress: r.Egress && r.StartBroker, Version: version,
		CreatedAt: time.Now().UTC().Round(0),
	}
	if s.DenyRules == nil {
		s.DenyRules = []string{}
	}
	if r.Import {
		abs, err := NormalizeImportPath(r.ImportPath)
		if err != nil {
			return Spec{}, Secrets{}, err
		}
		s.ImportPath = abs
	}
	var sec Secrets
	if r.EnableFly {
		s.Fly = true
		sec.Fly = strings.TrimSpace(r.FlyToken)
		s.FlyApps = SplitCSV(r.FlyApps)
		if len(s.FlyApps) == 0 {
			s.FlyApps = []string{"*"}
		}
	}
	if r.EnableDoppler {
		s.Doppler = true
		sec.Doppler = strings.TrimSpace(r.DopplerToken)
		s.Projects = SplitCSV(r.DopplerProjects)
	}
	return s, sec, nil
}

// Marker is the marker this spec creates.
func (s Spec) Marker() *Marker {
	m := &Marker{
		Name: s.Name, CreatedAt: s.CreatedAt, ColimanderVersion: s.Version,
		CPU: s.CPU, Memory: s.Memory, Disk: s.Disk, SwapGiB: s.Swap,
	}
	if s.ImportPath != "" {
		m.ImportedFrom = s.ImportPath
		m.ImportMode = "dir"
	}
	return m
}

// owns reports whether the profile on disk is the one this spec created. That's the
// only thing retry and clean-up may act on, whatever else later took the name.
func (s Spec) owns() bool {
	m, err := LoadMarker(s.Name)
	return err == nil && m != nil && m.Name == s.Name && m.CreatedAt.Equal(s.CreatedAt)
}

// Hooks are the parts of creating a sandbox that belong to the broker or the caller.
type Hooks struct {
	// SaveConfig writes the sandbox's policy and stores its tokens.
	SaveConfig func(Spec, Secrets) error
	// Forget removes what SaveConfig stored outside the profile directory.
	Forget func(name string) error
	// AfterBoot runs when the VM is up. The CLI syncs /etc/hosts here. Optional.
	AfterBoot func(name string)
	// ActivateBroker wires the VM to the broker.
	ActivateBroker func(name string, o IO) error
	// EnableEgress turns on egress monitoring.
	EnableEgress func(name string, o IO) error
}

// Step is one stage of creating a sandbox. A soft step's failure is a warning, the
// way it is in the CLI: the VM is usable and what failed can be redone by hand.
type Step struct {
	ID    string
	Label string
	Soft  bool
	Run   func(IO) error
}

const stepPrepare = "prepare"

// Steps is the whole of creating a sandbox, in order. The CLI and the daemon both
// run this list.
func Steps(s Spec, sec Secrets, h Hooks) []Step {
	m := s.Marker()
	steps := []Step{
		{ID: stepPrepare, Label: "Save settings", Run: func(IO) error { return prepare(s, sec, h) }},
		{ID: "boot", Label: "Boot the VM", Run: func(o IO) error {
			if err := BootVM(m, o); err != nil {
				return err
			}
			if h.AfterBoot != nil {
				h.AfterBoot(s.Name)
			}
			return nil
		}},
	}
	if s.Swap > 0 {
		steps = append(steps, Step{ID: "swap", Label: fmt.Sprintf("Set up %d GiB of swap", s.Swap), Soft: true, Run: func(o IO) error {
			if err := EnsureSwap(s.Name, s.Swap, o); err != nil {
				return fmt.Errorf("swap setup failed: %w", err)
			}
			return nil
		}})
	}
	if s.ImportPath != "" {
		steps = append(steps, Step{ID: "import", Label: "Copy " + s.ImportPath + " into the VM", Run: func(o IO) error {
			if err := ImportDir(s.Name, s.ImportPath, o); err != nil {
				return fmt.Errorf("import-dir: %w", err)
			}
			return nil
		}})
	}
	if s.Broker {
		steps = append(steps, Step{ID: "broker", Label: "Connect the VM to the credential broker", Soft: true, Run: func(o IO) error {
			return h.ActivateBroker(s.Name, o)
		}})
	}
	steps = append(steps, Step{ID: "baseline", Label: "Install baseline tools", Soft: true, Run: func(o IO) error {
		return InstallBaseline(s.Name, o)
	}})
	for _, p := range PackagesFromIDs(s.Packages) {
		p := p
		steps = append(steps, Step{ID: "package:" + p.ID, Label: "Install " + p.Label, Soft: true, Run: func(o IO) error {
			return InstallPackage(s.Name, p, o)
		}})
	}
	// Last, so installers don't depend on it: with monitoring on, the VM's web
	// traffic needs the daemon.
	if s.Egress {
		steps = append(steps, Step{ID: "egress", Label: "Turn on egress monitoring", Soft: true, Run: func(o IO) error {
			return h.EnableEgress(s.Name, o)
		}})
	}
	return steps
}

// prepare claims the name and writes everything the VM needs. The claim is an
// exclusive mkdir, so two creators can't both win. If it fails nothing is left.
func prepare(s Spec, sec Secrets, h Hooks) (err error) {
	if err := EnsureNameAvailable(s.Name); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ProfileDir(s.Name)), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(ProfileDir(s.Name), 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("colima profile dir %q exists; pick another name", ProfileDir(s.Name))
		}
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(ProfileDir(s.Name))
			if h.Forget != nil {
				h.Forget(s.Name)
			}
		}
	}()
	m := s.Marker()
	if err := WriteMarker(m); err != nil {
		return err
	}
	if err := WriteColimaConfig(m); err != nil {
		return err
	}
	return h.SaveConfig(s, sec)
}

// Note is one line of what to do next.
type Note struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// NextSteps is what to tell someone once the sandbox is ready.
func NextSteps(s Spec) []Note {
	notes := []Note{{"Edit over SSH (in your editor's remote-host picker)", "lima-" + LimaInstanceName(s.Name)}}
	if s.ImportPath != "" {
		vmUser, _ := VMUserName()
		notes = append(notes, Note{"Source landed inside the VM at", fmt.Sprintf("/home/%s/%s", vmUser, filepath.Base(s.ImportPath))})
	}
	return append(notes,
		Note{"Browser", fmt.Sprintf("http://%s.local:<port>", s.Name)},
		Note{"List ports", "colimander ports " + s.Name},
		Note{"SSH shell", "colimander ssh " + s.Name},
		Note{"Stop", "colimander stop " + s.Name},
	)
}
