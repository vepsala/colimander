// Colimander v0 — minimal CLI wrapper around Colima for safe per-profile lifecycle.
//
// Safety model: every profile this tool creates gets a marker file at
// ~/.colima/<name>/.colimander.json. Mutating commands (start, stop, destroy)
// refuse to operate on profiles without a marker unless --force-unmanaged
// is passed. This is the guardrail that keeps Colimander from ever
// accidentally touching the user's other Colima profiles.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
)

const (
	version    = "0.0.1"
	markerName = ".colimander.json"
)

type marker struct {
	Name              string    `json:"name"`
	CreatedAt         time.Time `json:"created_at"`
	ColimanderVersion string    `json:"colimander_version"`
	CPU               int       `json:"cpu"`
	Memory            int       `json:"memory"`
	Disk              int       `json:"disk"`
	// SwapGiB controls a /swapfile created inside the VM at start time.
	// 0 = no swap. Idempotent — applied on every `start` if non-zero.
	SwapGiB int `json:"swap_gib,omitempty"`
	// ImportedFrom records what was loaded into the VM at create time. Either a
	// host path (mode "dir") or a git URL (mode "repo"). For audit only.
	ImportedFrom string `json:"imported_from,omitempty"`
	ImportMode   string `json:"import_mode,omitempty"`
}

func colimaProfileDir(name string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".colima", name)
}

func markerPath(name string) string {
	return filepath.Join(colimaProfileDir(name), markerName)
}

func loadMarker(name string) (*marker, error) {
	data, err := os.ReadFile(markerPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m marker
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid marker at %s: %w", markerPath(name), err)
	}
	return &m, nil
}

func writeMarker(m *marker) error {
	if err := os.MkdirAll(colimaProfileDir(m.Name), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(markerPath(m.Name), data, 0o644)
}

// requireManaged loads the marker and returns it. If the profile has no
// marker, it refuses unless forceUnmanaged is set, in which case it returns
// (nil, nil) and the caller falls back to a plain colima invocation.
func requireManaged(name string, forceUnmanaged bool) (*marker, error) {
	m, err := loadMarker(name)
	if err != nil {
		return nil, err
	}
	if m == nil {
		if forceUnmanaged {
			fmt.Fprintf(os.Stderr, "warning: profile %q is not Colimander-managed; --force-unmanaged was passed.\n", name)
			return nil, nil
		}
		return nil, fmt.Errorf("profile %q is not managed by Colimander (no marker at %s). Refusing. Pass --force-unmanaged to override", name, markerPath(name))
	}
	return m, nil
}

// colimaListEntry mirrors a row of `colima list --json` output.
type colimaListEntry struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Arch    string `json:"arch"`
	CPUs    int    `json:"cpus"`
	Memory  int64  `json:"memory"`
	Disk    int64  `json:"disk"`
	Runtime string `json:"runtime"`
	Address string `json:"address"`
}

func listProfiles() ([]colimaListEntry, error) {
	out, err := exec.Command("colima", "list", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("colima list --json failed: %w", err)
	}
	var entries []colimaListEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e colimaListEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("parse colima list entry %q: %w", line, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func runColima(args ...string) error {
	cmd := exec.Command("colima", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func humanBytes(b int64) string {
	const gib = 1024 * 1024 * 1024
	if b >= gib {
		return fmt.Sprintf("%dGiB", b/gib)
	}
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", b)
}

// listManagedNames returns profile names that have a Colimander marker file,
// even if Colima has never started them.
func listManagedNames() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	colimaDir := filepath.Join(home, ".colima")
	dirs, err := os.ReadDir(colimaDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(colimaDir, d.Name(), markerName)); err == nil {
			names = append(names, d.Name())
		}
	}
	return names, nil
}

func cmdLs(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	all := fs.Bool("all", false, "show all Colima profiles, not just Colimander-managed")
	if err := fs.Parse(args); err != nil {
		return err
	}

	coli, err := listProfiles()
	if err != nil {
		return err
	}
	coliByName := map[string]colimaListEntry{}
	for _, e := range coli {
		coliByName[e.Name] = e
	}

	managed, err := listManagedNames()
	if err != nil {
		return err
	}
	managedSet := map[string]bool{}
	for _, n := range managed {
		managedSet[n] = true
	}

	const rowFmt = "%-20s %-8s %-7s %-10s %-4s %-7s %-7s %-16s %s\n"
	fmt.Printf(rowFmt, "PROFILE", "MANAGED", "POLICY", "STATUS", "CPU", "MEM", "DISK", "ADDRESS", "RUNTIME")

	policyStr := func(name string, isManaged bool) string {
		if !isManaged {
			return "-"
		}
		if _, err := os.Stat(policyPath(name)); err == nil {
			return "yes"
		}
		return "no"
	}

	printRow := func(name string, e *colimaListEntry, isManaged bool) {
		managedStr := "no"
		if isManaged {
			managedStr = "yes"
		}
		pol := policyStr(name, isManaged)
		if e != nil {
			addr := e.Address
			if addr == "" {
				addr = "-"
			}
			runtime := e.Runtime
			if runtime == "" {
				runtime = "-"
			}
			fmt.Printf(rowFmt, name, managedStr, pol, e.Status, fmt.Sprintf("%d", e.CPUs),
				humanBytes(e.Memory), humanBytes(e.Disk), addr, runtime)
			return
		}
		// No colima entry — managed-but-never-started. Pull resources from marker.
		m, _ := loadMarker(name)
		cpu, mem, disk := "-", "-", "-"
		if m != nil {
			cpu = fmt.Sprintf("%d", m.CPU)
			mem = fmt.Sprintf("%dGiB", m.Memory)
			disk = fmt.Sprintf("%dGiB", m.Disk)
		}
		fmt.Printf(rowFmt, name, managedStr, pol, "Created", cpu, mem, disk, "-", "-")
	}

	shown := 0
	if *all {
		for _, e := range coli {
			printRow(e.Name, &e, managedSet[e.Name])
			shown++
		}
		for _, n := range managed {
			if _, ok := coliByName[n]; ok {
				continue
			}
			printRow(n, nil, true)
			shown++
		}
	} else {
		for _, n := range managed {
			if e, ok := coliByName[n]; ok {
				printRow(n, &e, true)
			} else {
				printRow(n, nil, true)
			}
			shown++
		}
	}

	if shown == 0 {
		if *all {
			fmt.Println("(no Colima profiles found)")
		} else {
			fmt.Println("(no Colimander-managed profiles. Pass --all to see other Colima profiles.)")
		}
	}
	return nil
}

func cmdCreate(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: colimander create <name> [--cpu N] [--memory G] [--disk G] [--start]")
	}
	name := args[0]
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	cpu := fs.Int("cpu", 2, "vCPU count")
	memory := fs.Int("memory", 4, "memory in GiB")
	disk := fs.Int("disk", 20, "disk in GiB")
	start := fs.Bool("start", false, "also start the profile after creation")
	importDir := fs.String("import-dir", "", "copy a host directory into the VM after first boot (implies --start)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}
	if *importDir != "" {
		*start = true
	}

	existing, err := loadMarker(name)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("profile %q already exists (marker at %s)", name, markerPath(name))
	}
	if _, err := os.Stat(colimaProfileDir(name)); err == nil {
		return fmt.Errorf("Colima profile directory %s exists but has no Colimander marker. Refusing to overwrite", colimaProfileDir(name))
	}

	m := &marker{
		Name:              name,
		CreatedAt:         time.Now().UTC(),
		ColimanderVersion: version,
		CPU:               *cpu,
		Memory:            *memory,
		Disk:              *disk,
	}
	if *importDir != "" {
		abs, err := filepath.Abs(*importDir)
		if err != nil {
			return err
		}
		m.ImportedFrom = abs
		m.ImportMode = "dir"
	}
	if err := writeMarker(m); err != nil {
		return fmt.Errorf("write marker: %w", err)
	}
	if err := writeColimaConfig(m); err != nil {
		return fmt.Errorf("write colima.yaml: %w", err)
	}
	fmt.Printf("Created Colimander profile %q.\n", name)
	fmt.Printf("  CPU: %d   Memory: %d GiB   Disk: %d GiB\n", *cpu, *memory, *disk)
	fmt.Printf("  Marker: %s\n", markerPath(name))
	if !*start {
		fmt.Printf("\nTo start: colimander start %s\n", name)
		return nil
	}
	if err := startProfile(m); err != nil {
		return err
	}
	if *importDir != "" {
		if err := importDirIntoVM(name, *importDir); err != nil {
			return fmt.Errorf("import-dir: %w", err)
		}
	}
	return nil
}

// emptyMountPath returns a per-profile throwaway directory that we mount
// read-only into the VM. This is the trick that suppresses Colima's default
// $HOME + /tmp/colima-<profile> mounts: when --mount is passed explicitly,
// Colima only includes what we specify (plus its own image cache, which is
// always read-only and benign).
func emptyMountPath(name string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".colimander", "empty", name)
}

func ensureEmptyMount(name string) (string, error) {
	p := emptyMountPath(name)
	if err := os.MkdirAll(p, 0o755); err != nil {
		return "", err
	}
	return p, nil
}

func renderColimaConfig(m *marker) string {
	return fmt.Sprintf(`# Generated by colimander v%s for profile %q.
# colimander start regenerates this from the marker — edits will be overwritten.
cpu: %d
memory: %d
disk: %d
runtime: docker
vmType: vz
mountType: virtiofs
network:
  address: true
`, m.ColimanderVersion, m.Name, m.CPU, m.Memory, m.Disk)
}

func writeColimaConfig(m *marker) error {
	path := filepath.Join(colimaProfileDir(m.Name), "colima.yaml")
	return os.WriteFile(path, []byte(renderColimaConfig(m)), 0o644)
}

func startProfile(m *marker) error {
	if err := writeColimaConfig(m); err != nil {
		return fmt.Errorf("write colima.yaml: %w", err)
	}
	emptyMnt, err := ensureEmptyMount(m.Name)
	if err != nil {
		return fmt.Errorf("create empty mount stub: %w", err)
	}
	fmt.Printf("Starting %q (no host home mount; %d CPU / %d GiB RAM / %d GiB disk)\n",
		m.Name, m.CPU, m.Memory, m.Disk)
	// The --mount with our empty dir is the trick that suppresses Colima's
	// $HOME and /tmp/colima-<profile> defaults at the lima.yaml layer.
	if err := runColima("start", m.Name, "--mount", emptyMnt+":r"); err != nil {
		return err
	}
	if err := syncEtcHosts(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to update /etc/hosts: %v\n", err)
		fmt.Fprintf(os.Stderr, "  retry manually with: colimander hosts-sync\n")
	}
	if m.SwapGiB > 0 {
		if err := ensureSwap(m.Name, m.SwapGiB); err != nil {
			fmt.Fprintf(os.Stderr, "warning: swap setup failed: %v\n", err)
		}
	}
	return nil
}

// ensureSwap idempotently creates and activates a /swapfile of the requested
// size inside the VM and persists it in /etc/fstab. Safe to call on every
// start — if a /swapfile is already active at the right size, this is a no-op.
func ensureSwap(profile string, gib int) error {
	script := fmt.Sprintf(`set -e
DESIRED_BYTES=$(( %d * 1024 * 1024 * 1024 ))
if swapon --show=NAME,SIZE --bytes --noheadings 2>/dev/null | awk '$1=="/swapfile"{print $2}' | grep -qx "$DESIRED_BYTES"; then
  exit 0
fi
sudo swapoff /swapfile 2>/dev/null || true
sudo rm -f /swapfile
sudo fallocate -l %dG /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile > /dev/null
sudo swapon /swapfile
grep -q "^/swapfile " /etc/fstab || echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab > /dev/null
`, gib, gib)
	cmd := exec.Command("colima", "ssh", "-p", profile, "--", "bash", "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// activateBrokerForProfile starts the broker daemon (if not already running)
// and wires the VM-side config so git/api traffic flows through it. Called
// from the wizard (with explicit user consent) and from `colimander start`
// (when a policy file already exists for the profile).
//
// If the profile's policy has no Handle yet (older profiles created before
// Basic-auth identity landed), one is generated and saved here so existing
// VMs upgrade transparently on next start.
func activateBrokerForProfile(profile string) error {
	pol, err := loadPolicy(profile)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	if pol.Handle == "" {
		pol.Handle = generateHandle()
		if err := savePolicy(profile, pol); err != nil {
			return fmt.Errorf("save policy with new handle: %w", err)
		}
	}
	if err := ensureBrokerRunning(); err != nil {
		return fmt.Errorf("broker start: %w", err)
	}
	if err := wireBrokerInVM(profile, pol); err != nil {
		return fmt.Errorf("wire broker in VM: %w", err)
	}
	return nil
}

// ensureBrokerRunning starts the broker daemon if it isn't already up.
// Idempotent — safe to call on every `start`.
func ensureBrokerRunning() error {
	if pid, ok := readPid(); ok && processAlive(pid) {
		return nil
	}
	return brokerStartBg(nil)
}

// wireBrokerInVM configures the VM to route github.com traffic through the
// broker on the host, and (optionally) routes fly.io + doppler API calls
// through the broker too when those policies are present.
//
// Auth shapes:
//   - GitHub via git: `http.<URL>.extraHeader` (git's canonical pattern for
//     static Authorization headers on a specific URL). Not URL-embedded
//     user:pass — git doesn't reliably forward URL-embedded passwords on
//     POST/redirects, but extraHeader is always sent verbatim.
//   - GitHub via API tools: `GITHUB_API_URL` with embedded creds (octokit
//     and most SDKs respect this env var).
//   - Fly/Doppler: env vars FLY_API_HOSTNAME/FLY_API_TOKEN and
//     DOPPLER_API_HOST/DOPPLER_TOKEN, with token = "<profile>:<handle>" so
//     the broker can identify the caller from the Bearer header.
func wireBrokerInVM(profile string, pol *Policy) error {
	brokerBase := fmt.Sprintf("http://host.lima.internal:%d", defaultBrokerPort)
	gitInsteadOfVar := fmt.Sprintf("url.%s/git/.insteadOf", brokerBase)
	extraHeaderVar := fmt.Sprintf("http.%s/.extraHeader", brokerBase)
	basicCred := base64.StdEncoding.EncodeToString([]byte(profile + ":" + pol.Handle))
	extraHeaderVal := "Authorization: Basic " + basicCred
	apiURLWithAuth := fmt.Sprintf("http://%s:%s@host.lima.internal:%d/api", profile, pol.Handle, defaultBrokerPort)

	profileScript := "# Generated by colimander; rewritten on broker rewire / start.\n"
	profileScript += fmt.Sprintf("export GITHUB_API_URL=%s\n", apiURLWithAuth)
	if pol.FlyPolicy != nil {
		profileScript += fmt.Sprintf("export FLY_API_HOSTNAME=%s/fly\n", brokerBase)
		profileScript += fmt.Sprintf("export FLY_API_TOKEN=%s:%s\n", profile, pol.Handle)
	}
	if pol.DopplerPolicy != nil {
		profileScript += fmt.Sprintf("export DOPPLER_API_HOST=%s/doppler\n", brokerBase)
		profileScript += fmt.Sprintf("export DOPPLER_TOKEN=%s:%s\n", profile, pol.Handle)
	}

	// Drop any stale colimander-managed entries from prior runs (handles get
	// rotated on rewire; we don't want two extraHeader values racing).
	cleanup := `set -e
for k in $(git config --global --get-regexp '^url\..*host\.lima\.internal.*\.insteadof$' 2>/dev/null | awk '{print $1}'); do
  git config --global --unset-all "$k" 2>/dev/null || true
done
for k in $(git config --global --get-regexp '^http\..*host\.lima\.internal.*\.extraheader$' 2>/dev/null | awk '{print $1}'); do
  git config --global --unset-all "$k" 2>/dev/null || true
done
true`

	cmdSteps := [][]string{
		{"bash", "-c", cleanup},
		{"git", "config", "--global", gitInsteadOfVar, "https://github.com/"},
		{"git", "config", "--global", extraHeaderVar, extraHeaderVal},
	}
	for _, step := range cmdSteps {
		args := append([]string{"ssh", "-p", profile, "--"}, step...)
		cmd := exec.Command("colima", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("vm-wire %v: %w", step, err)
		}
	}
	// Write /etc/profile.d/colimander.sh from stdin via `sudo tee` — handles
	// the multi-line content without quoting hell.
	teeCmd := exec.Command("colima", "ssh", "-p", profile, "--",
		"sudo", "tee", "/etc/profile.d/colimander.sh")
	teeCmd.Stdin = strings.NewReader(profileScript)
	teeCmd.Stdout = nil // discard tee echo
	teeCmd.Stderr = os.Stderr
	if err := teeCmd.Run(); err != nil {
		return fmt.Errorf("vm-wire write profile.d: %w", err)
	}
	return nil
}

func cmdStart(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: colimander start <name>")
	}
	name := args[0]
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	forceUnmanaged := fs.Bool("force-unmanaged", false, "operate on a profile not managed by Colimander")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}
	m, err := requireManaged(name, *forceUnmanaged)
	if err != nil {
		return err
	}
	if m == nil {
		return runColima("start", name)
	}
	if err := startProfile(m); err != nil {
		return err
	}
	if _, err := os.Stat(policyPath(name)); err == nil {
		if err := activateBrokerForProfile(name); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
	return nil
}

func cmdStop(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: colimander stop <name>")
	}
	name := args[0]
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	forceUnmanaged := fs.Bool("force-unmanaged", false, "operate on a profile not managed by Colimander")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}
	if _, err := requireManaged(name, *forceUnmanaged); err != nil {
		return err
	}
	return runColima("stop", name)
}

func cmdDestroy(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: colimander destroy <name> [--yes]")
	}
	name := args[0]
	fs := flag.NewFlagSet("destroy", flag.ExitOnError)
	forceUnmanaged := fs.Bool("force-unmanaged", false, "operate on a profile not managed by Colimander")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}
	if _, err := requireManaged(name, *forceUnmanaged); err != nil {
		return err
	}
	if !*yes {
		return fmt.Errorf("this will permanently delete profile %q and its data; pass --yes to confirm", name)
	}
	// Best-effort: colima delete handles the VM + most files. Then ensure the
	// directory is gone in case the VM was never started.
	_ = runColima("delete", "-f", name)
	if err := os.RemoveAll(colimaProfileDir(name)); err != nil {
		return fmt.Errorf("cleanup %s: %w", colimaProfileDir(name), err)
	}
	// Also remove the per-profile empty-mount stub dir, if any.
	_ = os.RemoveAll(emptyMountPath(name))
	if err := syncEtcHosts(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to update /etc/hosts: %v\n", err)
	}
	fmt.Printf("Destroyed profile %q.\n", name)
	return nil
}

func cmdStatus(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: colimander status <name>")
	}
	name := args[0]
	m, err := loadMarker(name)
	if err != nil {
		return err
	}
	coli, err := listProfiles()
	if err != nil {
		return err
	}
	var c *colimaListEntry
	for i := range coli {
		if coli[i].Name == name {
			c = &coli[i]
			break
		}
	}
	if m == nil && c == nil {
		return fmt.Errorf("no profile named %q", name)
	}
	fmt.Printf("Profile:  %s\n", name)
	if m != nil {
		fmt.Printf("Managed:  yes (created %s, colimander v%s)\n",
			m.CreatedAt.Local().Format("2006-01-02 15:04:05"), m.ColimanderVersion)
		fmt.Printf("Marker:   %s\n", markerPath(name))
		fmt.Printf("Stored:   %d CPU, %d GiB memory, %d GiB disk\n", m.CPU, m.Memory, m.Disk)
	} else {
		fmt.Printf("Managed:  no\n")
	}
	if c != nil {
		fmt.Printf("Status:   %s\n", c.Status)
		fmt.Printf("Live:     %d CPU, %s memory, %s disk\n", c.CPUs, humanBytes(c.Memory), humanBytes(c.Disk))
		if c.Address != "" {
			fmt.Printf("Address:  %s\n", c.Address)
		}
		if c.Runtime != "" {
			fmt.Printf("Runtime:  %s\n", c.Runtime)
		}
	} else {
		fmt.Printf("Status:   Created (never started)\n")
	}
	return nil
}

func cmdSSH(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: colimander ssh <name> [-- cmd args...]")
	}
	name := args[0]
	fs := flag.NewFlagSet("ssh", flag.ExitOnError)
	forceUnmanaged := fs.Bool("force-unmanaged", false, "operate on a profile not managed by Colimander")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if _, err := requireManaged(name, *forceUnmanaged); err != nil {
		return err
	}
	colimaArgs := []string{"ssh", "-p", name}
	if fs.NArg() > 0 {
		colimaArgs = append(colimaArgs, "--")
		colimaArgs = append(colimaArgs, fs.Args()...)
	}
	return runColima(colimaArgs...)
}

// vmUserName returns the in-VM user Colima provisions by default: <host-user>.linux.
func vmUserName() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username + ".linux", nil
}

// limaInstanceName returns the lima instance name that backs a colima profile.
// Colima names the "default" profile's instance just "colima"; all others get
// the "colima-" prefix.
func limaInstanceName(profile string) string {
	if profile == "default" {
		return "colima"
	}
	return "colima-" + profile
}

func expandHome(p string) string {
	if !strings.HasPrefix(p, "~") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~"))
}

// ------------------------------ setup wizard --------------------------------

type depSpec struct {
	bin         string
	versionFlag string
	install     string
}

var requiredDeps = []depSpec{
	{"colima", "version", "brew install colima"},
	{"limactl", "--version", "brew install lima"},
	{"docker", "--version", "comes with colima; if missing, brew install docker"},
	{"git", "--version", "preinstalled on macOS; otherwise brew install git"},
}

func checkDeps() error {
	fmt.Println("Checking dependencies:")
	missing := 0
	for _, d := range requiredDeps {
		path, err := exec.LookPath(d.bin)
		if err != nil {
			fmt.Printf("  %-10s missing  —  install with: %s\n", d.bin, d.install)
			missing++
			continue
		}
		ver := ""
		if out, err := exec.Command(path, d.versionFlag).Output(); err == nil {
			ver = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		}
		fmt.Printf("  %-10s %s  (%s)\n", d.bin, path, ver)
	}
	if missing > 0 {
		return fmt.Errorf("%d dependency missing; install and re-run `colimander setup`", missing)
	}
	return nil
}

var profileNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

func validateProfileName(name string) error {
	if !profileNameRE.MatchString(name) {
		return fmt.Errorf("name must start with a letter/digit and be 1-31 lowercase chars, digits, or hyphens")
	}
	return nil
}

func ensureNameAvailable(name string) error {
	if m, _ := loadMarker(name); m != nil {
		return fmt.Errorf("profile %q already exists (marker at %s)", name, markerPath(name))
	}
	if _, err := os.Stat(colimaProfileDir(name)); err == nil {
		return fmt.Errorf("colima profile dir %q exists; pick another name", colimaProfileDir(name))
	}
	return nil
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("setup takes no arguments")
	}

	fmt.Println()
	fmt.Println("Colimander setup — create a new isolated project environment.")
	fmt.Println()

	if err := checkDeps(); err != nil {
		return err
	}
	fmt.Println()

	ghUser, err := ghCurrentLogin()
	if err != nil {
		return err
	}
	orgs, _ := ghOrgs()

	// Form state — all populated by huh.NewForm below.
	var name string
	cpuStr := "2"
	memStr := "4"
	diskStr := "20"
	swapStr := "4"
	doImport := false
	importPath := ""
	var pickedPkgIDs []string
	var pickedOrgs []string
	startBroker := true

	// Optional external-service broker config.
	enableFly := false
	flyToken := ""
	flyAppsCSV := ""
	enableDoppler := false
	dopplerToken := ""
	dopplerProjectsCSV := ""

	pkgOpts := make([]huh.Option[string], 0, len(availablePackages))
	for _, p := range availablePackages {
		pkgOpts = append(pkgOpts, huh.NewOption(fmt.Sprintf("%s — %s", p.Label, p.Description), p.ID))
	}
	orgOpts := make([]huh.Option[string], 0, len(orgs))
	for _, o := range orgs {
		orgOpts = append(orgOpts, huh.NewOption(o, o))
	}
	allRules := defaultDenyRules()
	denyOpts := make([]huh.Option[string], 0, len(allRules))
	for _, r := range allRules {
		denyOpts = append(denyOpts, huh.NewOption(denyRuleLabel(r), r.ID))
	}
	// Pre-select all rules so the default behavior is "enforce everything".
	pickedDenyIDs := make([]string, 0, len(allRules))
	for _, r := range allRules {
		pickedDenyIDs = append(pickedDenyIDs, r.ID)
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Project name").
				Description("Used for the VM, hostname, and editor SSH alias.").
				Value(&name).
				Validate(func(v string) error {
					if err := validateProfileName(v); err != nil {
						return err
					}
					return ensureNameAvailable(v)
				}),
		),
		huh.NewGroup(
			huh.NewInput().Title("CPU cores").Value(&cpuStr).Validate(validatePositiveInt),
			huh.NewInput().Title("Memory (GiB)").Value(&memStr).Validate(validatePositiveInt),
			huh.NewInput().Title("Disk (GiB)").Value(&diskStr).Validate(validatePositiveInt),
			huh.NewInput().Title("Swap (GiB)").Description("0 = none. Recommended ~half of memory for headroom.").Value(&swapStr).Validate(validateNonNegativeInt),
		),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Import an existing directory into the VM?").
				Description("One-shot copy at create time. After this, the VM is the source of truth — host copy is no longer touched.").
				Affirmative("Yes, import a dir").
				Negative("No, start fresh").
				Value(&doImport),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Path to import").
				Description("e.g. ~/code/myproject").
				Value(&importPath).
				Validate(validateImportPath),
		).WithHideFunc(func() bool { return !doImport }),
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Packages to install in the VM").
				Description("space toggles, enter confirms; leave blank to skip.").
				Options(pkgOpts...).
				Value(&pickedPkgIDs),
		),
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title(fmt.Sprintf("GitHub orgs this VM may touch (your user %q is always allowed)", ghUser)).
				Description("Broker denies traffic to owners not on this list.").
				Options(orgOpts...).
				Value(&pickedOrgs),
		).WithHideFunc(func() bool { return len(orgs) == 0 }),
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Broker deny rules — destructive operations to block").
				Description("All pre-selected. Uncheck any you don't want enforced. (Editable later at ~/.colima/<name>/policy.json.)").
				Options(denyOpts...).
				Value(&pickedDenyIDs).
				Height(15),
		),
		// ---- optional: fly.io brokering ----
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable fly.io API brokering?").
				Description("Lets the agent call a small allowlist of fly endpoints (app status, log streaming) via the broker. Default: read-only + logs for the apps you list.").
				Affirmative("Yes, configure fly.io").
				Negative("Skip").
				Value(&enableFly),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Fly upstream token").
				Description("Create a scoped one with `fly tokens create deploy -a <app>` or `fly tokens create org-read-only -o <org>`. Stored at ~/.colimander/tokens.json (0600).").
				EchoMode(huh.EchoModePassword).
				Value(&flyToken).
				Validate(validateNonEmpty),
			huh.NewInput().
				Title("Allowed fly app names").
				Description("Comma-separated. The broker refuses requests to apps not on this list.").
				Value(&flyAppsCSV).
				Validate(validateNonEmpty),
		).WithHideFunc(func() bool { return !enableFly }),
		// ---- optional: doppler brokering ----
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable Doppler secrets brokering?").
				Description("Lets the agent add secrets to listed projects. Reads and deletes are denied by default.").
				Affirmative("Yes, configure Doppler").
				Negative("Skip").
				Value(&enableDoppler),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Doppler upstream token").
				Description("Create a service token at https://dashboard.doppler.com (Workplace → Tokens). Scope it to one project + config for least privilege. Stored at ~/.colimander/tokens.json (0600).").
				EchoMode(huh.EchoModePassword).
				Value(&dopplerToken).
				Validate(validateNonEmpty),
			huh.NewInput().
				Title("Allowed Doppler project names").
				Description("Comma-separated. The broker refuses requests carrying a `project` query value outside this list.").
				Value(&dopplerProjectsCSV).
				Validate(validateNonEmpty),
		).WithHideFunc(func() bool { return !enableDoppler }),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Start the credential broker now?").
				Description("Required for VM→GitHub traffic. If you skip, the next `colimander start` will activate it.").
				Affirmative("Start").
				Negative("Skip for now").
				Value(&startBroker),
		),
	)
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			fmt.Println("Aborted. Nothing created.")
			return nil
		}
		return err
	}

	cpu, _ := strconv.Atoi(cpuStr)
	memory, _ := strconv.Atoi(memStr)
	disk, _ := strconv.Atoi(diskStr)
	swap, _ := strconv.Atoi(swapStr)
	if doImport {
		if abs, err := filepath.Abs(expandHome(importPath)); err == nil {
			importPath = abs
		}
	} else {
		importPath = ""
	}
	pkgs := pkgsFromIDs(pickedPkgIDs)
	policy := &Policy{
		Version:       policyVersion,
		Handle:        generateHandle(),
		AllowedOwners: append([]string{ghUser}, pickedOrgs...),
		DenyRules:     filterRulesByID(allRules, pickedDenyIDs),
	}
	if enableFly {
		policy.FlyPolicy = &FlyPolicy{
			AllowedApps:      splitCSV(flyAppsCSV),
			AllowedEndpoints: defaultFlyEndpoints(),
		}
	}
	if enableDoppler {
		policy.DopplerPolicy = &DopplerPolicy{
			AllowedProjects:  splitCSV(dopplerProjectsCSV),
			AllowedEndpoints: defaultDopplerEndpoints(),
		}
	}

	fmt.Println("About to create:")
	fmt.Printf("  Profile:        %s\n", name)
	swapStrLabel := "none"
	if swap > 0 {
		swapStrLabel = fmt.Sprintf("%d GiB", swap)
	}
	fmt.Printf("  Resources:      %d CPU / %d GiB RAM / %d GiB disk / swap %s\n", cpu, memory, disk, swapStrLabel)
	if importPath != "" {
		fmt.Printf("  Import:         %s\n", importPath)
	}
	if len(pkgs) > 0 {
		labels := make([]string, 0, len(pkgs))
		for _, p := range pkgs {
			labels = append(labels, p.Label)
		}
		fmt.Printf("  Packages:       %s\n", strings.Join(labels, ", "))
	}
	fmt.Printf("  Allowed owners: %s\n", strings.Join(policy.AllowedOwners, ", "))
	fmt.Printf("  Deny rules:     %d / %d enforced\n", len(policy.DenyRules), len(allRules))
	if policy.FlyPolicy != nil {
		fmt.Printf("  Fly apps:       %s (%d allowed endpoint(s))\n",
			strings.Join(policy.FlyPolicy.AllowedApps, ", "), len(policy.FlyPolicy.AllowedEndpoints))
	}
	if policy.DopplerPolicy != nil {
		fmt.Printf("  Doppler projects: %s (%d allowed endpoint(s))\n",
			strings.Join(policy.DopplerPolicy.AllowedProjects, ", "), len(policy.DopplerPolicy.AllowedEndpoints))
	}
	if startBroker {
		fmt.Println("  Broker:         start now + wire VM-side git/api routing")
	} else {
		fmt.Println("  Broker:         skip (will activate on next `colimander start`)")
	}
	fmt.Println()

	var proceed bool
	if err := huh.NewConfirm().
		Title("Proceed?").
		Affirmative("Yes, create").
		Negative("Cancel").
		Value(&proceed).
		Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			fmt.Println("Aborted. Nothing created.")
			return nil
		}
		return err
	}
	if !proceed {
		fmt.Println("Aborted. Nothing created.")
		return nil
	}
	fmt.Println()

	m := &marker{
		Name:              name,
		CreatedAt:         time.Now().UTC(),
		ColimanderVersion: version,
		CPU:               cpu,
		Memory:            memory,
		Disk:              disk,
		SwapGiB:           swap,
	}
	if importPath != "" {
		m.ImportedFrom = importPath
		m.ImportMode = "dir"
	}
	if err := writeMarker(m); err != nil {
		return err
	}
	if err := writeColimaConfig(m); err != nil {
		return err
	}
	if err := savePolicy(name, policy); err != nil {
		return fmt.Errorf("save policy: %w", err)
	}
	if enableFly || enableDoppler {
		pt := ProfileTokens{}
		if enableFly {
			pt.Fly = strings.TrimSpace(flyToken)
		}
		if enableDoppler {
			pt.Doppler = strings.TrimSpace(dopplerToken)
		}
		if err := setProfileTokens(name, pt); err != nil {
			return fmt.Errorf("save upstream tokens: %w", err)
		}
	}
	if err := startProfile(m); err != nil {
		return err
	}
	if importPath != "" {
		if err := importDirIntoVM(name, importPath); err != nil {
			return fmt.Errorf("import-dir: %w", err)
		}
	}
	if startBroker {
		if err := activateBrokerForProfile(name); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
	installBaseline(name)
	installPackages(name, pkgs)

	fmt.Println()
	fmt.Println("Profile ready. Next steps:")
	fmt.Printf("  - Edit over SSH (in your editor's remote-host picker):  lima-%s\n", limaInstanceName(name))
	if importPath != "" {
		vmUser, _ := vmUserName()
		fmt.Printf("    Source landed at /home/%s/%s inside the VM.\n", vmUser, filepath.Base(importPath))
	}
	fmt.Printf("  - Browser:       http://%s.local:<port>\n", name)
	fmt.Printf("  - List ports:    colimander ports %s\n", name)
	fmt.Printf("  - SSH shell:     colimander ssh %s\n", name)
	fmt.Printf("  - Stop:          colimander stop %s\n", name)
	fmt.Println()
	return nil
}

// ------------------------------ wizard helpers ------------------------------

func validatePositiveInt(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("required")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("must be an integer")
	}
	if n <= 0 {
		return fmt.Errorf("must be > 0")
	}
	return nil
}

func validateNonEmpty(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("required")
	}
	return nil
}

// splitCSV splits a comma-separated list, trims whitespace, drops empties.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func validateNonNegativeInt(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("required")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("must be an integer")
	}
	if n < 0 {
		return fmt.Errorf("must be >= 0")
	}
	return nil
}

func validateImportPath(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("required")
	}
	abs, err := filepath.Abs(expandHome(s))
	if err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("%s: %w", abs, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", abs)
	}
	return nil
}

// denyRuleLabel renders a deny rule as one line suitable for huh's MultiSelect.
// API rules show as "METHOD path-glob — reason"; git rules show as "git push
// delete <ref> — reason". Truncated at ~110 chars to keep the list scannable.
func denyRuleLabel(r DenyRule) string {
	var head string
	switch r.Kind {
	case "api":
		head = fmt.Sprintf("%-6s %s", r.Method, r.PathGlob)
	case "git-delete-ref":
		head = "git push delete " + r.RefGlob
	default:
		head = r.ID
	}
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

func pkgsFromIDs(ids []string) []vmPackage {
	out := make([]vmPackage, 0, len(ids))
	for _, id := range ids {
		for _, p := range availablePackages {
			if p.ID == id {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// ------------------------------ policy subcommand --------------------------

func cmdPolicy(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: colimander policy {default [--owner NAME...]|show <profile>}")
	}
	switch args[0] {
	case "default":
		fs := flag.NewFlagSet("policy default", flag.ExitOnError)
		var owners multiFlag
		fs.Var(&owners, "owner", "allowed owner (repeat for multiple)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if len(owners) == 0 {
			if u, err := ghCurrentLogin(); err == nil {
				owners = []string{u}
			}
		}
		p := &Policy{Version: policyVersion, AllowedOwners: owners, DenyRules: defaultDenyRules()}
		data, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	case "show":
		if len(args) < 2 {
			return errors.New("usage: colimander policy show <profile>")
		}
		p, err := loadPolicy(args[1])
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	default:
		return fmt.Errorf("unknown policy subcommand %q", args[0])
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// ------------------------------ gh shellouts -------------------------------

func ghCurrentLogin() (string, error) {
	out, err := exec.Command("gh", "api", "user", "--jq", ".login").Output()
	if err != nil {
		return "", fmt.Errorf("gh api user: %w (is `gh auth status` healthy?)", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func ghOrgs() ([]string, error) {
	out, err := exec.Command("gh", "api", "user/orgs", "--paginate", "--jq", ".[].login").Output()
	if err != nil {
		return nil, fmt.Errorf("gh api user/orgs: %w", err)
	}
	var orgs []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			orgs = append(orgs, l)
		}
	}
	return orgs, nil
}

// ------------------------------ init ----------------------------------------

const sshIncludeLine = "Include ~/.lima/*/ssh.config"

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("init takes no arguments")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	configPath := filepath.Join(sshDir, "config")
	existing, err := os.ReadFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == sshIncludeLine {
			fmt.Printf("~/.ssh/config already includes Lima profiles. Nothing to do.\n")
			return nil
		}
	}
	block := fmt.Sprintf("\n# Added by colimander: makes Lima/Colima profiles visible to editors via SSH-remote.\n%s\n", sshIncludeLine)
	f, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(block); err != nil {
		return err
	}
	fmt.Printf("Added %q to %s.\n", sshIncludeLine, configPath)
	fmt.Println("Your editor's SSH-remote picker should now show lima-colima-<profile> hosts.")
	return nil
}

// ------------------------------ /etc/hosts ----------------------------------

const (
	hostsFile        = "/etc/hosts"
	hostsBeginMarker = "# BEGIN colimander (managed automatically; do not edit between markers)"
	hostsEndMarker   = "# END colimander"
)

// desiredHostsBlock returns the colimander-managed block to splice into
// /etc/hosts, or the empty string if no managed profiles currently have an
// address. The trailing newline is always included when non-empty.
func desiredHostsBlock() (string, error) {
	managed, err := listManagedNames()
	if err != nil {
		return "", err
	}
	coli, err := listProfiles()
	if err != nil {
		return "", err
	}
	addr := map[string]string{}
	for _, e := range coli {
		if e.Address != "" {
			addr[e.Name] = e.Address
		}
	}
	var rows []string
	for _, n := range managed {
		ip, ok := addr[n]
		if !ok {
			continue
		}
		rows = append(rows, fmt.Sprintf("%s\t%s.local", ip, n))
	}
	if len(rows) == 0 {
		return "", nil
	}
	return hostsBeginMarker + "\n" + strings.Join(rows, "\n") + "\n" + hostsEndMarker + "\n", nil
}

// splitHostsBlock locates the existing colimander block (if any) and returns
// the surrounding before/after slices.
func splitHostsBlock(contents string) (before, block, after string) {
	bi := strings.Index(contents, hostsBeginMarker)
	if bi < 0 {
		return contents, "", ""
	}
	ei := strings.Index(contents[bi:], hostsEndMarker)
	if ei < 0 {
		return contents, "", ""
	}
	ei += bi + len(hostsEndMarker)
	if ei < len(contents) && contents[ei] == '\n' {
		ei++
	}
	return contents[:bi], contents[bi:ei], contents[ei:]
}

// syncEtcHosts rewrites the colimander-managed block in /etc/hosts to reflect
// the currently running managed profiles. It only invokes sudo when the file
// actually needs changing.
func syncEtcHosts() error {
	desired, err := desiredHostsBlock()
	if err != nil {
		return err
	}
	current, err := os.ReadFile(hostsFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", hostsFile, err)
	}
	before, _, after := splitHostsBlock(string(current))
	var next string
	if desired == "" {
		next = before + after
	} else {
		b := before
		if b != "" && !strings.HasSuffix(b, "\n") {
			b += "\n"
		}
		next = b + desired + after
	}
	if next == string(current) {
		return nil
	}
	tmp, err := os.CreateTemp("", "colimander-hosts-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(next); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Updating /etc/hosts (sudo prompt may follow)...")
	cmd := exec.Command("sudo", "cp", tmpPath, hostsFile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmdHostsSync(args []string) error {
	fs := flag.NewFlagSet("hosts-sync", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("hosts-sync takes no arguments")
	}
	return syncEtcHosts()
}

// ------------------------------ source import -------------------------------

// limaHome returns the directory where colima keeps its bundled lima
// instances. Colima 0.8+ puts them under ~/.colima/_lima/ instead of the
// default ~/.lima/, so any limactl invocation needs LIMA_HOME pointed there.
func limaHome() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".colima", "_lima")
}

// runLimactl runs `limactl <args>` with the colima-managed LIMA_HOME so
// instance names like colima-<profile> resolve correctly.
func runLimactl(args ...string) error {
	cmd := exec.Command("limactl", args...)
	cmd.Env = append(os.Environ(), "LIMA_HOME="+limaHome())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// importDirIntoVM copies a host directory into the VM at /home/<vmuser>/<basename>.
// Caller is responsible for ensuring the VM is running.
//
// While limactl cp runs (silent, single-stream scp), a background goroutine
// polls the VM target with `du -sb` every 2s and rewrites a single line with
// "X / Y (Z%) — elapsed". Stops on completion or any limactl error.
func importDirIntoVM(profile, srcDir string) error {
	abs, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("import-dir %q: %w", abs, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("import-dir %q is not a directory", abs)
	}
	vmUser, err := vmUserName()
	if err != nil {
		return err
	}
	instance := limaInstanceName(profile)
	dest := fmt.Sprintf("%s:/home/%s/", instance, vmUser)
	vmTarget := fmt.Sprintf("/home/%s/%s", vmUser, filepath.Base(abs))

	fmt.Printf("Importing %s into %s%s ...\n", abs, dest, filepath.Base(abs))

	srcSize, sizeErr := dirAppSize(abs)

	cmd := exec.Command("limactl", "cp", "-r", abs, dest)
	cmd.Env = append(os.Environ(), "LIMA_HOME="+limaHome())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	if sizeErr == nil && srcSize > 0 && isTTY(os.Stdout) {
		go func() {
			defer close(done)
			progressLoop(profile, vmTarget, srcSize, stop)
		}()
	} else {
		close(done)
	}

	waitErr := cmd.Wait()
	close(stop)
	<-done

	if isTTY(os.Stdout) && sizeErr == nil && srcSize > 0 {
		if waitErr == nil {
			fmt.Printf("\r  %s imported.%s\n", humanSize(srcSize), strings.Repeat(" ", 40))
		} else {
			fmt.Printf("\r%s\r", strings.Repeat(" ", 80))
		}
	}
	return waitErr
}

func dirAppSize(p string) (int64, error) {
	var total int64
	err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func progressLoop(profile, vmPath string, total int64, stop <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	start := time.Now()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			n, err := vmPathBytes(profile, vmPath)
			if err != nil {
				continue
			}
			pct := float64(n) / float64(total) * 100
			if pct > 100 {
				pct = 100
			}
			elapsed := time.Since(start).Round(time.Second)
			fmt.Printf("\r  %s / %s  (%3.0f%%)  %s elapsed   ",
				humanSize(n), humanSize(total), pct, elapsed)
		}
	}
}

func vmPathBytes(profile, path string) (int64, error) {
	out, err := exec.Command("colima", "ssh", "-p", profile, "--", "du", "-sb", path).Output()
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 1 {
		return 0, errors.New("empty du output")
	}
	return strconv.ParseInt(fields[0], 10, 64)
}

func humanSize(n int64) string {
	const (
		kib = 1024
		mib = kib * 1024
		gib = mib * 1024
	)
	switch {
	case n >= gib:
		return fmt.Sprintf("%.2f GiB", float64(n)/float64(gib))
	case n >= mib:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(mib))
	case n >= kib:
		return fmt.Sprintf("%.0f KiB", float64(n)/float64(kib))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// ------------------------------ ports ---------------------------------------

// portsLineRE matches `ss -Hltn` output. We pull the local-address column (col 4)
// and the optional `users:(("name"...` process column. Example:
//
//	LISTEN 0      511                          *:3000              *:*    users:(("node",pid=123,fd=10))
var (
	ssLineRE = regexp.MustCompile(`^LISTEN\s+\S+\s+\S+\s+(\S+)\s+\S+(?:\s+(.*))?$`)
	ssProcRE = regexp.MustCompile(`users:\(\("([^"]+)"`)
)

type listenEntry struct {
	port int
	proc string
}

func parseSSOutput(out string) []listenEntry {
	var entries []listenEntry
	seen := map[int]string{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		m := ssLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		local := m[1]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(local[i+1:], "%d", &port); err != nil {
			continue
		}
		proc := ""
		if len(m) >= 3 {
			if pm := ssProcRE.FindStringSubmatch(m[2]); pm != nil {
				proc = pm[1]
			}
		}
		if existing, ok := seen[port]; ok {
			if existing == "" && proc != "" {
				seen[port] = proc
			}
			continue
		}
		seen[port] = proc
		entries = append(entries, listenEntry{port: port, proc: proc})
	}
	// Backfill any updated proc names from the seen map.
	for i := range entries {
		if seen[entries[i].port] != "" {
			entries[i].proc = seen[entries[i].port]
		}
	}
	return entries
}

func cmdPorts(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: colimander ports <name>")
	}
	name := args[0]
	fs := flag.NewFlagSet("ports", flag.ExitOnError)
	forceUnmanaged := fs.Bool("force-unmanaged", false, "operate on a profile not managed by Colimander")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}
	if _, err := requireManaged(name, *forceUnmanaged); err != nil {
		return err
	}
	out, err := exec.Command("colima", "ssh", "-p", name, "--", "sudo", "ss", "-Hltnp").Output()
	if err != nil {
		return fmt.Errorf("listing ports via ssh: %w", err)
	}
	entries := parseSSOutput(string(out))
	if len(entries) == 0 {
		fmt.Println("(no TCP listeners inside the VM)")
		return nil
	}
	const row = "%-6s %-20s %s\n"
	fmt.Printf(row, "PORT", "PROCESS", "URL")
	for _, e := range entries {
		proc := e.proc
		if proc == "" {
			proc = "-"
		}
		fmt.Printf(row, fmt.Sprintf("%d", e.port), proc, fmt.Sprintf("http://%s.local:%d", name, e.port))
	}
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `Colimander — safe per-project Colima profile management.

Commands:
  setup                               interactive wizard: deps check, name, specs, optional import
  init                                add the Lima SSH include to ~/.ssh/config (one-time setup)
  ls [--all]                          list Colimander-managed profiles (--all shows everything)
  create <name> [--cpu N] [--memory G] [--disk G] [--start] [--import-dir PATH]
                                      create a new profile; --import-dir copies a host directory
                                      into the VM after first boot (implies --start)
  start <name>                        start a Colimander-managed profile with its stored resources
  stop <name>                         stop a profile
  destroy <name> --yes                permanently delete a profile (VM + marker + dir)
  ssh <name> [-- cmd args...]         SSH into a profile (or run a command in it)
  status <name>                       show detailed status for a single profile
  ports <name>                        list TCP listeners inside the VM with host-side URLs
  hosts-sync                          rewrite the colimander block in /etc/hosts (recovery)
  broker {run|start|stop|status|tail} run the credential broker (proxy for github.com / api.github.com)
  policy {default|show <name>}        emit default policy JSON, or show a profile's current policy
  packages <name>                     install optional packages (claude-code, opencode, postgres, …) into a profile
  tokens {set|list|clear} ...         manage upstream tokens for fly.io / doppler brokers (~/.colimander/tokens.json)
  version                             print version

All mutating commands refuse profiles without a Colimander marker unless
--force-unmanaged is passed. This is the guardrail against accidentally
touching other Colima profiles you have running.`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "init":
		err = cmdInit(os.Args[2:])
	case "ls", "list":
		err = cmdLs(os.Args[2:])
	case "create":
		err = cmdCreate(os.Args[2:])
	case "start":
		err = cmdStart(os.Args[2:])
	case "stop":
		err = cmdStop(os.Args[2:])
	case "destroy":
		err = cmdDestroy(os.Args[2:])
	case "ssh":
		err = cmdSSH(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "ports":
		err = cmdPorts(os.Args[2:])
	case "hosts-sync":
		err = cmdHostsSync(os.Args[2:])
	case "broker":
		err = cmdBroker(os.Args[2:])
	case "policy":
		err = cmdPolicy(os.Args[2:])
	case "packages":
		err = cmdPackages(os.Args[2:])
	case "tokens":
		err = cmdTokens(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("colimander", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
