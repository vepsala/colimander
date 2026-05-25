// Colimander v0 — minimal CLI wrapper around Colima for safe per-profile lifecycle.
//
// Safety model: every profile this tool creates gets a marker file at
// ~/.colima/<name>/.colimander.json. Mutating commands (start, stop, destroy)
// refuse to operate on profiles without a marker unless --force-unmanaged
// is passed. This is the guardrail that keeps Colimander from ever
// accidentally touching the user's other Colima profiles.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

	const rowFmt = "%-20s %-8s %-10s %-4s %-7s %-7s %-16s %s\n"
	fmt.Printf(rowFmt, "PROFILE", "MANAGED", "STATUS", "CPU", "MEM", "DISK", "ADDRESS", "RUNTIME")

	printRow := func(name string, e *colimaListEntry, isManaged bool) {
		managedStr := "no"
		if isManaged {
			managedStr = "yes"
		}
		if e != nil {
			addr := e.Address
			if addr == "" {
				addr = "-"
			}
			runtime := e.Runtime
			if runtime == "" {
				runtime = "-"
			}
			fmt.Printf(rowFmt, name, managedStr, e.Status, fmt.Sprintf("%d", e.CPUs),
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
		fmt.Printf(rowFmt, name, managedStr, "Created", cpu, mem, disk, "-", "-")
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
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected extra arguments: %v", fs.Args())
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
	return startProfile(m)
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
	return runColima("start", m.Name, "--mount", emptyMnt+":r")
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
	return startProfile(m)
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

func usage() {
	fmt.Fprintln(os.Stderr, `Colimander — safe per-project Colima profile management.

Commands:
  ls [--all]                          list Colimander-managed profiles (--all shows everything)
  create <name> [--cpu N] [--memory G] [--disk G] [--start]
                                      create a new profile (marker only; --start to also start it)
  start <name>                        start a Colimander-managed profile with its stored resources
  stop <name>                         stop a profile
  destroy <name> --yes                permanently delete a profile (VM + marker + dir)
  ssh <name> [-- cmd args...]         SSH into a profile (or run a command in it)
  status <name>                       show detailed status for a single profile
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
