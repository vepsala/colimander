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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/vepsala/colimander/internal/broker"
	dbcli "github.com/vepsala/colimander/internal/pgproxy/cli"
	"github.com/vepsala/colimander/internal/sandbox"
)

const version = "0.1.0-dev"

// terminal is what commands the CLI runs read from and write to.
var terminal = sandbox.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}

// requireManaged loads the marker and returns it. If the profile has no
// marker, it refuses unless forceUnmanaged is set, in which case it returns
// (nil, nil) and the caller falls back to a plain colima invocation.
func requireManaged(name string, forceUnmanaged bool) (*sandbox.Marker, error) {
	m, err := sandbox.LoadMarker(name)
	if err != nil {
		return nil, err
	}
	if m == nil {
		if forceUnmanaged {
			fmt.Fprintf(os.Stderr, "warning: profile %q is not Colimander-managed; --force-unmanaged was passed.\n", name)
			return nil, nil
		}
		return nil, fmt.Errorf("profile %q is not managed by Colimander (no marker at %s). Refusing. Pass --force-unmanaged to override", name, sandbox.MarkerPath(name))
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
		if _, err := os.Stat(filepath.Join(colimaDir, d.Name(), sandbox.MarkerName)); err == nil {
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
		if _, err := os.Stat(broker.PolicyPath(name)); err == nil {
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
		m, _ := sandbox.LoadMarker(name)
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
	if err := sandbox.ValidateProfileName(name); err != nil {
		return err
	}
	if err := sandbox.EnsureNameAvailable(name); err != nil {
		return err
	}
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

	existing, err := sandbox.LoadMarker(name)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("profile %q already exists (marker at %s)", name, sandbox.MarkerPath(name))
	}
	if _, err := os.Stat(sandbox.ProfileDir(name)); err == nil {
		return fmt.Errorf("Colima profile directory %s exists but has no Colimander marker. Refusing to overwrite", sandbox.ProfileDir(name))
	}

	m := &sandbox.Marker{
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
	if err := sandbox.WriteMarker(m); err != nil {
		return fmt.Errorf("write marker: %w", err)
	}
	if err := sandbox.WriteColimaConfig(m); err != nil {
		return fmt.Errorf("write colima.yaml: %w", err)
	}
	fmt.Printf("Created Colimander profile %q.\n", name)
	fmt.Printf("  CPU: %d   Memory: %d GiB   Disk: %d GiB\n", *cpu, *memory, *disk)
	fmt.Printf("  Marker: %s\n", sandbox.MarkerPath(name))
	if !*start {
		fmt.Printf("\nTo start: colimander start %s\n", name)
		return nil
	}
	if err := startProfile(m); err != nil {
		return err
	}
	if *importDir != "" {
		if err := sandbox.ImportDir(name, *importDir, terminal); err != nil {
			return fmt.Errorf("import-dir: %w", err)
		}
	}
	return nil
}

func startProfile(m *sandbox.Marker) error {
	if err := sandbox.BootVM(m, terminal); err != nil {
		return err
	}
	if err := syncEtcHosts(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to update /etc/hosts: %v\n", err)
		fmt.Fprintf(os.Stderr, "  retry manually with: colimander hosts-sync\n")
	}
	if m.SwapGiB > 0 {
		if err := sandbox.EnsureSwap(m.Name, m.SwapGiB, terminal); err != nil {
			fmt.Fprintf(os.Stderr, "warning: swap setup failed: %v\n", err)
		}
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
	if _, err := os.Stat(broker.PolicyPath(name)); err == nil {
		if err := broker.ActivateBrokerForProfile(name); err != nil {
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
	if err := os.RemoveAll(sandbox.ProfileDir(name)); err != nil {
		return fmt.Errorf("cleanup %s: %w", sandbox.ProfileDir(name), err)
	}
	// Also remove the per-profile empty-mount stub dir, if any.
	_ = os.RemoveAll(sandbox.EmptyMountPath(name))
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
	m, err := sandbox.LoadMarker(name)
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
		fmt.Printf("Marker:   %s\n", sandbox.MarkerPath(name))
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

	ghUser, err := sandbox.GHCurrentLogin()
	if err != nil {
		return err
	}
	orgs, _ := sandbox.GHOrgs()

	// Form state — all populated by huh.NewForm below.
	req := sandbox.Request{
		CPU: sandbox.Defaults.CPU, Memory: sandbox.Defaults.Memory, Disk: sandbox.Defaults.Disk, Swap: sandbox.Defaults.Swap,
		StartBroker: sandbox.Defaults.StartBroker, Egress: sandbox.Defaults.Egress,
	}

	pkgOpts := make([]huh.Option[string], 0, len(sandbox.Packages))
	for _, p := range sandbox.Packages {
		pkgOpts = append(pkgOpts, huh.NewOption(fmt.Sprintf("%s — %s", p.Label, p.Description), p.ID))
	}
	orgOpts := make([]huh.Option[string], 0, len(orgs))
	for _, o := range orgs {
		orgOpts = append(orgOpts, huh.NewOption(o, o))
	}
	allRules := broker.DefaultDenyRules()
	denyOpts := make([]huh.Option[string], 0, len(allRules))
	for _, r := range allRules {
		denyOpts = append(denyOpts, huh.NewOption(broker.DenyRuleLabel(r), r.ID))
	}
	// Pre-select all rules so the default behavior is "enforce everything".
	req.DenyRuleIDs = make([]string, 0, len(allRules))
	for _, r := range allRules {
		req.DenyRuleIDs = append(req.DenyRuleIDs, r.ID)
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Project name").
				Description("Used for the VM, hostname, and editor SSH alias.").
				Value(&req.Name).
				Validate(sandbox.ValidateName),
		),
		huh.NewGroup(
			huh.NewInput().Title("CPU cores").Value(&req.CPU).Validate(sandbox.ValidatePositiveInt),
			huh.NewInput().Title("Memory (GiB)").Value(&req.Memory).Validate(sandbox.ValidatePositiveInt),
			huh.NewInput().Title("Disk (GiB)").Value(&req.Disk).Validate(sandbox.ValidatePositiveInt),
			huh.NewInput().Title("Swap (GiB)").Description("0 = none. Recommended ~half of memory for headroom.").Value(&req.Swap).Validate(sandbox.ValidateNonNegativeInt),
		),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Import an existing directory into the VM?").
				Description("One-shot copy at create time. After this, the VM is the source of truth — host copy is no longer touched.").
				Affirmative("Yes, import a dir").
				Negative("No, start fresh").
				Value(&req.Import),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Path to import").
				Description("e.g. ~/code/myproject").
				Value(&req.ImportPath).
				Validate(sandbox.ValidateImportPath),
		).WithHideFunc(func() bool { return !req.Import }),
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Packages to install in the VM").
				Description("space toggles, enter confirms; leave blank to skip.").
				Options(pkgOpts...).
				Value(&req.Packages),
		),
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title(fmt.Sprintf("GitHub orgs this VM may touch (your user %q is always allowed)", ghUser)).
				Description("Broker denies traffic to owners not on this list.").
				Options(orgOpts...).
				Value(&req.Orgs),
		).WithHideFunc(func() bool { return len(orgs) == 0 }),
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Broker deny rules — destructive operations to block").
				Description("All pre-selected. Uncheck any you don't want enforced. (Editable later at ~/.colima/<name>/policy.json.)").
				Options(denyOpts...).
				Value(&req.DenyRuleIDs).
				Height(15),
		),
		// ---- optional: fly.io brokering ----
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable fly.io API brokering?").
				Description("Lets the agent call a small allowlist of fly endpoints (app status, log streaming) via the broker. Default: read-only + logs, for all apps or just the ones you list.").
				Affirmative("Yes, configure fly.io").
				Negative("Skip").
				Value(&req.EnableFly),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Fly upstream token").
				Description("Create a scoped one with `fly tokens create deploy -a <app>` or `fly tokens create readonly -o <org>`. Stored encrypted in ~/.colimander/vault.db.").
				EchoMode(huh.EchoModePassword).
				Value(&req.FlyToken).
				Validate(sandbox.ValidateNonEmpty),
			huh.NewInput().
				Title("Allowed fly app names").
				Description("Comma-separated. Leave blank to allow all apps the token can see (endpoints stay read-only + logs).").
				Value(&req.FlyApps),
		).WithHideFunc(func() bool { return !req.EnableFly }),
		// ---- optional: doppler brokering ----
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable Doppler secrets brokering?").
				Description("Lets the agent add secrets to listed projects. Reads and deletes are denied by default.").
				Affirmative("Yes, configure Doppler").
				Negative("Skip").
				Value(&req.EnableDoppler),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Doppler upstream token").
				Description("Create a service token at https://dashboard.doppler.com (Workplace → Tokens). Scope it to one project + config for least privilege. Stored encrypted in ~/.colimander/vault.db.").
				EchoMode(huh.EchoModePassword).
				Value(&req.DopplerToken).
				Validate(sandbox.ValidateNonEmpty),
			huh.NewInput().
				Title("Allowed Doppler project names").
				Description("Comma-separated. The broker refuses requests carrying a `project` query value outside this list.").
				Value(&req.DopplerProjects).
				Validate(sandbox.ValidateNonEmpty),
		).WithHideFunc(func() bool { return !req.EnableDoppler }),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Start the credential broker now?").
				Description("Required for VM→GitHub traffic. If you skip, the next `colimander start` will activate it.").
				Affirmative("Start").
				Negative("Skip for now").
				Value(&req.StartBroker),
		),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Monitor this sandbox's web traffic?").
				Description("Records destinations and byte counts. Nothing is blocked, but the VM loses web access while the daemon is down.").
				Affirmative("Monitor").
				Negative("Skip").
				Value(&req.Egress),
		).WithHideFunc(func() bool { return !req.StartBroker }),
	)
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			fmt.Println("Aborted. Nothing created.")
			return nil
		}
		return err
	}
	if !req.StartBroker {
		req.Egress = false
	}
	spec, secrets, err := req.Spec(version, ghUser, req.DenyRuleIDs)
	if err != nil {
		return err
	}
	pkgs := sandbox.PackagesFromIDs(spec.Packages)

	fmt.Println("About to create:")
	fmt.Printf("  Profile:        %s\n", spec.Name)
	swapStrLabel := "none"
	if spec.Swap > 0 {
		swapStrLabel = fmt.Sprintf("%d GiB", spec.Swap)
	}
	fmt.Printf("  Resources:      %d CPU / %d GiB RAM / %d GiB disk / swap %s\n", spec.CPU, spec.Memory, spec.Disk, swapStrLabel)
	if spec.ImportPath != "" {
		fmt.Printf("  Import:         %s\n", spec.ImportPath)
	}
	if len(pkgs) > 0 {
		labels := make([]string, 0, len(pkgs))
		for _, p := range pkgs {
			labels = append(labels, p.Label)
		}
		fmt.Printf("  Packages:       %s\n", strings.Join(labels, ", "))
	}
	fmt.Printf("  Allowed owners: %s\n", strings.Join(append([]string{spec.Login}, spec.Orgs...), ", "))
	fmt.Printf("  Deny rules:     %d / %d enforced\n", len(spec.DenyRules), len(allRules))
	if spec.Fly {
		flyApps := strings.Join(spec.FlyApps, ", ")
		if broker.ContainsFold(spec.FlyApps, "*") {
			flyApps = "all apps"
		}
		fmt.Printf("  Fly apps:       %s (%d allowed endpoint(s))\n", flyApps, len(broker.DefaultFlyEndpoints()))
	}
	if spec.Doppler {
		fmt.Printf("  Doppler projects: %s (%d allowed endpoint(s))\n",
			strings.Join(spec.Projects, ", "), len(broker.DefaultDopplerEndpoints()))
	}
	if spec.Broker {
		fmt.Println("  Broker:         start now + wire VM-side git/api routing")
	} else {
		fmt.Println("  Broker:         skip (will activate on next `colimander start`)")
	}
	if spec.Egress {
		fmt.Println("  Egress:         monitor web traffic")
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

	hooks := broker.SetupHooks()
	hooks.AfterBoot = func(string) {
		if err := syncEtcHosts(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to update /etc/hosts: %v\n", err)
			fmt.Fprintf(os.Stderr, "  retry manually with: colimander hosts-sync\n")
		}
	}
	for _, step := range sandbox.Steps(spec, secrets, hooks) {
		if err := step.Run(terminal); err != nil {
			if !step.Soft {
				return err
			}
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}

	fmt.Println()
	fmt.Println("Profile ready. Next steps:")
	for _, n := range sandbox.NextSteps(spec) {
		fmt.Printf("  - %s:  %s\n", n.Label, n.Value)
	}
	fmt.Println()
	return nil
}

// checkDeps prints what setup needs and fails if anything's missing.
func checkDeps() error {
	fmt.Println("Checking dependencies:")
	missing := 0
	for _, d := range sandbox.CheckDeps() {
		if !d.OK {
			fmt.Printf("  %-10s missing  —  install with: %s\n", d.Bin, d.Install)
			missing++
			continue
		}
		fmt.Printf("  %-10s %s  (%s)\n", d.Bin, d.Path, d.Version)
	}
	if missing > 0 {
		return fmt.Errorf("%d dependency missing; install and re-run `colimander setup`", missing)
	}
	return nil
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
			if u, err := sandbox.GHCurrentLogin(); err == nil {
				owners = []string{u}
			}
		}
		p := &broker.Policy{Version: broker.PolicyVersion, AllowedOwners: owners, DenyRules: broker.DefaultDenyRules()}
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
		p, err := broker.LoadPolicy(args[1])
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

// runLimactl runs `limactl <args>` with the colima-managed LIMA_HOME so
// instance names like colima-<profile> resolve correctly.
func runLimactl(args ...string) error {
	cmd := exec.Command("limactl", args...)
	cmd.Env = append(os.Environ(), "LIMA_HOME="+sandbox.LimaHome())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
  logs [--limit N]                    live TUI over the broker audit log (filter by profile/surface/action)
  policy {default|show <name>}        emit default policy JSON, or show a profile's current policy
  packages <name>                     install optional packages (claude-code, opencode, postgres, …) into a profile
  tokens {set|list|clear} ...         manage upstream tokens for fly.io / doppler brokers (~/.colimander/tokens.json)
  egress {enable|disable|status} <name>  record where a sandbox's web traffic goes
  suspend <name> [reason]             cut a sandbox off from the broker; the VM keeps running
  resume <name>                       restore a suspended sandbox with new credentials
  version                             print version

All mutating commands refuse profiles without a Colimander marker unless
--force-unmanaged is passed. This is the guardrail against accidentally
touching other Colima profiles you have running.`)
}

func main() {
	broker.Version = version
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
		err = broker.CmdBroker(os.Args[2:])
	case "db":
		err = dbcli.Run(os.Args[2:])
	case "logs":
		err = broker.CmdLogs(os.Args[2:])
	case "policy":
		err = cmdPolicy(os.Args[2:])
	case "packages":
		err = cmdPackages(os.Args[2:])
	case "tokens":
		err = broker.CmdTokens(os.Args[2:])
	case "egress":
		err = broker.CmdEgress(os.Args[2:])
	case "suspend":
		err = broker.CmdSuspend(os.Args[2:])
	case "resume":
		err = broker.CmdResume(os.Args[2:])
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
