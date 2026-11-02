// `colimander packages`: add optional packages to an existing profile.

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/vepsala/colimander/internal/sandbox"
)

// promptForPackages is the standalone (non-wizard) huh prompt used by
// `colimander packages <name>`. The setup wizard inlines the same options
// into its big form instead of calling this.
func promptForPackages() []sandbox.Package {
	opts := make([]huh.Option[string], 0, len(sandbox.Packages))
	for _, p := range sandbox.Packages {
		opts = append(opts, huh.NewOption(fmt.Sprintf("%s — %s", p.Label, p.Description), p.ID))
	}
	var picked []string
	err := huh.NewForm(huh.NewGroup(
		huh.NewMultiSelect[string]().
			Title("Packages to install in the VM").
			Description("space toggles, enter confirms; leave blank to skip.").
			Options(opts...).
			Value(&picked),
	)).Run()
	if err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return nil
		}
		fmt.Fprintln(os.Stderr, "package selection:", err)
		return nil
	}
	return sandbox.PackagesFromIDs(picked)
}

// cmdPackages is the standalone `colimander packages <profile>` entrypoint,
// for adding packages to an existing profile without re-running setup.
func cmdPackages(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: colimander packages <name>")
	}
	name := args[0]
	if _, err := requireManaged(name, false); err != nil {
		return err
	}
	pkgs := promptForPackages()
	if len(pkgs) == 0 {
		fmt.Println("Nothing selected. Exiting.")
		return nil
	}
	installPackages(name, pkgs)
	return nil
}

// installPackages runs each selected package's script inside the VM.
// Failures are surfaced but don't abort.
func installPackages(profile string, pkgs []sandbox.Package) {
	if len(pkgs) == 0 {
		return
	}
	fmt.Printf("\nInstalling %d package(s) inside the VM:\n", len(pkgs))
	for _, p := range pkgs {
		if err := sandbox.InstallPackage(profile, p, terminal); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: %v.\n", err)
		}
	}
}
