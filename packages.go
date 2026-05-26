// Optional packages the wizard can install into a newly-created VM.
//
// Each package has a single bash script that the wizard pipes via stdin to
// `bash -s` on the remote. Stdin-piping side-steps the classic SSH quoting
// trap (where multi-arg shell strings get concatenated and re-parsed once on
// the host and once on the remote).
//
// Failures are warnings, not fatal — the wizard's already produced a usable
// VM; a missing package is fixable later with `colimander ssh <name>`.

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/huh"
)

type vmPackage struct {
	ID          string
	Label       string
	Description string
	Script      string
}

var availablePackages = []vmPackage{
	{
		ID:          "claude-code",
		Label:       "Claude Code",
		Description: "Anthropic agent CLI (official installer)",
		Script:      `curl -fsSL https://claude.ai/install.sh | bash`,
	},
	{
		ID:          "opencode",
		Label:       "OpenCode",
		Description: "SST OpenCode agent",
		Script:      `curl -fsSL https://opencode.ai/install | bash`,
	},
	{
		ID:    "postgres-16",
		Label: "PostgreSQL 16",
		Description: "PostgreSQL 16 from the PGDG apt repo, enabled as a system service",
		Script: `set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y -qq curl ca-certificates lsb-release gnupg
sudo install -d -m 0755 /usr/share/postgresql-common/pgdg
sudo curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
  -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
  | sudo tee /etc/apt/sources.list.d/pgdg.list > /dev/null
sudo apt-get update -qq
sudo apt-get install -y -qq postgresql-16
sudo systemctl enable --now postgresql
echo "  PostgreSQL 16 listening; connect locally as: sudo -u postgres psql"`,
	},
	{
		ID:          "node-mise",
		Label:       "Node.js LTS (via mise)",
		Description: "mise as the polyglot version manager + Node LTS + pnpm. mise auto-switches versions per project via .tool-versions / .mise.toml.",
		Script: `set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y -qq curl ca-certificates
# Install mise to ~/.local/bin (no sudo required).
curl -fsSL https://mise.run | sh
# Activate mise in interactive bash + zsh shells.
if ! grep -q 'mise activate bash' "$HOME/.bashrc" 2>/dev/null; then
  echo 'eval "$(~/.local/bin/mise activate bash)"' >> "$HOME/.bashrc"
fi
if [ -f "$HOME/.zshrc" ] && ! grep -q 'mise activate zsh' "$HOME/.zshrc"; then
  echo 'eval "$(~/.local/bin/mise activate zsh)"' >> "$HOME/.zshrc"
fi
# Install Node LTS as the global default, then pnpm on top.
~/.local/bin/mise use -g node@lts
~/.local/bin/mise exec -- npm install -g pnpm
echo "  Node LTS + pnpm via mise. New shells get it from .bashrc/.zshrc."`,
	},
}

// baselineInstallScript runs once on every newly-created profile. tmux is a
// universally-useful terminal multiplexer for keeping work alive across SSH
// sessions; the user asked for it without prompting.
const baselineInstallScript = `set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y -qq tmux
echo "  tmux installed."`

// installBaseline runs the universal baseline inside a freshly-started VM.
// Failures are warnings, not fatal — the user can re-run via colima ssh.
func installBaseline(profile string) {
	fmt.Println("\n--- baseline tools ---")
	cmd := exec.Command("colima", "ssh", "-p", profile, "--", "bash", "-s")
	cmd.Stdin = strings.NewReader(baselineInstallScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: baseline install exited with %v. Re-run manually: colimander ssh %s -- 'sudo apt-get install -y tmux'\n", err, profile)
	}
}

// promptForPackages is the standalone (non-wizard) huh prompt used by
// `colimander packages <name>`. The setup wizard inlines the same options
// into its big form instead of calling this.
func promptForPackages() []vmPackage {
	opts := make([]huh.Option[string], 0, len(availablePackages))
	for _, p := range availablePackages {
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
	return pkgsFromIDs(picked)
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

// installPackages runs each selected package's script inside the VM,
// piping the script via stdin to `bash -s` to avoid SSH-quoting issues.
// Failures are surfaced but don't abort the wizard.
func installPackages(profile string, pkgs []vmPackage) {
	if len(pkgs) == 0 {
		return
	}
	fmt.Printf("\nInstalling %d package(s) inside the VM:\n", len(pkgs))
	for _, p := range pkgs {
		fmt.Printf("\n--- %s ---\n", p.Label)
		cmd := exec.Command("colima", "ssh", "-p", profile, "--", "bash", "-s")
		cmd.Stdin = strings.NewReader(p.Script)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: %s installer exited with %v. The VM is still usable; rerun the installer manually with `colimander ssh %s`.\n", p.Label, err, profile)
		}
	}
}
