// Optional packages the wizard can install into a newly-created VM.
//
// Each package has a single bash script that the wizard pipes via stdin to
// `bash -s` on the remote. Stdin-piping side-steps the classic SSH quoting
// trap (where multi-arg shell strings get concatenated and re-parsed once on
// the host and once on the remote).
//
// Failures are warnings, not fatal — the wizard's already produced a usable
// VM; a missing package is fixable later with `colimander ssh <name>`.

package sandbox

import (
	"fmt"
	"strings"
)

// Package is an optional install for a new VM.
type Package struct {
	ID          string
	Label       string
	Description string
	Script      string
}

// Packages is what setup offers.
var Packages = []Package{
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
		ID:          "postgres-16",
		Label:       "PostgreSQL 16",
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
# Node's prebuilt binaries need libatomic1, which minimal Ubuntu images lack.
sudo apt-get install -y -qq curl ca-certificates libatomic1
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

// InstallBaseline runs the universal baseline inside a freshly-started VM.
func InstallBaseline(profile string, o IO) error {
	fmt.Fprintln(o.Out, "\n--- baseline tools ---")
	err := o.command(strings.NewReader(baselineInstallScript), "colima", "ssh", "-p", profile, "--", "bash", "-s").Run()
	if err != nil {
		return fmt.Errorf("baseline install exited with %v. Re-run manually: colimander ssh %s -- 'sudo apt-get install -y tmux'", err, profile)
	}
	return nil
}

// InstallPackage runs one package's script inside the VM.
func InstallPackage(profile string, p Package, o IO) error {
	fmt.Fprintf(o.Out, "\n--- %s ---\n", p.Label)
	err := o.command(strings.NewReader(p.Script), "colima", "ssh", "-p", profile, "--", "bash", "-s").Run()
	if err != nil {
		return fmt.Errorf("%s installer exited with %v. The VM is still usable; rerun the installer manually with `colimander ssh %s`", p.Label, err, profile)
	}
	return nil
}

// PackagesFromIDs maps ids to packages, skipping unknown ones.
func PackagesFromIDs(ids []string) []Package {
	out := make([]Package, 0, len(ids))
	for _, id := range ids {
		for _, p := range Packages {
			if p.ID == id {
				out = append(out, p)
				break
			}
		}
	}
	return out
}
