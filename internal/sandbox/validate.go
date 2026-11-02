package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var profileNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// ValidateProfileName checks a name's form. See EnsureNameAvailable for collisions.
func ValidateProfileName(name string) error {
	if !profileNameRE.MatchString(name) {
		return fmt.Errorf("name must start with a letter/digit and be 1-31 lowercase chars, digits, or hyphens")
	}
	return nil
}

// EnsureNameAvailable refuses names that collide with an existing profile.
//
// Colima strips a "colima-" prefix and treats "colima" as its default profile, so
// those names would pass the directory check and then operate on someone else's
// VM, including when a failed creation gets cleaned up.
func EnsureNameAvailable(name string) error {
	if name == "colima" || strings.HasPrefix(name, "colima-") {
		return fmt.Errorf("Colima reads %q as another profile's name; pick another name", name)
	}
	if m, _ := LoadMarker(name); m != nil {
		return fmt.Errorf("profile %q already exists (marker at %s)", name, MarkerPath(name))
	}
	if _, err := os.Stat(ProfileDir(name)); err == nil {
		return fmt.Errorf("colima profile dir %q exists; pick another name", ProfileDir(name))
	}
	return nil
}

// ValidatePositiveInt is for CPU, memory and disk.
func ValidatePositiveInt(s string) error {
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

// ValidateNonNegativeInt is for swap, where 0 means none.
func ValidateNonNegativeInt(s string) error {
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

// ValidateNonEmpty is for tokens and other required text.
func ValidateNonEmpty(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("required")
	}
	return nil
}

// ValidateImportPath checks that a path is an existing directory. A relative path
// is relative to the current directory, which suits a CLI.
func ValidateImportPath(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("required")
	}
	abs, err := filepath.Abs(ExpandHome(s))
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
	return refuseSensitiveImport(abs)
}

// refuseSensitiveImport keeps credentials out of a sandbox: copying these would
// put SSH keys, cloud logins and Colimander's own vault inside the VM.
func refuseSensitiveImport(abs string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	real := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	path, homeDir := real(abs), real(home)
	if rel, err := filepath.Rel(path, homeDir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s holds your whole home folder, including SSH keys and logins. Pick a project folder inside it", abs)
	}
	for _, name := range []string{".ssh", ".aws", ".gnupg", ".config", ".colima", ".colimander"} {
		secret := filepath.Join(homeDir, name)
		if path == secret || strings.HasPrefix(path, secret+string(filepath.Separator)) {
			return fmt.Errorf("%s can hold credentials, so it can't be imported into a sandbox", abs)
		}
	}
	return nil
}

// ValidateImportPathFromApp is ValidateImportPath for paths typed into the app.
// The daemon's current directory means nothing to the person typing, so a relative
// path could silently pick the wrong directory.
func ValidateImportPathFromApp(s string) error {
	t := strings.TrimSpace(s)
	if t != "" && !filepath.IsAbs(t) && t != "~" && !strings.HasPrefix(t, "~/") {
		return fmt.Errorf("use a full path, such as ~/code/myproject")
	}
	return ValidateImportPath(s)
}

// NormalizeImportPath turns a validated path into the absolute path to copy from.
func NormalizeImportPath(s string) (string, error) {
	return filepath.Abs(ExpandHome(strings.TrimSpace(s)))
}

// SplitCSV splits a comma-separated list, trims whitespace, drops empties.
func SplitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
