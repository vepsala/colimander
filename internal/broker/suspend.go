package broker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func suspensionPath(profile string) string {
	return filepath.Join(stateDir(), "suspended", profile)
}

// Suspend cuts a sandbox off. It's a file, so it holds across daemon restarts and
// works with the daemon down. The VM keeps running, so it can still be inspected.
func Suspend(profile, reason string) error {
	if err := validProfile(profile); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(suspensionPath(profile)), 0o700); err != nil {
		return err
	}
	if reason == "" {
		reason = "suspended by user"
	}
	return os.WriteFile(suspensionPath(profile), []byte(reason), 0o600)
}

// SuspendedReason returns why a sandbox is suspended, or "" if it isn't. A marker
// that can't be read counts as suspended, so a fault can't reopen access.
func SuspendedReason(profile string) string {
	data, err := os.ReadFile(suspensionPath(profile))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil || len(data) == 0 {
		return "suspended"
	}
	return string(data)
}

func clearSuspension(profile string) error {
	err := os.Remove(suspensionPath(profile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// validProfile keeps a name from a request from escaping the suspended directory.
func validProfile(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid profile name %q", name)
	}
	return nil
}

func refuseSuspended(profile string, pol *Policy, err error) (string, *Policy, error) {
	if err != nil {
		return profile, pol, err
	}
	if reason := SuspendedReason(profile); reason != "" {
		return profile, nil, fmt.Errorf("sandbox %q is suspended: %s", profile, reason)
	}
	return profile, pol, nil
}

// CmdSuspend is `colimander suspend <name> [reason]`.
func CmdSuspend(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: colimander suspend <name> [reason]")
	}
	if _, err := LoadPolicy(args[0]); err != nil {
		return fmt.Errorf("load policy for %q: %w", args[0], err)
	}
	if err := Suspend(args[0], strings.Join(args[1:], " ")); err != nil {
		return err
	}
	fmt.Printf("Suspended %q. The VM is still running. Stop it with: colimander stop %s\n", args[0], args[0])
	return nil
}

// CmdResume is `colimander resume <name>`. It always issues a new handle, because
// the old one may be why the sandbox was suspended.
func CmdResume(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: colimander resume <name>")
	}
	if err := resumeSandbox(args[0]); err != nil {
		return err
	}
	fmt.Printf("Resumed %q with new credentials.\n", args[0])
	return nil
}

func resumeSandbox(name string) error {
	pol, err := LoadPolicy(name)
	if err != nil {
		return fmt.Errorf("load policy for %q: %w", name, err)
	}
	pol.Handle = GenerateHandle()
	if err := SavePolicy(name, pol); err != nil {
		return err
	}
	if err := wireBrokerInVM(name, pol); err != nil {
		fmt.Fprintf(os.Stderr, "Could not update the VM (%v). It gets the new handle on its next `colimander start`.\n", err)
	}
	return clearSuspension(name)
}
