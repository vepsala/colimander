// Per-profile upstream tokens for external service brokers (fly.io, doppler).
//
// Stored separately from policy.json because:
//   - Tokens are sensitive; policy.json is 0644 (so the user can hand-edit
//     rules without sudo). Tokens belong in a file mode 0600.
//   - Policy is the "what's allowed" — declarative, version-control-friendly.
//     Tokens are the "how we authenticate upstream" — per-machine, secret,
//     not for committing.
//
// File lives at ~/.colimander/tokens.json, owner-read/write only.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const tokensFileVersion = 1

// ProfileTokens holds the upstream tokens the broker substitutes when
// proxying to an external service. Empty string = not configured (and the
// corresponding broker route will return 502 until set).
type ProfileTokens struct {
	Fly     string `json:"fly,omitempty"`
	Doppler string `json:"doppler,omitempty"`
}

type tokensFile struct {
	Version  int                      `json:"version"`
	Profiles map[string]ProfileTokens `json:"profiles"`
}

var tokensMu sync.Mutex

func tokensPath() string {
	return filepath.Join(stateDir(), "tokens.json")
}

func loadTokens() (*tokensFile, error) {
	data, err := os.ReadFile(tokensPath())
	if errors.Is(err, os.ErrNotExist) {
		return &tokensFile{Version: tokensFileVersion, Profiles: map[string]ProfileTokens{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var f tokensFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("invalid tokens file at %s: %w", tokensPath(), err)
	}
	if f.Profiles == nil {
		f.Profiles = map[string]ProfileTokens{}
	}
	return &f, nil
}

func saveTokens(f *tokensFile) error {
	if err := os.MkdirAll(stateDir(), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tokensPath(), data, 0o600); err != nil {
		return err
	}
	// Belt + suspenders: re-chmod in case the file pre-existed at 0644.
	_ = os.Chmod(tokensPath(), 0o600)
	return nil
}

func setProfileTokens(profile string, t ProfileTokens) error {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	f, err := loadTokens()
	if err != nil {
		return err
	}
	existing := f.Profiles[profile]
	if t.Fly != "" {
		existing.Fly = t.Fly
	}
	if t.Doppler != "" {
		existing.Doppler = t.Doppler
	}
	f.Profiles[profile] = existing
	return saveTokens(f)
}

func getProfileTokens(profile string) (ProfileTokens, error) {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	f, err := loadTokens()
	if err != nil {
		return ProfileTokens{}, err
	}
	return f.Profiles[profile], nil
}

func clearProfileTokens(profile string) error {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	f, err := loadTokens()
	if err != nil {
		return err
	}
	delete(f.Profiles, profile)
	return saveTokens(f)
}

// cmdTokens is the `colimander tokens` entrypoint. Subcommands:
//
//	colimander tokens set <profile> <fly|doppler> <token>
//	colimander tokens list <profile>     (shows which slots are populated, never values)
//	colimander tokens clear <profile>    (forget all tokens for a profile)
func cmdTokens(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: colimander tokens {set|list|clear} ...")
	}
	switch args[0] {
	case "set":
		if len(args) < 4 {
			return errors.New("usage: colimander tokens set <profile> <fly|doppler> <token>")
		}
		profile, kind, tok := args[1], args[2], args[3]
		var pt ProfileTokens
		switch kind {
		case "fly":
			pt.Fly = tok
		case "doppler":
			pt.Doppler = tok
		default:
			return fmt.Errorf("unknown token kind %q (want: fly | doppler)", kind)
		}
		if err := setProfileTokens(profile, pt); err != nil {
			return err
		}
		fmt.Printf("Stored %s token for profile %q in %s.\n", kind, profile, tokensPath())
		return nil
	case "list":
		if len(args) < 2 {
			return errors.New("usage: colimander tokens list <profile>")
		}
		t, err := getProfileTokens(args[1])
		if err != nil {
			return err
		}
		mark := func(s string) string {
			if s == "" {
				return "(not set)"
			}
			return "(set)"
		}
		fmt.Printf("Profile %q upstream tokens:\n", args[1])
		fmt.Printf("  fly:     %s\n", mark(t.Fly))
		fmt.Printf("  doppler: %s\n", mark(t.Doppler))
		return nil
	case "clear":
		if len(args) < 2 {
			return errors.New("usage: colimander tokens clear <profile>")
		}
		return clearProfileTokens(args[1])
	default:
		return fmt.Errorf("unknown tokens subcommand %q", args[0])
	}
}
