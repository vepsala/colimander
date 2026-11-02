// Per-profile upstream tokens for external service brokers (fly.io, doppler),
// encrypted in the vault. policy.json holds what's allowed and stays hand-editable;
// tokens are how we authenticate upstream, so they never go there.

package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/vepsala/colimander/internal/vault"
)

// ProfileTokens holds the upstream tokens the broker substitutes when
// proxying to an external service. Empty string = not configured (and the
// corresponding broker route will return 502 until set).
type ProfileTokens struct {
	Fly     string `json:"fly,omitempty"`
	Doppler string `json:"doppler,omitempty"`
}

var tokensMu sync.Mutex

func openVault() (*vault.Vault, error) {
	v, err := vault.Open(filepath.Join(stateDir(), "vault.db"), filepath.Join(stateDir(), "master.key"))
	if err != nil {
		return nil, err
	}
	if err := importLegacyTokens(v); err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}

// importLegacyTokens copies tokens.json into the vault once. The file is left
// for the user to delete, so going back to an older build stays possible.
func importLegacyTokens(v *vault.Vault) error {
	if done, err := v.Get("meta", "tokens_imported"); err != nil || done != "" {
		return err
	}
	path := filepath.Join(stateDir(), "tokens.json")
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		var f struct {
			Profiles map[string]ProfileTokens `json:"profiles"`
		}
		if err := json.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("invalid tokens file at %s: %w", path, err)
		}
		for profile, t := range f.Profiles {
			if err := putTokens(v, profile, t); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stderr, "Imported %s into the vault. It still holds tokens in plain text: delete it once you won't go back to an older build.\n", path)
	}
	return v.Put("meta", "tokens_imported", "1")
}

func tokenScope(profile string) string { return "profile:" + profile }

func putTokens(v *vault.Vault, profile string, t ProfileTokens) error {
	if t.Fly != "" {
		if err := v.Put(tokenScope(profile), "fly", t.Fly); err != nil {
			return err
		}
	}
	if t.Doppler != "" {
		if err := v.Put(tokenScope(profile), "doppler", t.Doppler); err != nil {
			return err
		}
	}
	return nil
}

func SetProfileTokens(profile string, t ProfileTokens) error {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	v, err := openVault()
	if err != nil {
		return err
	}
	defer v.Close()
	return putTokens(v, profile, t)
}

func getProfileTokens(profile string) (ProfileTokens, error) {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	v, err := openVault()
	if err != nil {
		return ProfileTokens{}, err
	}
	defer v.Close()
	var t ProfileTokens
	if t.Fly, err = v.Get(tokenScope(profile), "fly"); err != nil {
		return ProfileTokens{}, err
	}
	if t.Doppler, err = v.Get(tokenScope(profile), "doppler"); err != nil {
		return ProfileTokens{}, err
	}
	return t, nil
}

func clearProfileTokens(profile string) error {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	v, err := openVault()
	if err != nil {
		return err
	}
	defer v.Close()
	return v.DeleteScope(tokenScope(profile))
}

// CmdTokens is the `colimander tokens` entrypoint. Subcommands:
//
//	colimander tokens set <profile> <fly|doppler> <token>
//	colimander tokens list <profile>     (shows which slots are populated, never values)
//	colimander tokens clear <profile>    (forget all tokens for a profile)
func CmdTokens(args []string) error {
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
		if err := SetProfileTokens(profile, pt); err != nil {
			return err
		}
		fmt.Printf("Stored %s token for profile %q in %s.\n", kind, profile, filepath.Join(stateDir(), "vault.db"))
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
