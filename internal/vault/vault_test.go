package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T, dir string) *Vault {
	t.Helper()
	v, err := Open(filepath.Join(dir, "vault.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestRoundTripAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	v := open(t, dir)
	if err := v.Put("profile:a", "fly", "s3cret-value"); err != nil {
		t.Fatal(err)
	}
	v.Close()
	v = open(t, dir)
	if got, err := v.Get("profile:a", "fly"); err != nil || got != "s3cret-value" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := v.Get("profile:a", "unset"); err != nil || got != "" {
		t.Fatalf("unset: %q, %v", got, err)
	}
}

func TestValueIsNotStoredInPlainText(t *testing.T) {
	dir := t.TempDir()
	v := open(t, dir)
	if err := v.Put("s", "n", "s3cret-value"); err != nil {
		t.Fatal(err)
	}
	v.Close()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(data), "s3cret-value") {
			t.Errorf("%s holds the plain text", e.Name())
		}
	}
}

func TestCiphertextIsBoundToItsRow(t *testing.T) {
	v := open(t, t.TempDir())
	if err := v.Put("profile:a", "fly", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.db.Exec(`UPDATE secrets SET scope = 'profile:b'`); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("profile:b", "fly"); err == nil {
		t.Error("a value moved to another profile should not decrypt")
	}
}

func TestMissingKeyIsNotRegenerated(t *testing.T) {
	dir := t.TempDir()
	v := open(t, dir)
	if err := v.Put("s", "n", "x"); err != nil {
		t.Fatal(err)
	}
	v.Close()
	os.Remove(filepath.Join(dir, "master.key"))
	if _, err := Open(filepath.Join(dir, "vault.db"), filepath.Join(dir, "master.key")); !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); err == nil {
		t.Error("a new key was generated")
	}
}

func TestDeleteScope(t *testing.T) {
	v := open(t, t.TempDir())
	v.Put("a", "x", "1")
	v.Put("b", "x", "2")
	if err := v.DeleteScope("a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get("a", "x"); got != "" {
		t.Error("not deleted")
	}
	if got, _ := v.Get("b", "x"); got != "2" {
		t.Error("deleted too much")
	}
}
