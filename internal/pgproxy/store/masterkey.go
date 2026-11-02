package store

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// masterKeySize is the AES-256 key length in bytes.
const masterKeySize = 32

var (
	// ErrMasterKeyMissing means the registry holds encrypted data but the key
	// file is gone. A new key must not be generated: it could never decrypt the
	// existing data.
	ErrMasterKeyMissing = errors.New("master key file is missing but the registry holds data encrypted with it")
	// ErrMasterKeyWrong means the key file does not match the registry.
	ErrMasterKeyWrong = errors.New("master key file does not match this registry")
)

// loadMasterKey reads the key at path. permsFixed reports that the file was
// readable by other users and has been restricted to its owner. A missing file
// is returned as fs.ErrNotExist.
func loadMasterKey(path string) (key []byte, permsFixed bool, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("master key %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, false, fmt.Errorf("restrict master key permissions: %w", err)
		}
		permsFixed = true
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	key, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != masterKeySize {
		return nil, false, fmt.Errorf("master key %s is malformed", path)
	}
	return key, permsFixed, nil
}

// createMasterKey generates a key and publishes it at path atomically, so a
// crash can't leave a partial key and concurrent first starts agree on one key.
func createMasterKey(path string) ([]byte, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create master key directory: %w", err)
	}
	key, err := randomBytes(masterKeySize)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".master.key-*") // created with mode 0600
	if err != nil {
		return nil, fmt.Errorf("create master key: %w", err)
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(base64.StdEncoding.EncodeToString(key) + "\n")
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			existing, _, loadErr := loadMasterKey(path) // lost the race; use the winner's
			return existing, loadErr
		}
		return nil, fmt.Errorf("publish master key: %w", err)
	}
	return key, nil
}

// excludeFromBackup keeps the key out of Time Machine, so a backup of the
// registry can't be decrypted on its own. It does nothing off macOS.
func excludeFromBackup(path string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return exec.Command("tmutil", "addexclusion", path).Run()
}
