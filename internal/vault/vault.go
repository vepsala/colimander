package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const sealedPrefix = "v1:"

// ErrKeyMissing means the vault holds secrets but its key file is gone. A new
// key must not be generated, because it could never decrypt them.
var ErrKeyMissing = errors.New("master key file is missing but the vault holds secrets encrypted with it")

// Vault stores named secrets, grouped by scope.
type Vault struct {
	db   *sql.DB
	aead cipher.AEAD
}

// Open opens the vault at path, creating it and the key file on first use.
func Open(path, keyFile string) (*Vault, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=secure_delete(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	v := &Vault{db: db}
	if err := v.init(path, keyFile); err != nil {
		db.Close()
		return nil, err
	}
	return v, nil
}

func (v *Vault) init(path, keyFile string) error {
	if _, err := v.db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		scope TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL,
		PRIMARY KEY (scope, name))`); err != nil {
		return fmt.Errorf("create vault: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	var rows int
	if err := v.db.QueryRow(`SELECT count(*) FROM secrets`).Scan(&rows); err != nil {
		return err
	}
	key, _, err := LoadKey(keyFile)
	if errors.Is(err, fs.ErrNotExist) {
		if rows > 0 {
			return ErrKeyMissing
		}
		key, err = CreateKey(keyFile)
		if err == nil {
			_ = ExcludeFromBackup(keyFile) // best effort
		}
	}
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	v.aead, err = cipher.NewGCM(block)
	return err
}

// Close releases the database.
func (v *Vault) Close() error { return v.db.Close() }

// binding ties a ciphertext to its row, so one can't be copied over another.
func binding(scope, name string) []byte {
	return []byte("colimander:v1:" + scope + "\x00" + name)
}

// Put stores a secret, replacing any previous value.
func (v *Vault) Put(scope, name, value string) error {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := v.aead.Seal(nonce, nonce, []byte(value), binding(scope, name))
	_, err := v.db.Exec(`INSERT INTO secrets (scope, name, value, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (scope, name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		scope, name, sealedPrefix+base64.RawStdEncoding.EncodeToString(sealed), time.Now().UTC().Format(time.RFC3339))
	return err
}

// Get returns a secret, or "" if it isn't set.
func (v *Vault) Get(scope, name string) (string, error) {
	var enc string
	err := v.db.QueryRow(`SELECT value FROM secrets WHERE scope = ? AND name = ?`, scope, name).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(enc) < len(sealedPrefix) || enc[:len(sealedPrefix)] != sealedPrefix {
		return "", errors.New("vault value is not sealed")
	}
	raw, err := base64.RawStdEncoding.DecodeString(enc[len(sealedPrefix):])
	if err != nil || len(raw) < v.aead.NonceSize() {
		return "", errors.New("malformed vault value")
	}
	n := v.aead.NonceSize()
	pt, err := v.aead.Open(nil, raw[:n], raw[n:], binding(scope, name))
	if err != nil {
		return "", fmt.Errorf("decrypt %s/%s: %w", scope, name, err)
	}
	return string(pt), nil
}

// DeleteScope removes every secret in a scope.
func (v *Vault) DeleteScope(scope string) error {
	_, err := v.db.Exec(`DELETE FROM secrets WHERE scope = ?`, scope)
	return err
}
