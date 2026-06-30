// Package store is the SQLite-backed registry of proxy connections. Each
// connection maps a generated agent username/password to an upstream database
// plus that connection's PII and gating rules.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo)

	"github.com/kotisivukamu/pg-agent-proxy/internal/policy"
)

// ErrNotFound is returned when a connection does not exist.
var ErrNotFound = errors.New("connection not found")

// Connection is a registered proxy connection.
type Connection struct {
	ID            int64            `json:"id"`
	Name          string           `json:"name"`
	AgentUsername string           `json:"agent_username"`
	UpstreamURL   string           `json:"upstream_url"`
	MaxRows       int              `json:"max_rows"`
	GateMutations bool             `json:"gate_mutations"`
	PIIRules      []policy.PIIRule `json:"pii_rules"`
	CreatedAt     time.Time        `json:"created_at"`
	// AgentPassword is the plaintext agent password, decrypted for display.
	// It is empty when no secret is set or when the stored ciphertext can no
	// longer be decrypted (e.g. the admin token was rotated) — rotate the
	// connection to mint a fresh, displayable password.
	AgentPassword string `json:"agent_password,omitempty"`

	passwordHash string
}

// CreateInput holds the fields needed to create a connection.
type CreateInput struct {
	Name          string
	UpstreamURL   string
	MaxRows       int
	GateMutations bool
	PIIRules      []policy.PIIRule
}

// Store wraps the SQLite database.
type Store struct {
	db   *sql.DB
	aead cipher.AEAD // nil when no secret is set; gates password encryption
}

// UseSecret derives a symmetric key from secret (the admin token) and uses it
// to encrypt agent passwords at rest. Pass "" to disable storage of
// re-displayable passwords. Rotating the secret renders previously stored
// passwords undecryptable — by design, they become unrecoverable.
func (s *Store) UseSecret(secret string) {
	if secret == "" {
		s.aead = nil
		return
	}
	sum := sha256.Sum256([]byte("pgproxy:agent-password:v1:" + secret))
	block, err := aes.NewCipher(sum[:]) // 32-byte key → AES-256
	if err != nil {
		s.aead = nil
		return
	}
	s.aead, _ = cipher.NewGCM(block)
}

// encrypt seals plaintext as base64(nonce||ciphertext). Returns "" when no
// secret is set or plaintext is empty.
func (s *Store) encrypt(plaintext string) (string, error) {
	if s.aead == nil || plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// decrypt reverses encrypt. Returns "" if the secret is absent or the
// ciphertext can no longer be authenticated (e.g. the admin token changed).
func (s *Store) decrypt(enc string) string {
	if s.aead == nil || enc == "" {
		return ""
	}
	raw, err := base64.RawStdEncoding.DecodeString(enc)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return ""
	}
	nonce, ct := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	pt, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return ""
	}
	return string(pt)
}

// Open opens (and migrates) the registry at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer; serialize to avoid lock errors.
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS connections (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  name                TEXT    NOT NULL,
  agent_username      TEXT    NOT NULL UNIQUE,
  agent_password_hash TEXT    NOT NULL,
  agent_password_enc  TEXT    NOT NULL DEFAULT '',
  upstream_url        TEXT    NOT NULL,
  max_rows            INTEGER NOT NULL DEFAULT 1000,
  gate_mutations      INTEGER NOT NULL DEFAULT 1,
  pii_rules           TEXT    NOT NULL DEFAULT '[]',
  created_at          TEXT    NOT NULL
);`); err != nil {
		return err
	}
	// Add agent_password_enc to registries created before encrypted display.
	if _, err := s.db.Exec(`ALTER TABLE connections ADD COLUMN agent_password_enc TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		return err
	}
	return nil
}

// Create inserts a new connection, generating an agent username and password.
// The plaintext password is returned once and never stored.
func (s *Store) Create(in CreateInput) (*Connection, string, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, "", errors.New("name is required")
	}
	if strings.TrimSpace(in.UpstreamURL) == "" {
		return nil, "", errors.New("upstream_url is required")
	}
	if in.PIIRules == nil {
		in.PIIRules = []policy.PIIRule{}
	}
	rulesJSON, err := json.Marshal(in.PIIRules)
	if err != nil {
		return nil, "", err
	}

	password, err := randomToken(24)
	if err != nil {
		return nil, "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}
	encPassword, err := s.encrypt(password)
	if err != nil {
		return nil, "", err
	}

	createdAt := time.Now().UTC()

	// Generate a unique username; retry on the rare collision.
	var id int64
	var username string
	for attempt := 0; attempt < 5; attempt++ {
		suffix, err := randomToken(4)
		if err != nil {
			return nil, "", err
		}
		username = slugify(in.Name) + "_" + strings.ToLower(suffix[:6])
		res, err := s.db.Exec(`
INSERT INTO connections (name, agent_username, agent_password_hash, agent_password_enc, upstream_url, max_rows, gate_mutations, pii_rules, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			in.Name, username, string(hash), encPassword, in.UpstreamURL, in.MaxRows, boolToInt(in.GateMutations), string(rulesJSON), createdAt.Format(time.RFC3339Nano))
		if err != nil {
			if isUniqueViolation(err) {
				continue
			}
			return nil, "", err
		}
		id, err = res.LastInsertId()
		if err != nil {
			return nil, "", err
		}
		break
	}
	if id == 0 {
		return nil, "", errors.New("could not generate a unique agent username")
	}

	return &Connection{
		ID:            id,
		Name:          in.Name,
		AgentUsername: username,
		UpstreamURL:   in.UpstreamURL,
		MaxRows:       in.MaxRows,
		GateMutations: in.GateMutations,
		PIIRules:      in.PIIRules,
		CreatedAt:     createdAt,
		AgentPassword: password,
		passwordHash:  string(hash),
	}, password, nil
}

// Rotate generates a new password for a connection and returns the plaintext.
func (s *Store) Rotate(id int64) (string, error) {
	password, err := randomToken(24)
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	encPassword, err := s.encrypt(password)
	if err != nil {
		return "", err
	}
	res, err := s.db.Exec(`UPDATE connections SET agent_password_hash = ?, agent_password_enc = ? WHERE id = ?`, string(hash), encPassword, id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return password, nil
}

// Delete removes a connection.
func (s *Store) Delete(id int64) error {
	res, err := s.db.Exec(`DELETE FROM connections WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns all connections. AgentPassword is decrypted for display when a
// secret is set and the stored ciphertext is still valid; otherwise it is "".
func (s *Store) List() ([]Connection, error) {
	rows, err := s.db.Query(`
SELECT id, name, agent_username, agent_password_enc, upstream_url, max_rows, gate_mutations, pii_rules, created_at
FROM connections ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		c, err := scanConnection(rows)
		if err != nil {
			return nil, err
		}
		// scanConnection leaves the ciphertext in AgentPassword; decrypt it.
		c.AgentPassword = s.decrypt(c.AgentPassword)
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetByUsername looks up a connection for authentication/routing. The returned
// Connection carries the password hash for verification via VerifyPassword.
func (s *Store) GetByUsername(username string) (*Connection, error) {
	row := s.db.QueryRow(`
SELECT id, name, agent_username, agent_password_hash, upstream_url, max_rows, gate_mutations, pii_rules, created_at
FROM connections WHERE agent_username = ?`, username)
	return scanConnectionWithHash(row)
}

// VerifyPassword reports whether plaintext matches the connection's stored hash.
func VerifyPassword(c *Connection, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(c.passwordHash), []byte(plaintext)) == nil
}

// Policy compiles this connection's anonymization and gating rules.
func (c *Connection) Policy(hashSalt, redactString string) *policy.Policy {
	return policy.New(c.PIIRules, hashSalt, redactString, c.MaxRows, c.GateMutations)
}

type scanner interface{ Scan(...any) error }

func scanConnection(sc scanner) (*Connection, error) {
	var (
		c         Connection
		gate      int
		rulesJSON string
		createdAt string
	)
	if err := sc.Scan(&c.ID, &c.Name, &c.AgentUsername, &c.AgentPassword, &c.UpstreamURL, &c.MaxRows, &gate, &rulesJSON, &createdAt); err != nil {
		return nil, err
	}
	return finishScan(&c, gate, rulesJSON, createdAt)
}

func scanConnectionWithHash(sc scanner) (*Connection, error) {
	var (
		c         Connection
		gate      int
		rulesJSON string
		createdAt string
	)
	if err := sc.Scan(&c.ID, &c.Name, &c.AgentUsername, &c.passwordHash, &c.UpstreamURL, &c.MaxRows, &gate, &rulesJSON, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return finishScan(&c, gate, rulesJSON, createdAt)
}

func finishScan(c *Connection, gate int, rulesJSON, createdAt string) (*Connection, error) {
	c.GateMutations = gate != 0
	if err := json.Unmarshal([]byte(rulesJSON), &c.PIIRules); err != nil {
		return nil, fmt.Errorf("decode pii_rules: %w", err)
	}
	if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
		c.CreatedAt = t
	}
	return c, nil
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func slugify(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('_')
		}
	}
	s := strings.Trim(b.String(), "_")
	if s == "" {
		s = "conn"
	}
	if len(s) > 24 {
		s = s[:24]
	}
	return s
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}
