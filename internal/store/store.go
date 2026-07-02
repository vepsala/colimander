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
	// ExpiresAt is when the connection stops working and becomes eligible for
	// sweeping. The zero value means the connection never expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// AgentPassword is the plaintext agent password, decrypted for display.
	// It is empty when no secret is set or when the stored ciphertext can no
	// longer be decrypted (e.g. the admin token was rotated) — rotate the
	// connection to mint a fresh, displayable password.
	AgentPassword string `json:"agent_password,omitempty"`

	passwordHash string
}

// Expired reports whether the connection has a deadline that has passed.
func (c *Connection) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
}

// CreateInput holds the fields needed to create a connection.
type CreateInput struct {
	Name          string
	UpstreamURL   string
	MaxRows       int
	GateMutations bool
	PIIRules      []policy.PIIRule
	// ExpiresAt, when non-zero, sets a hard deadline after which the connection
	// stops authenticating and is swept.
	ExpiresAt time.Time
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
  created_at          TEXT    NOT NULL,
  expires_at          TEXT    NOT NULL DEFAULT ''
);`); err != nil {
		return err
	}
	// Add columns to registries created before they existed. SQLite ignores
	// nothing here, so tolerate the "duplicate column" error on re-runs.
	for _, col := range []string{
		`ALTER TABLE connections ADD COLUMN agent_password_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE connections ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(col); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	return nil
}

// expiryLayout is a fixed-width UTC RFC3339 layout (always 9 fractional
// digits). Unlike time.RFC3339Nano it never varies in length, so the stored
// strings sort lexicographically — which is what DeleteExpired's SQL "<="
// comparison relies on. It still parses cleanly with time.RFC3339Nano.
const expiryLayout = "2006-01-02T15:04:05.000000000Z07:00"

// formatExpiry renders an expiry timestamp for storage, or "" for a
// never-expiring connection.
func formatExpiry(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(expiryLayout)
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
INSERT INTO connections (name, agent_username, agent_password_hash, agent_password_enc, upstream_url, max_rows, gate_mutations, pii_rules, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			in.Name, username, string(hash), encPassword, in.UpstreamURL, in.MaxRows, boolToInt(in.GateMutations), string(rulesJSON), createdAt.Format(time.RFC3339Nano), formatExpiry(in.ExpiresAt))
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
		ExpiresAt:     in.ExpiresAt,
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

// UpdateInput holds the editable fields of a connection. Credentials and the
// upstream URL are not editable here.
type UpdateInput struct {
	Name          string
	MaxRows       int
	GateMutations bool
	PIIRules      []policy.PIIRule
	// SetExpiry gates whether ExpiresAt is applied. When false the stored
	// expiry is left unchanged; when true, ExpiresAt is written (a zero value
	// clears the expiry, making the connection never expire).
	SetExpiry bool
	ExpiresAt time.Time
}

// Update changes a connection's policy fields (name, row limit, mutation
// gating, PII rules, and optionally the expiry). Returns ErrNotFound if no
// connection has that id.
func (s *Store) Update(id int64, in UpdateInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return errors.New("name is required")
	}
	if in.PIIRules == nil {
		in.PIIRules = []policy.PIIRule{}
	}
	rulesJSON, err := json.Marshal(in.PIIRules)
	if err != nil {
		return err
	}

	var res sql.Result
	if in.SetExpiry {
		res, err = s.db.Exec(`
UPDATE connections SET name = ?, max_rows = ?, gate_mutations = ?, pii_rules = ?, expires_at = ? WHERE id = ?`,
			in.Name, in.MaxRows, boolToInt(in.GateMutations), string(rulesJSON), formatExpiry(in.ExpiresAt), id)
	} else {
		res, err = s.db.Exec(`
UPDATE connections SET name = ?, max_rows = ?, gate_mutations = ?, pii_rules = ? WHERE id = ?`,
			in.Name, in.MaxRows, boolToInt(in.GateMutations), string(rulesJSON), id)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
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

// DeleteExpired removes every connection whose expiry is at or before now, and
// returns how many were deleted.
func (s *Store) DeleteExpired(now time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM connections WHERE expires_at != '' AND expires_at <= ?`,
		now.UTC().Format(expiryLayout))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// List returns all connections. AgentPassword is decrypted for display when a
// secret is set and the stored ciphertext is still valid; otherwise it is "".
func (s *Store) List() ([]Connection, error) {
	rows, err := s.db.Query(`
SELECT id, name, agent_username, agent_password_enc, upstream_url, max_rows, gate_mutations, pii_rules, created_at, expires_at
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
// An expired connection is treated as not found, so auth fails closed even
// before the sweeper removes it.
func (s *Store) GetByUsername(username string) (*Connection, error) {
	row := s.db.QueryRow(`
SELECT id, name, agent_username, agent_password_hash, upstream_url, max_rows, gate_mutations, pii_rules, created_at, expires_at
FROM connections WHERE agent_username = ?`, username)
	c, err := scanConnectionWithHash(row)
	if err != nil {
		return nil, err
	}
	if c.Expired(time.Now().UTC()) {
		return nil, ErrNotFound
	}
	return c, nil
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
		expiresAt string
	)
	if err := sc.Scan(&c.ID, &c.Name, &c.AgentUsername, &c.AgentPassword, &c.UpstreamURL, &c.MaxRows, &gate, &rulesJSON, &createdAt, &expiresAt); err != nil {
		return nil, err
	}
	return finishScan(&c, gate, rulesJSON, createdAt, expiresAt)
}

func scanConnectionWithHash(sc scanner) (*Connection, error) {
	var (
		c         Connection
		gate      int
		rulesJSON string
		createdAt string
		expiresAt string
	)
	if err := sc.Scan(&c.ID, &c.Name, &c.AgentUsername, &c.passwordHash, &c.UpstreamURL, &c.MaxRows, &gate, &rulesJSON, &createdAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return finishScan(&c, gate, rulesJSON, createdAt, expiresAt)
}

func finishScan(c *Connection, gate int, rulesJSON, createdAt, expiresAt string) (*Connection, error) {
	c.GateMutations = gate != 0
	if err := json.Unmarshal([]byte(rulesJSON), &c.PIIRules); err != nil {
		return nil, fmt.Errorf("decode pii_rules: %w", err)
	}
	if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
		c.CreatedAt = t
	}
	if expiresAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, expiresAt); err == nil {
			c.ExpiresAt = t
		}
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
