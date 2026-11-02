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
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo)

	"github.com/vepsala/colimander/internal/pgproxy/policy"
)

// ErrNotFound is returned when a connection does not exist.
var ErrNotFound = errors.New("connection not found")

// Connection is a registered proxy connection.
type Connection struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	AgentUsername string `json:"agent_username"`
	// UpstreamURL is the decrypted connection string, including its password.
	// List leaves it empty when the stored ciphertext can't be decrypted.
	UpstreamURL string `json:"upstream_url"`
	// UpstreamTarget is "user@host:port/database", stored unencrypted so a
	// connection stays identifiable without its secrets. Empty if unparseable.
	UpstreamTarget string           `json:"upstream_target,omitempty"`
	MaxRows        int              `json:"max_rows"`
	GateMutations  bool             `json:"gate_mutations"`
	PIIRules       []policy.PIIRule `json:"pii_rules"`
	CreatedAt      time.Time        `json:"created_at"`
	// ExpiresAt is when the connection stops working and becomes eligible for
	// sweeping. The zero value means the connection never expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// RotateEvery is the automatic password-rotation interval. Zero means the
	// password is only ever rotated manually.
	RotateEvery time.Duration `json:"rotate_every,omitempty"`
	// RotatedAt is when the current password was minted: creation, or the last
	// rotation (manual or automatic).
	RotatedAt time.Time `json:"rotated_at"`
	// AgentPassword is the plaintext agent password, decrypted for display.
	// It is empty when the stored ciphertext can't be decrypted or was cleared
	// during migration — rotate the connection to mint a displayable password.
	AgentPassword string `json:"agent_password,omitempty"`
	// StrictAll treats every table as holding PII unless listed in SafeRelations.
	StrictAll bool `json:"strict_all"`
	// SafeRelations are tables and views reviewed as holding no PII.
	SafeRelations []string `json:"safe_relations"`
	// SuspendedAt is when the tripwire stopped this connection. While set, it
	// can't authenticate. The zero value means it's active.
	SuspendedAt time.Time `json:"suspended_at,omitempty"`
	// SuspendReason says what tripped it.
	SuspendReason string `json:"suspend_reason,omitempty"`

	passwordHash string
}

// Suspended reports whether the tripwire has stopped this connection.
func (c *Connection) Suspended() bool { return !c.SuspendedAt.IsZero() }

// Expired reports whether the connection has a deadline that has passed.
func (c *Connection) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
}

// NextRotation returns when the password is next rotated automatically, or the
// zero time when automatic rotation is off.
func (c *Connection) NextRotation() time.Time {
	if c.RotateEvery <= 0 || c.RotatedAt.IsZero() {
		return time.Time{}
	}
	return c.RotatedAt.Add(c.RotateEvery)
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
	// RotateEvery, when positive, makes the sweeper rotate the password every
	// interval (see RotateDue). Zero means manual rotation only.
	RotateEvery time.Duration
	// StrictAll and SafeRelations: see Connection.
	StrictAll     bool
	SafeRelations []string
}

// Options configures Open.
type Options struct {
	// Path is the SQLite registry file.
	Path string
	// MasterKeyFile holds the key that encrypts secrets in the registry. It is
	// generated on first use.
	MasterKeyFile string
	// LegacySecret is the admin token that encrypted agent passwords before the
	// master key existed. It is only read while migrating an older registry.
	LegacySecret string
}

// StartupReport describes what Open did, for the caller to surface.
type StartupReport struct {
	KeyCreated bool // a new master key was generated
	PermsFixed bool // the key file was too open and has been restricted
	// BackupExcludeErr is set when the new key couldn't be excluded from backups.
	BackupExcludeErr error
	// Migrated counts older rows whose secrets were encrypted under the master key.
	Migrated int
	// PasswordsCleared counts agent passwords that couldn't be carried over.
	// Those credentials still authenticate but can't be displayed until rotated.
	PasswordsCleared int
	// ScrubPending means old plaintext could not yet be purged from the database
	// files, usually because another process had them open. Open retries it.
	ScrubPending bool
}

// Store wraps the SQLite database.
type Store struct {
	db     *sql.DB
	aead   cipher.AEAD
	report StartupReport
}

// Startup reports what Open did.
func (s *Store) Startup() StartupReport { return s.report }

const (
	// sealedPrefix marks values encrypted under the master key.
	sealedPrefix = "v2:"
	// keyCheckPlaintext is sealed into the meta table to detect a wrong key.
	keyCheckPlaintext = "pgproxy-key-check"

	fieldUpstream = "upstream_url"
	fieldPassword = "agent_password"
	fieldKeyCheck = "key_check"
	fieldEvent    = "event_query"

	metaKeyCheck     = "key_check"
	metaScrubPending = "scrub_pending"
)

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// binding is the AES-GCM additional data. It ties a ciphertext to its field and
// connection, so someone able to edit the database can't move a value elsewhere.
func binding(field, username string) []byte {
	return []byte("pgproxy:v2:" + field + ":" + username)
}

// seal encrypts plaintext as "v2:" + base64(nonce||ciphertext). An empty
// plaintext stays empty.
func (s *Store) seal(plaintext, field, username string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce, err := randomBytes(s.aead.NonceSize())
	if err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(plaintext), binding(field, username))
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// unseal reverses seal.
func (s *Store) unseal(enc, field, username string) (string, error) {
	if enc == "" {
		return "", nil
	}
	if !strings.HasPrefix(enc, sealedPrefix) {
		return "", errors.New("value is not sealed")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(enc, sealedPrefix))
	if err != nil || len(raw) < s.aead.NonceSize() {
		return "", errors.New("malformed ciphertext")
	}
	nonce, ct := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	pt, err := s.aead.Open(nil, nonce, ct, binding(field, username))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Open opens the registry, loading or creating the master key and encrypting
// any secrets left in plaintext by an older version.
func Open(opts Options) (*Store, error) {
	if opts.MasterKeyFile == "" {
		return nil, errors.New("store: MasterKeyFile is required")
	}
	db, err := sql.Open("sqlite", opts.Path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=secure_delete(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer; serialize to avoid lock errors.
	s := &Store{db: db}
	err = s.migrate()
	if err == nil {
		err = s.initKey(opts.MasterKeyFile)
	}
	if err == nil {
		err = s.encryptLegacyRows(opts.LegacySecret)
	}
	if err == nil {
		err = s.scrubIfPending()
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// initKey loads or creates the master key and checks it against the registry.
func (s *Store) initKey(path string) error {
	check, err := s.metaGet(metaKeyCheck)
	if err != nil {
		return err
	}
	key, permsFixed, err := loadMasterKey(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if check != "" {
			return fmt.Errorf("%w: %s", ErrMasterKeyMissing, path)
		}
		if key, err = createMasterKey(path); err != nil {
			return err
		}
		s.report.KeyCreated = true
		s.report.BackupExcludeErr = excludeFromBackup(path)
	case err != nil:
		return err
	}
	s.report.PermsFixed = permsFixed

	if s.aead, err = newAEAD(key); err != nil {
		return err
	}
	if check != "" {
		if _, err := s.unseal(check, fieldKeyCheck, ""); err != nil {
			return fmt.Errorf("%w: %s", ErrMasterKeyWrong, path)
		}
		return nil
	}
	check, err = s.seal(keyCheckPlaintext, fieldKeyCheck, "")
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)`, metaKeyCheck, check)
	return err
}

// encryptLegacyRows moves secrets written by older versions under the master
// key in one transaction, then flags the old plaintext for scrubbing.
func (s *Store) encryptLegacyRows(legacySecret string) error {
	var legacy cipher.AEAD
	if legacySecret != "" {
		sum := sha256.Sum256([]byte("pgproxy:agent-password:v1:" + legacySecret))
		var err error
		if legacy, err = newAEAD(sum[:]); err != nil {
			return err
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`
SELECT id, agent_username, upstream_url, agent_password_enc FROM connections
WHERE upstream_url != '' OR (agent_password_enc != '' AND agent_password_enc NOT LIKE 'v2:%')`)
	if err != nil {
		return err
	}
	type legacyRow struct {
		id                 int64
		username, url, enc string
	}
	var pending []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.id, &r.username, &r.url, &r.enc); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(pending) == 0 {
		return nil
	}

	for _, r := range pending {
		upstreamEnc, err := s.seal(r.url, fieldUpstream, r.username)
		if err != nil {
			return err
		}
		passwordEnc := r.enc
		if !strings.HasPrefix(r.enc, sealedPrefix) {
			password := openLegacyPassword(legacy, r.enc)
			if password == "" && r.enc != "" {
				s.report.PasswordsCleared++
			}
			if passwordEnc, err = s.seal(password, fieldPassword, r.username); err != nil {
				return err
			}
		}
		query := `UPDATE connections SET agent_password_enc = ? WHERE id = ?`
		args := []any{passwordEnc, r.id}
		if r.url != "" {
			query = `UPDATE connections SET upstream_url = '', upstream_enc = ?, upstream_target = ?, agent_password_enc = ? WHERE id = ?`
			args = []any{upstreamEnc, upstreamTarget(r.url), passwordEnc, r.id}
		}
		if _, err := tx.Exec(query, args...); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, '1')`, metaScrubPending); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.report.Migrated = len(pending)
	return nil
}

// openLegacyPassword decrypts a pre-master-key agent password, returning "" if
// that isn't possible.
func openLegacyPassword(legacy cipher.AEAD, enc string) string {
	if legacy == nil || enc == "" {
		return ""
	}
	raw, err := base64.RawStdEncoding.DecodeString(enc)
	if err != nil || len(raw) < legacy.NonceSize() {
		return ""
	}
	pt, err := legacy.Open(nil, raw[:legacy.NonceSize()], raw[legacy.NonceSize():], nil)
	if err != nil {
		return ""
	}
	return string(pt)
}

// scrubIfPending removes old plaintext from free pages and the WAL. The flag is
// only cleared once that succeeds, so an interrupted scrub is retried.
func (s *Store) scrubIfPending() error {
	pending, err := s.metaGet(metaScrubPending)
	if err != nil || pending == "" {
		return err
	}
	if _, err := s.db.Exec(`VACUUM`); err != nil {
		s.report.ScrubPending = true
		return nil // the data is safe to use; retry on the next Open
	}
	if !s.checkpoint() {
		s.report.ScrubPending = true
		return nil
	}
	if _, err := s.db.Exec(`DELETE FROM meta WHERE key = ?`, metaScrubPending); err != nil {
		return err
	}
	s.checkpoint()
	return nil
}

// checkpoint flushes and truncates the WAL, reporting whether it fully did.
func (s *Store) checkpoint() bool {
	var busy, logFrames, checkpointed int
	err := s.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed)
	return err == nil && busy == 0
}

func (s *Store) metaGet(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

// upstreamTarget renders a connection string without its password.
func upstreamTarget(connString string) string {
	cfg, err := pgconn.ParseConfig(connString)
	if err != nil {
		return ""
	}
	return cfg.User + "@" + cfg.Host + ":" + strconv.Itoa(int(cfg.Port)) + "/" + cfg.Database
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
  upstream_url        TEXT    NOT NULL DEFAULT '', -- legacy plaintext; always '' once migrated
  upstream_enc        TEXT    NOT NULL DEFAULT '',
  upstream_target     TEXT    NOT NULL DEFAULT '',
  max_rows            INTEGER NOT NULL DEFAULT 1000,
  gate_mutations      INTEGER NOT NULL DEFAULT 1,
  pii_rules           TEXT    NOT NULL DEFAULT '[]',
  created_at          TEXT    NOT NULL,
  expires_at          TEXT    NOT NULL DEFAULT '',
  rotate_every        INTEGER NOT NULL DEFAULT 0,
  rotated_at          TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  connection_id INTEGER NOT NULL,
  agent_username TEXT   NOT NULL,
  at            TEXT    NOT NULL,
  kind          TEXT    NOT NULL,
  detail        TEXT    NOT NULL,
  query_enc     TEXT    NOT NULL DEFAULT ''
);`); err != nil {
		return err
	}
	// Add columns to registries created before they existed. SQLite ignores
	// nothing here, so tolerate the "duplicate column" error on re-runs.
	for _, col := range []string{
		`ALTER TABLE connections ADD COLUMN agent_password_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE connections ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE connections ADD COLUMN rotate_every INTEGER NOT NULL DEFAULT 0`, // nanoseconds; 0 = never
		`ALTER TABLE connections ADD COLUMN rotated_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE connections ADD COLUMN upstream_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE connections ADD COLUMN upstream_target TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE connections ADD COLUMN strict_all INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE connections ADD COLUMN safe_relations TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE connections ADD COLUMN suspended_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE connections ADD COLUMN suspend_reason TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(col); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	// Rows from before rotated_at existed count their creation as the last
	// rotation (finishScan applies the same fallback for any row still blank).
	if _, err := s.db.Exec(`UPDATE connections SET rotated_at = created_at WHERE rotated_at = ''`); err != nil {
		return err
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
	return formatTimestamp(t)
}

// formatTimestamp renders a timestamp in the fixed-width storage layout.
func formatTimestamp(t time.Time) string {
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
	if in.SafeRelations == nil {
		in.SafeRelations = []string{}
	}
	safeJSON, err := json.Marshal(in.SafeRelations)
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
	target := upstreamTarget(in.UpstreamURL)
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
		// Sealed per attempt because the ciphertext is bound to the username.
		encPassword, err := s.seal(password, fieldPassword, username)
		if err != nil {
			return nil, "", err
		}
		encUpstream, err := s.seal(in.UpstreamURL, fieldUpstream, username)
		if err != nil {
			return nil, "", err
		}
		res, err := s.db.Exec(`
INSERT INTO connections (name, agent_username, agent_password_hash, agent_password_enc, upstream_url, upstream_enc, upstream_target, max_rows, gate_mutations, pii_rules, created_at, expires_at, rotate_every, rotated_at, strict_all, safe_relations)
VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			in.Name, username, string(hash), encPassword, encUpstream, target, in.MaxRows, boolToInt(in.GateMutations), string(rulesJSON), createdAt.Format(time.RFC3339Nano), formatExpiry(in.ExpiresAt),
			int64(in.RotateEvery), formatTimestamp(createdAt), boolToInt(in.StrictAll), string(safeJSON))
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
		ID:             id,
		Name:           in.Name,
		AgentUsername:  username,
		UpstreamURL:    in.UpstreamURL,
		UpstreamTarget: target,
		MaxRows:        in.MaxRows,
		GateMutations:  in.GateMutations,
		PIIRules:       in.PIIRules,
		CreatedAt:      createdAt,
		ExpiresAt:      in.ExpiresAt,
		RotateEvery:    in.RotateEvery,
		RotatedAt:      createdAt,
		StrictAll:      in.StrictAll,
		SafeRelations:  in.SafeRelations,
		AgentPassword:  password,
		passwordHash:   string(hash),
	}, password, nil
}

// Rotate generates a new password for a connection and returns the plaintext.
// It also resets RotatedAt, so an automatic rotation schedule restarts from now.
func (s *Store) Rotate(id int64) (string, error) {
	return s.rotate(id, time.Now().UTC())
}

// rotate mints, hashes and encrypts a new password for id and records now as
// the rotation time. Sessions already proxied keep running; only new
// authentication attempts see the change.
func (s *Store) rotate(id int64, now time.Time) (string, error) {
	password, err := randomToken(24)
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	var username string
	err = s.db.QueryRow(`SELECT agent_username FROM connections WHERE id = ?`, id).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	encPassword, err := s.seal(password, fieldPassword, username)
	if err != nil {
		return "", err
	}
	res, err := s.db.Exec(`UPDATE connections SET agent_password_hash = ?, agent_password_enc = ?, rotated_at = ? WHERE id = ?`,
		string(hash), encPassword, formatTimestamp(now), id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return password, nil
}

// Rotation describes one automatic rotation performed by RotateDue.
type Rotation struct {
	ID             int64
	Name           string
	AgentUsername  string
	NextRotationAt time.Time
}

// RotateDue rotates the password of every connection whose automatic rotation
// is due (rotated_at + rotate_every <= now) and reports what was rotated. The
// new password is stored exactly as Rotate stores it (bcrypt hash plus
// ciphertext under the master key), so it stays re-displayable. A failure on
// one connection is returned after the others have been attempted.
func (s *Store) RotateDue(now time.Time) ([]Rotation, error) {
	rows, err := s.db.Query(`
SELECT id, name, agent_username, rotate_every, rotated_at
FROM connections WHERE rotate_every > 0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var due []Rotation
	for rows.Next() {
		var (
			r         Rotation
			every     int64
			rotatedAt string
		)
		if err := rows.Scan(&r.ID, &r.Name, &r.AgentUsername, &every, &rotatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		last, err := time.Parse(time.RFC3339Nano, rotatedAt)
		if err != nil {
			continue // unparseable timestamp; leave the row alone
		}
		if !now.Before(last.Add(time.Duration(every))) {
			r.NextRotationAt = now.Add(time.Duration(every))
			due = append(due, r)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close() // release the single SQLite connection before writing

	var rotated []Rotation
	var firstErr error
	for _, r := range due {
		if _, err := s.rotate(r.ID, now); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // deleted between the scan and the rotate
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("rotate connection %d: %w", r.ID, err)
			}
			continue
		}
		rotated = append(rotated, r)
	}
	return rotated, firstErr
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
	// SetRotateEvery gates whether RotateEvery is applied, with the same
	// semantics as SetExpiry (a zero RotateEvery turns automatic rotation off).
	// Changing the interval does not itself rotate the password; the next
	// automatic rotation is measured from the existing RotatedAt.
	SetRotateEvery bool
	RotateEvery    time.Duration
	// SetStrict gates whether StrictAll and SafeRelations are applied.
	SetStrict     bool
	StrictAll     bool
	SafeRelations []string
}

// Update changes a connection's policy fields (name, row limit, mutation
// gating, PII rules, and optionally the expiry and rotation interval). Returns
// ErrNotFound if no connection has that id.
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

	set := `name = ?, max_rows = ?, gate_mutations = ?, pii_rules = ?`
	args := []any{in.Name, in.MaxRows, boolToInt(in.GateMutations), string(rulesJSON)}
	if in.SetExpiry {
		set += `, expires_at = ?`
		args = append(args, formatExpiry(in.ExpiresAt))
	}
	if in.SetRotateEvery {
		if in.RotateEvery < 0 {
			in.RotateEvery = 0
		}
		set += `, rotate_every = ?`
		args = append(args, int64(in.RotateEvery))
	}
	if in.SetStrict {
		if in.SafeRelations == nil {
			in.SafeRelations = []string{}
		}
		safeJSON, err := json.Marshal(in.SafeRelations)
		if err != nil {
			return err
		}
		set += `, strict_all = ?, safe_relations = ?`
		args = append(args, boolToInt(in.StrictAll), string(safeJSON))
	}
	args = append(args, id)
	res, err := s.db.Exec(`UPDATE connections SET `+set+` WHERE id = ?`, args...)
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

// List returns all connections with their secrets decrypted. A value that can't
// be decrypted comes back empty, so one damaged row doesn't hide the others.
func (s *Store) List() ([]Connection, error) {
	rows, err := s.db.Query(`
SELECT id, name, agent_username, agent_password_enc, upstream_enc, upstream_target, max_rows, gate_mutations, pii_rules, created_at, expires_at, rotate_every, rotated_at, strict_all, safe_relations, suspended_at, suspend_reason
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
		// scanConnection leaves ciphertext in both secret fields; decrypt them.
		c.AgentPassword, _ = s.unseal(c.AgentPassword, fieldPassword, c.AgentUsername)
		c.UpstreamURL, _ = s.unseal(c.UpstreamURL, fieldUpstream, c.AgentUsername)
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
SELECT id, name, agent_username, agent_password_hash, upstream_enc, upstream_target, max_rows, gate_mutations, pii_rules, created_at, expires_at, rotate_every, rotated_at, strict_all, safe_relations, suspended_at, suspend_reason
FROM connections WHERE agent_username = ?`, username)
	c, err := scanConnectionWithHash(row)
	if err != nil {
		return nil, err
	}
	if c.Expired(time.Now().UTC()) {
		return nil, ErrNotFound
	}
	// Fail closed: an undecryptable upstream must not become an empty connection
	// string, which libpq-style clients would resolve to local defaults.
	if c.UpstreamURL, err = s.unseal(c.UpstreamURL, fieldUpstream, c.AgentUsername); err != nil {
		return nil, fmt.Errorf("decrypt upstream for %q: %w", c.AgentUsername, err)
	}
	if c.UpstreamURL == "" {
		return nil, fmt.Errorf("connection %q has no upstream", c.AgentUsername)
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
	var c Connection
	var r rawColumns
	if err := sc.Scan(&c.ID, &c.Name, &c.AgentUsername, &c.AgentPassword, &c.UpstreamURL, &c.UpstreamTarget, &c.MaxRows, &r.gate, &r.rulesJSON, &r.createdAt, &r.expiresAt, &r.rotateEvery, &r.rotatedAt, &r.strictAll, &r.safeJSON, &r.suspendedAt, &c.SuspendReason); err != nil {
		return nil, err
	}
	return finishScan(&c, r)
}

func scanConnectionWithHash(sc scanner) (*Connection, error) {
	var c Connection
	var r rawColumns
	if err := sc.Scan(&c.ID, &c.Name, &c.AgentUsername, &c.passwordHash, &c.UpstreamURL, &c.UpstreamTarget, &c.MaxRows, &r.gate, &r.rulesJSON, &r.createdAt, &r.expiresAt, &r.rotateEvery, &r.rotatedAt, &r.strictAll, &r.safeJSON, &r.suspendedAt, &c.SuspendReason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return finishScan(&c, r)
}

// rawColumns holds the columns that need converting after a scan.
type rawColumns struct {
	gate, strictAll                                                   int
	rulesJSON, safeJSON, createdAt, expiresAt, rotatedAt, suspendedAt string
	rotateEvery                                                       int64
}

func finishScan(c *Connection, r rawColumns) (*Connection, error) {
	c.GateMutations = r.gate != 0
	c.StrictAll = r.strictAll != 0
	if err := json.Unmarshal([]byte(r.rulesJSON), &c.PIIRules); err != nil {
		return nil, fmt.Errorf("decode pii_rules: %w", err)
	}
	if err := json.Unmarshal([]byte(r.safeJSON), &c.SafeRelations); err != nil {
		return nil, fmt.Errorf("decode safe_relations: %w", err)
	}
	if t, err := time.Parse(time.RFC3339Nano, r.createdAt); err == nil {
		c.CreatedAt = t
	}
	if r.expiresAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, r.expiresAt); err == nil {
			c.ExpiresAt = t
		}
	}
	if r.rotateEvery > 0 {
		c.RotateEvery = time.Duration(r.rotateEvery)
	}
	// A blank rotated_at (row predating the column) counts creation as the
	// last rotation.
	c.RotatedAt = c.CreatedAt
	if r.rotatedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, r.rotatedAt); err == nil {
			c.RotatedAt = t
		}
	}
	if r.suspendedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, r.suspendedAt); err == nil {
			c.SuspendedAt = t
		} else {
			c.SuspendedAt = time.Now().UTC() // unreadable: stay suspended
		}
	}
	return c, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func randomToken(nBytes int) (string, error) {
	b, err := randomBytes(nBytes)
	if err != nil {
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
