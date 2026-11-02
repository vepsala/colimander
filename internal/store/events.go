package store

import (
	"time"
)

// maxSecurityEvents bounds the event log, since queries are stored with it.
const maxSecurityEvents = 5000

// Event kinds.
const (
	EventBlocked   = "blocked"   // the guard rejected a statement
	EventScrubbed  = "scrubbed"  // the value scanner replaced something in a result
	EventSuspended = "suspended" // the tripwire stopped the connection
	EventResumed   = "resumed"   // an operator resumed it, rotating the password
)

// SecurityEvent is one entry in the security log.
type SecurityEvent struct {
	ID            int64     `json:"id"`
	ConnectionID  int64     `json:"connection_id"`
	AgentUsername string    `json:"agent_username"`
	At            time.Time `json:"at"`
	Kind          string    `json:"kind"`
	Detail        string    `json:"detail"`
	// Query is what the agent sent. It can contain personal data, so it's
	// encrypted at rest and never written to the log file.
	Query string `json:"query,omitempty"`
}

// AddSecurityEvent records an event, encrypting query under the master key.
func (s *Store) AddSecurityEvent(connID int64, username, kind, detail, query string) error {
	enc, err := s.seal(query, fieldEvent, username)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO security_events (connection_id, agent_username, at, kind, detail, query_enc) VALUES (?, ?, ?, ?, ?, ?)`,
		connID, username, formatTimestamp(time.Now()), kind, detail, enc); err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM security_events WHERE id <= (SELECT MAX(id) FROM security_events) - ?`, maxSecurityEvents)
	return err
}

// SecurityEvents returns the most recent events, newest first.
func (s *Store) SecurityEvents(limit int) ([]SecurityEvent, error) {
	rows, err := s.db.Query(`SELECT id, connection_id, agent_username, at, kind, detail, query_enc FROM security_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SecurityEvent{}
	for rows.Next() {
		var e SecurityEvent
		var at, enc string
		if err := rows.Scan(&e.ID, &e.ConnectionID, &e.AgentUsername, &at, &e.Kind, &e.Detail, &enc); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		e.Query, _ = s.unseal(enc, fieldEvent, e.AgentUsername)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Suspend stops a connection from authenticating. It stays suspended across
// restarts until Resume.
func (s *Store) Suspend(id int64, reason string) error {
	res, err := s.db.Exec(`UPDATE connections SET suspended_at = ?, suspend_reason = ? WHERE id = ?`, formatTimestamp(time.Now()), reason, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Resume reactivates a suspended connection and returns its new password. The
// old password is assumed compromised, so resuming always rotates it.
func (s *Store) Resume(id int64) (string, error) {
	password, err := s.Rotate(id)
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`UPDATE connections SET suspended_at = '', suspend_reason = '' WHERE id = ?`, id); err != nil {
		return "", err
	}
	return password, nil
}
