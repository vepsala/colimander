// Package detect provides best-effort PII discovery: it introspects a
// database's schema and flags columns whose names suggest personal data. It is
// a heuristic (name matching only) — every result must be reviewed by a human.
package detect

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// nameHints maps a substring found in a column name to a suggested action.
// "redact" is suggested for high-sensitivity secrets; "hash" for identifiers
// you may still want to compare for equality.
var nameHints = []struct {
	substr string
	action string
}{
	{"password", "redact"}, {"passwd", "redact"}, {"secret", "redact"},
	{"token", "redact"}, {"api_key", "redact"}, {"apikey", "redact"},
	{"private_key", "redact"}, {"card", "redact"}, {"cvv", "redact"},
	{"iban", "hash"}, {"account_number", "hash"}, {"ssn", "hash"},
	{"social_security", "hash"}, {"national_id", "hash"}, {"passport", "hash"},
	{"email", "hash"}, {"phone", "hash"}, {"mobile", "hash"}, {"msisdn", "hash"},
	{"address", "hash"}, {"street", "hash"}, {"postal", "hash"}, {"zip", "hash"},
	{"first_name", "hash"}, {"last_name", "hash"}, {"full_name", "hash"},
	{"birth", "hash"}, {"dob", "hash"}, {"date_of_birth", "hash"},
	{"rekkari", "hash"}, {"license_plate", "hash"}, {"reg_number", "hash"},
}

// SuggestAction returns a suggested anonymization action for a column name, and
// whether the name matched any heuristic at all.
func SuggestAction(columnName string) (string, bool) {
	lower := strings.ToLower(columnName)
	for _, h := range nameHints {
		if strings.Contains(lower, h.substr) {
			return h.action, true
		}
	}
	return "", false
}

// Match is a single column flagged as likely PII.
type Match struct {
	Table  string
	Column string
	Action string
}

// introspectQuery lists user-table columns (excludes the system catalogs).
const introspectQuery = `
SELECT table_name, column_name
FROM information_schema.columns
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY table_name, ordinal_position`

// Scan connects to upstreamURL, reads its schema, and returns the columns whose
// names look like PII. It is read-only and never modifies the database. The
// caller should bound the work with a context deadline.
func Scan(ctx context.Context, upstreamURL string) ([]Match, error) {
	conn, err := pgconn.Connect(ctx, upstreamURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	results, err := conn.Exec(ctx, introspectQuery).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	result := results[len(results)-1]

	var matches []Match
	for _, row := range result.Rows {
		table, column := string(row[0]), string(row[1])
		if action, ok := SuggestAction(column); ok {
			matches = append(matches, Match{Table: table, Column: column, Action: action})
		}
	}
	return matches, nil
}
