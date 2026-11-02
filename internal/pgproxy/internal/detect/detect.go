// Package detect suggests PII rules for a person to review. Nothing is masked
// because of a suggestion, only once it's saved as a rule.
//
// It provides best-effort PII discovery: it introspects a
// database's schema and flags columns whose names suggest personal data. It is
// a heuristic (name matching only) — every result must be reviewed by a human.
package detect

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// hints are substrings of column names that suggest personal data or secrets.
var hints = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey", "private_key",
	"card", "cvv", "iban", "account_number", "ssn", "social_security",
	"national_id", "passport", "hetu", "henkilotunnus", "email", "phone", "mobile",
	"msisdn", "address", "street", "postal", "zip", "first_name", "last_name",
	"full_name", "customer_name", "contact", "birth", "dob", "date_of_birth",
	"rekkari", "license_plate", "reg_number",
	// Free text: a scanner can't reliably spot a person's name in these.
	"comment", "message", "description", "remark",
}

// exactHints are too short or common to match as substrings.
var exactHints = map[string]bool{
	"name": true, "surname": true, "note": true, "notes": true, "body": true,
	"bio": true, "content": true, "text": true, "memo": true, "subject": true,
}

// SuggestAction returns a suggested anonymization action for a column name, and
// whether the name matched any heuristic at all. It always suggests "redact": a
// hash is generally still personal data under GDPR, so hashing should be a
// deliberate choice.
func SuggestAction(columnName string) (string, bool) {
	lower := strings.ToLower(columnName)
	if exactHints[lower] {
		return "redact", true
	}
	for _, h := range hints {
		if strings.Contains(lower, h) {
			return "redact", true
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
