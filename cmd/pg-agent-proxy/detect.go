package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// piiNameHints maps a substring found in a column name to a suggested action.
// "redact" is suggested for high-sensitivity secrets; "hash" for identifiers
// you may still want to compare for equality.
var piiNameHints = []struct {
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

func suggestAction(columnName string) (string, bool) {
	lower := strings.ToLower(columnName)
	for _, h := range piiNameHints {
		if strings.Contains(lower, h.substr) {
			return h.action, true
		}
	}
	return "", false
}

// runDetectPII connects to the upstream database and prints a suggested pii
// config block based on column-name heuristics. It never modifies anything.
func runDetectPII(args []string) {
	fs := flag.NewFlagSet("detect-pii", flag.ExitOnError)
	upstream := fs.String("upstream", "", "upstream connection string to scan (required)")
	_ = fs.Parse(args)

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "-upstream connection string is required")
		os.Exit(2)
	}

	ctx := context.Background()
	conn, err := pgconn.Connect(ctx, *upstream)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upstream connect failed:", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	const q = `
SELECT table_name, column_name
FROM information_schema.columns
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY table_name, ordinal_position`

	results, err := conn.Exec(ctx, q).ReadAll()
	if err != nil {
		fmt.Fprintln(os.Stderr, "introspection failed:", err)
		os.Exit(1)
	}
	result := results[len(results)-1]

	type suggestion struct{ table, column, action string }
	var suggestions []suggestion
	for _, row := range result.Rows {
		table := string(row[0])
		column := string(row[1])
		if action, ok := suggestAction(column); ok {
			suggestions = append(suggestions, suggestion{table, column, action})
		}
	}

	if len(suggestions) == 0 {
		fmt.Println("# No likely PII columns detected by name heuristics.")
		return
	}

	fmt.Println("# Likely PII columns (review carefully — name heuristics only):")
	seen := map[string]bool{}
	var spec []string
	for _, s := range suggestions {
		fmt.Printf("#   %s.%s -> %s\n", s.table, s.column, s.action)
		key := s.column + ":" + s.action
		if !seen[key] {
			seen[key] = true
			spec = append(spec, key)
		}
	}
	fmt.Println("\n# Pass to `connections add` with:")
	fmt.Printf("#   -pii %s\n", strings.Join(spec, ","))
}
