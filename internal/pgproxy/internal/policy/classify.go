package policy

import "strings"

// Kind classifies a SQL statement for gating purposes.
type Kind int

const (
	// KindRead is a data-returning statement with no side effects (SELECT,
	// SHOW, EXPLAIN without ANALYZE, TABLE, VALUES, FETCH).
	KindRead Kind = iota
	// KindMutation writes data or changes schema, or otherwise has side
	// effects. These are gated behind approval when GateMutations is on.
	KindMutation
	// KindSession is a transaction/session-control statement that neither
	// returns rows nor mutates data (BEGIN, SET, COMMIT, ...). Always allowed.
	KindSession
)

func (k Kind) String() string {
	switch k {
	case KindRead:
		return "read"
	case KindMutation:
		return "mutation"
	case KindSession:
		return "session"
	default:
		return "unknown"
	}
}

// readKeywords are first tokens that begin a pure read.
var readKeywords = map[string]bool{
	"SELECT": true, "SHOW": true, "TABLE": true, "VALUES": true, "FETCH": true,
}

// sessionKeywords are first tokens that begin a session/transaction-control
// statement with no data effect.
var sessionKeywords = map[string]bool{
	"BEGIN": true, "START": true, "COMMIT": true, "END": true, "ROLLBACK": true,
	"SAVEPOINT": true, "RELEASE": true, "SET": true, "RESET": true,
	"DISCARD": true, "DEALLOCATE": true, "CLOSE": true, "LISTEN": true,
	"UNLISTEN": true, "CHECKPOINT": true,
}

// dangerKeywords are mutation/DDL keywords that, if they appear anywhere inside
// a WITH or EXPLAIN statement, force a mutation classification.
var dangerKeywords = []string{
	"INSERT", "UPDATE", "DELETE", "TRUNCATE", "MERGE",
	"DROP", "CREATE", "ALTER", "GRANT", "REVOKE", "COPY",
}

// Classify determines the Kind of the first/primary statement in sql.
//
// It is intentionally conservative: anything not clearly a read or a
// session-control statement is treated as a mutation so it gets gated.
func Classify(sql string) Kind {
	s := stripLeading(sql)
	first := firstToken(s)
	upper := strings.ToUpper(first)

	switch {
	case upper == "WITH" || upper == "EXPLAIN":
		// CTEs can contain data-modifying statements, and EXPLAIN ANALYZE
		// actually executes its target. Scan the body for danger keywords.
		if containsDanger(s) {
			return KindMutation
		}
		if upper == "EXPLAIN" && containsWord(strings.ToUpper(s), "ANALYZE") {
			// EXPLAIN ANALYZE executes; treat as mutation unless we proved the
			// body has no danger keyword above. A plain ANALYZE of a SELECT is
			// read-only, so allow it.
			return KindRead
		}
		return KindRead
	case readKeywords[upper]:
		return KindRead
	case sessionKeywords[upper]:
		return KindSession
	case upper == "PREPARE":
		// PREPARE itself is harmless; its execution goes through EXECUTE.
		return KindSession
	case upper == "EXECUTE":
		// We cannot see the prepared body, so gate conservatively.
		return KindMutation
	default:
		return KindMutation
	}
}

// stripLeading removes leading whitespace and SQL comments so the first real
// token can be found.
func stripLeading(sql string) string {
	for {
		sql = strings.TrimLeft(sql, " \t\r\n")
		switch {
		case strings.HasPrefix(sql, "--"):
			if i := strings.IndexByte(sql, '\n'); i >= 0 {
				sql = sql[i+1:]
				continue
			}
			return ""
		case strings.HasPrefix(sql, "/*"):
			if i := strings.Index(sql, "*/"); i >= 0 {
				sql = sql[i+2:]
				continue
			}
			return ""
		default:
			return sql
		}
	}
}

func firstToken(s string) string {
	i := 0
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '(' || c == ';' {
			break
		}
		i++
	}
	return s[:i]
}

func containsDanger(s string) bool {
	upper := strings.ToUpper(s)
	for _, kw := range dangerKeywords {
		if containsWord(upper, kw) {
			return true
		}
	}
	return false
}

// containsWord reports whether word appears in s delimited by non-identifier
// characters (so "delete" matches but "deleted_at" does not).
func containsWord(s, word string) bool {
	from := 0
	for {
		i := strings.Index(s[from:], word)
		if i < 0 {
			return false
		}
		i += from
		before := i == 0 || !isIdentChar(s[i-1])
		afterIdx := i + len(word)
		after := afterIdx >= len(s) || !isIdentChar(s[afterIdx])
		if before && after {
			return true
		}
		from = i + len(word)
	}
}

func isIdentChar(b byte) bool {
	return b == '_' ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9')
}
