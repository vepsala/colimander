// Package policy compiles per-connection rules into runtime decisions: how to
// classify a statement, and how to anonymize a column value.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Action is what to do with a PII column value.
type Action int

const (
	// ActionNone leaves the value untouched.
	ActionNone Action = iota
	// ActionHash replaces the value with a salted SHA-256 hex digest. Equal
	// inputs hash equally, so values can still be compared for identity.
	ActionHash
	// ActionRedact replaces the value with the configured redaction string.
	ActionRedact
)

// PIIRule is a single anonymization rule for a connection.
type PIIRule struct {
	// Name is the column name to match (case-insensitive). Required.
	Name string `json:"name"`
	// Table limits the rule to one table. Without it, the rule covers the column
	// in every table.
	Table string `json:"table,omitempty"`
	// Action is "redact", "hash" or "allow". A hash is pseudonymous, not
	// anonymous: under GDPR it generally remains personal data, so prefer redact.
	// "allow" records that a column was reviewed and holds nothing sensitive,
	// which also exempts it from a broader rule.
	Action string `json:"action"`
}

// Policy is the compiled, immutable set of rules used at request time.
type Policy struct {
	byColumn      map[string]Action // rules with no table
	byTable       map[string]Action // rules with a table, keyed "table.column"
	byName        map[string]Action // every rule by column name, most restrictive
	rules         []PIIRule
	salt          []byte
	redact        []byte
	maxRows       int
	gateMutations bool
}

// New compiles a Policy.
func New(rules []PIIRule, hashSalt, redactString string, maxRows int, gateMutations bool) *Policy {
	if redactString == "" {
		redactString = "[REDACTED]"
	}
	p := &Policy{
		byColumn:      make(map[string]Action, len(rules)),
		byTable:       make(map[string]Action, len(rules)),
		byName:        make(map[string]Action, len(rules)),
		rules:         rules,
		salt:          []byte(hashSalt),
		redact:        []byte(redactString),
		maxRows:       maxRows,
		gateMutations: gateMutations,
	}
	for _, r := range rules {
		name, action := strings.ToLower(r.Name), ParseAction(r.Action)
		if r.Table != "" {
			p.byTable[strings.ToLower(tableName(r.Table))+"."+name] = action
		} else {
			p.byColumn[name] = action
		}
		if existing, ok := p.byName[name]; !ok || action > existing {
			p.byName[name] = action
		}
	}
	return p
}

// tableName strips any schema from a table name.
func tableName(t string) string {
	if i := strings.LastIndexByte(t, '.'); i >= 0 {
		return t[i+1:]
	}
	return t
}

// ParseAction converts a config string to an Action. "allow", and anything
// unrecognised, returns ActionNone; only the rule's presence distinguishes them.
func ParseAction(s string) Action {
	switch strings.ToLower(s) {
	case "hash":
		return ActionHash
	case "redact":
		return ActionRedact
	default:
		return ActionNone
	}
}

// MaxRows returns the configured read-result row limit (0 = unlimited).
func (p *Policy) MaxRows() int { return p.maxRows }

// GateMutations reports whether mutating statements require approval.
func (p *Policy) GateMutations() bool { return p.gateMutations }

// Rules returns the configured PII rules (used for schema annotation).
func (p *Policy) Rules() []PIIRule { return p.rules }

// ActionFor returns the action for a result column known only by its name, such
// as a computed column. It errs towards masking: a rule for that name applies
// whatever the rule's table.
func (p *Policy) ActionFor(columnName string) Action {
	return p.byName[strings.ToLower(columnName)]
}

// ActionForOrigin returns the action for a column whose source table is known.
// PostgreSQL still reports the source through an alias, so this catches renames.
func (p *Policy) ActionForOrigin(table, column string) Action {
	name := strings.ToLower(column)
	if a, ok := p.byTable[strings.ToLower(table)+"."+name]; ok {
		return a
	}
	return p.byColumn[name]
}

// AnonymizeValue applies the column's action to a raw value, honoring the
// column's PostgreSQL type OID.
//
//   - A nil value (SQL NULL) is returned unchanged.
//   - For text-family columns the transformed bytes are valid in both the text
//     and binary wire formats, so hashing/redaction is applied directly.
//   - For non-text columns (numbers, dates, ...) a hash/redact string cannot be
//     safely encoded, so the value is replaced with NULL. This is a deliberate,
//     safe default; keep PII in text columns to retain hashing.
func (p *Policy) AnonymizeValue(action Action, typeOID uint32, value []byte) []byte {
	if value == nil || action == ActionNone {
		return value
	}
	if !IsTextFamilyOID(typeOID) {
		return nil // NULL out non-text PII rather than risk a decode error.
	}
	switch action {
	case ActionHash:
		h := sha256.New()
		h.Write(p.salt)
		h.Write(value)
		sum := h.Sum(nil)
		out := make([]byte, hex.EncodedLen(len(sum)))
		hex.Encode(out, sum)
		return out
	case ActionRedact:
		out := make([]byte, len(p.redact))
		copy(out, p.redact)
		return out
	default:
		return value
	}
}

// textFamilyOIDs are PostgreSQL types whose binary wire format is identical to
// their text representation (raw UTF-8 bytes), so byte-level anonymization is
// format-agnostic for them.
var textFamilyOIDs = map[uint32]bool{
	0:    true, // unknown / untyped
	18:   true, // char
	19:   true, // name
	25:   true, // text
	1042: true, // bpchar
	1043: true, // varchar
	705:  true, // unknown
}

// IsTextFamilyOID reports whether a type OID is a text-family type.
func IsTextFamilyOID(oid uint32) bool { return textFamilyOIDs[oid] }
