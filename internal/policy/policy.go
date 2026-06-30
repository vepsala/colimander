// Package policy compiles per-connection rules into runtime decisions: how to
// classify a statement, and how to anonymize a column value.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
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
	// ActionLabel replaces the value with a readable per-row placeholder of the
	// form "<column>-<rownumber>" (e.g. "name-4"). Unlike hashing it is not
	// stable across queries, but it keeps results legible and distinct per row.
	ActionLabel
)

// PIIRule is a single anonymization rule for a connection.
type PIIRule struct {
	// Name is the column name to match (case-insensitive). Required.
	Name string `json:"name"`
	// Table optionally documents the owning table. It is used for schema
	// annotation and detection output only; streamed rows are matched by
	// column name regardless of table (a conservative default).
	Table string `json:"table,omitempty"`
	// Action is "hash" or "redact".
	Action string `json:"action"`
}

// Policy is the compiled, immutable set of rules used at request time.
type Policy struct {
	byColumn      map[string]Action
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
		rules:         rules,
		salt:          []byte(hashSalt),
		redact:        []byte(redactString),
		maxRows:       maxRows,
		gateMutations: gateMutations,
	}
	for _, r := range rules {
		p.byColumn[strings.ToLower(r.Name)] = ParseAction(r.Action)
	}
	return p
}

// ParseAction converts a config string to an Action.
func ParseAction(s string) Action {
	switch strings.ToLower(s) {
	case "hash":
		return ActionHash
	case "redact":
		return ActionRedact
	case "label":
		return ActionLabel
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

// ActionFor returns the anonymization action for a column name.
func (p *Policy) ActionFor(columnName string) Action {
	if a, ok := p.byColumn[strings.ToLower(columnName)]; ok {
		return a
	}
	return ActionNone
}

// AnonymizeValue applies the column's action to a raw value, honoring the
// column's PostgreSQL type OID. column and rowNumber are used only by
// ActionLabel to build a per-row placeholder ("<column>-<rowNumber>").
//
//   - A nil value (SQL NULL) is returned unchanged.
//   - For text-family columns the transformed bytes are valid in both the text
//     and binary wire formats, so the transform is applied directly.
//   - For non-text columns (numbers, dates, ...) a replacement string cannot be
//     safely encoded, so the value is replaced with NULL. This is a deliberate,
//     safe default; keep PII in text columns to retain anonymization.
func (p *Policy) AnonymizeValue(action Action, typeOID uint32, value []byte, column string, rowNumber int) []byte {
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
	case ActionLabel:
		return []byte(column + "-" + strconv.Itoa(rowNumber))
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
