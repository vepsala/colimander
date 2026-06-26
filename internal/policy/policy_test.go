package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func testPolicy() *Policy {
	return New([]PIIRule{
		{Name: "email", Action: "hash"},
		{Name: "SSN", Action: "redact"},
		{Name: "phone", Table: "users", Action: "hash"},
	}, "s4lt", "[REDACTED]", 1000, true)
}

func TestActionFor(t *testing.T) {
	p := testPolicy()
	cases := map[string]Action{
		"email": ActionHash,
		"EMAIL": ActionHash, // case-insensitive
		"ssn":   ActionRedact,
		"phone": ActionHash, // table-qualified rule still matches by name
		"name":  ActionNone,
	}
	for col, want := range cases {
		if got := p.ActionFor(col); got != want {
			t.Errorf("ActionFor(%q) = %v, want %v", col, got, want)
		}
	}
}

func TestAnonymizeHashIsStableAndSalted(t *testing.T) {
	p := testPolicy()
	val := []byte("alice@example.com")

	got := p.AnonymizeValue(ActionHash, textOID, val)

	h := sha256.New()
	h.Write([]byte("s4lt"))
	h.Write(val)
	want := hex.EncodeToString(h.Sum(nil))
	if string(got) != want {
		t.Fatalf("hash = %s, want %s", got, want)
	}
	if string(p.AnonymizeValue(ActionHash, textOID, val)) != string(got) {
		t.Fatal("hash is not stable across calls")
	}
	if string(p.AnonymizeValue(ActionHash, textOID, []byte("bob@example.com"))) == string(got) {
		t.Fatal("distinct inputs produced the same hash")
	}
}

const textOID = 25

func TestAnonymizeRedact(t *testing.T) {
	p := testPolicy()
	if got := p.AnonymizeValue(ActionRedact, textOID, []byte("123-45-6789")); string(got) != "[REDACTED]" {
		t.Errorf("redact = %s, want [REDACTED]", got)
	}
}

func TestAnonymizeNilPassesThrough(t *testing.T) {
	p := testPolicy()
	if got := p.AnonymizeValue(ActionHash, textOID, nil); got != nil {
		t.Errorf("nil (SQL NULL) should pass through unchanged, got %v", got)
	}
}

func TestAnonymizeNonTextBecomesNull(t *testing.T) {
	p := testPolicy()
	// int8 OID 20 is not text-family: a hashed/redacted value can't be safely
	// encoded, so it is nulled out.
	if got := p.AnonymizeValue(ActionHash, 20, []byte{0, 0, 0, 0, 0, 0, 0, 1}); got != nil {
		t.Errorf("non-text PII should become NULL, got %v", got)
	}
	if got := p.AnonymizeValue(ActionRedact, 20, []byte("x")); got != nil {
		t.Errorf("non-text PII redact should become NULL, got %v", got)
	}
}

func TestIsTextFamilyOID(t *testing.T) {
	for _, oid := range []uint32{25, 1043, 1042, 19} {
		if !IsTextFamilyOID(oid) {
			t.Errorf("OID %d should be text-family", oid)
		}
	}
	for _, oid := range []uint32{20, 23, 1114, 16} {
		if IsTextFamilyOID(oid) {
			t.Errorf("OID %d should not be text-family", oid)
		}
	}
}
