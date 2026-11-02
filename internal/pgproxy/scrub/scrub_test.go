package scrub

import (
	"strings"
	"testing"
)

func TestTextFinds(t *testing.T) {
	cases := []struct {
		in, kind string
	}{
		{"mail alice@example.com please", KindEmail},
		{"call +358 40 1234567 today", KindPhone},
		{"call 040 123 4567 today", KindPhone},
		{"hetu 131052-308T here", KindNationalID},
		{"tili FI21 1234 5600 0007 85", KindIBAN},
		{"card 4111 1111 1111 1111", KindCard},
		{"key sk-abcdefghijklmnopqrstuvwxyz123456", KindSecret},
		{"key AKIAIOSFODNN7EXAMPLE", KindSecret},
		{"dsn postgres://user:hunter2@db/app", KindSecret},
		{`{"contact":"bob@leak.example"}`, KindEmail},
		{`(1,alice@example.com,"Alice",x)`, KindEmail},
	}
	for _, c := range cases {
		out, kinds := String(c.in)
		if len(kinds) != 1 || kinds[0] != c.kind {
			t.Errorf("String(%q) kinds = %v, want %s", c.in, kinds, c.kind)
		}
		if !strings.Contains(out, "[REDACTED:"+c.kind+"]") {
			t.Errorf("String(%q) = %q", c.in, out)
		}
	}
}

func TestTextLeavesOrdinaryValues(t *testing.T) {
	for _, in := range []string{
		"", "hello world", "order 12345", "2026-11-02 10:04:09", "v1.2.3",
		"131052-308A",            // wrong hetu control character
		"FI21 1234 5600 0007 86", // wrong IBAN checksum
		"4111 1111 1111 1112",    // wrong card checksum
		"550e8400-e29b-41d4-a716-446655440000",
		"not an @ address",
	} {
		if out, kinds := String(in); out != in || kinds != nil {
			t.Errorf("String(%q) = %q, %v", in, out, kinds)
		}
	}
}

func TestTextReportsEachKindOnce(t *testing.T) {
	_, kinds := String("a@example.com b@example.com +358401234567")
	if len(kinds) != 2 {
		t.Errorf("kinds = %v", kinds)
	}
}
