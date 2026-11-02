// Package scrub finds personal data and secrets by their shape in values that
// column rules didn't catch: free text, and anything a view or function renamed.
// It is a best-effort second layer. It can't recognise a person's name, so
// free-text columns should still be marked as PII.
package scrub

import (
	"regexp"
	"strconv"
	"strings"
)

// Kinds of data Text can find.
const (
	KindEmail      = "email"
	KindPhone      = "phone"
	KindNationalID = "national_id"
	KindIBAN       = "iban"
	KindCard       = "card"
	KindSecret     = "secret"
)

type pattern struct {
	kind  string
	re    *regexp.Regexp
	valid func(string) bool // optional check that cuts false positives
}

// Order matters: specific shapes run first, so a card number isn't half-eaten
// by the phone pattern.
var patterns = []pattern{
	{KindSecret, regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)`), nil},
	{KindSecret, regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`), nil},
	{KindEmail, regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`), nil},
	{KindNationalID, regexp.MustCompile(`\b\d{6}[-+A-FU-Y]\d{3}[0-9A-Y]\b`), validHetu},
	{KindIBAN, regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b`), validIBAN},
	{KindCard, regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`), validLuhn},
	{KindPhone, regexp.MustCompile(`\+\d[\d ()-]{7,16}\d`), nil},
	{KindPhone, regexp.MustCompile(`\b0(?:4\d|50)[ -]?\d{3}[ -]?\d{3,4}\b`), nil},
}

// Text replaces anything sensitive in b and returns the result along with the
// kinds found. It returns b itself when nothing matched.
func Text(b []byte) ([]byte, []string) {
	if len(b) == 0 {
		return b, nil
	}
	var kinds []string
	out := b
	for _, p := range patterns {
		out = p.re.ReplaceAllFunc(out, func(m []byte) []byte {
			if p.valid != nil && !p.valid(string(m)) {
				return m
			}
			kinds = appendUnique(kinds, p.kind)
			return []byte("[REDACTED:" + p.kind + "]")
		})
	}
	return out, kinds
}

// String is Text for strings.
func String(s string) (string, []string) {
	out, kinds := Text([]byte(s))
	return string(out), kinds
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// validHetu checks a Finnish personal identity code's control character.
func validHetu(s string) bool {
	const controls = "0123456789ABCDEFHJKLMNPRSTUVWXY"
	n, err := strconv.Atoi(s[:6] + s[7:10])
	if err != nil {
		return false
	}
	return controls[n%31] == s[10]
}

// validIBAN applies the ISO 13616 mod-97 check.
func validIBAN(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	rearranged := s[4:] + s[:4]
	remainder := 0
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			remainder = (remainder*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			remainder = (remainder*100 + int(r-'A') + 10) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

// validLuhn applies the payment card checksum.
func validLuhn(s string) bool {
	sum, double, digits := 0, false, 0
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
		digits++
	}
	return digits >= 13 && digits <= 19 && sum%10 == 0
}
