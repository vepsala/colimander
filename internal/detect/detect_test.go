package detect

import "testing"

func TestSuggestAction(t *testing.T) {
	cases := []struct {
		column     string
		wantAction string
		wantMatch  bool
	}{
		{"email", "hash", true},
		{"user_email", "hash", true}, // substring match
		{"EmailAddress", "hash", true},
		{"phone", "hash", true},
		{"full_name", "hash", true},
		{"password_hash", "redact", true}, // "password" wins (redact)
		{"api_key", "redact", true},
		{"card_number", "redact", true},
		{"ssn", "hash", true},
		{"id", "", false},
		{"amount", "", false},
		{"created_at", "", false},
	}
	for _, c := range cases {
		action, ok := SuggestAction(c.column)
		if ok != c.wantMatch || action != c.wantAction {
			t.Errorf("SuggestAction(%q) = (%q, %v), want (%q, %v)", c.column, action, ok, c.wantAction, c.wantMatch)
		}
	}
}
