package detect

import "testing"

func TestSuggestAction(t *testing.T) {
	cases := []struct {
		column     string
		wantAction string
		wantMatch  bool
	}{
		{"email", "redact", true},
		{"user_email", "redact", true}, // substring match
		{"EmailAddress", "redact", true},
		{"phone", "redact", true},
		{"full_name", "redact", true},
		{"password_hash", "redact", true}, // "password" wins (redact)
		{"api_key", "redact", true},
		{"card_number", "redact", true},
		{"ssn", "redact", true},
		{"notes", "redact", true},
		{"name", "redact", true},
		{"message_body", "redact", true},
		{"id", "", false},
		{"username", "", false},
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
