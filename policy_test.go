package main

import "testing"

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/repos/*/*", "/repos/foo/bar", true},
		{"/repos/*/*", "/repos/foo/bar/baz", false}, // single * doesn't cross /
		{"/repos/*/*/git/refs/heads/main", "/repos/foo/bar/git/refs/heads/main", true},
		{"/repos/*/*/git/refs/heads/main", "/repos/foo/bar/git/refs/heads/dev", false},
		{"/repos/*/*/git/refs/**", "/repos/foo/bar/git/refs/heads/main", true},
		{"/repos/*/*/git/refs/**", "/repos/foo/bar/git/refs/tags/v1.0", true},
		{"/repos/*/*/git/refs/**", "/repos/foo/bar/git/something/else", false},
		{"/user", "/user", true},
		{"/user", "/user/keys", false},
		{"/user/keys", "/user/keys", true},
		{"/user/keys", "/user/keys/123", false},
		{"/user/keys/*", "/user/keys/123", true},
		{"/orgs/*", "/orgs/acme", true},
		{"/orgs/*", "/orgs/acme/members", false},
		{"/", "/", true},
	}
	for _, c := range cases {
		got := matchGlob(c.pattern, c.path)
		if got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestExtractAPIOwner(t *testing.T) {
	cases := map[string]string{
		"/repos/vepsala/kotisivukamu":              "vepsala",
		"/repos/vepsala/kotisivukamu/git/refs":     "vepsala",
		"/orgs/acme":                               "acme",
		"/orgs/acme/members/foo":                   "acme",
		"/users/vepsala":                           "vepsala",
		"/user":                                    "",
		"/user/keys":                               "",
		"/rate_limit":                              "",
		"/":                                        "",
	}
	for path, want := range cases {
		got := extractAPIOwner(path)
		if got != want {
			t.Errorf("extractAPIOwner(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestCheckAPIAllowsBenignReads(t *testing.T) {
	p := &Policy{
		AllowedOwners: []string{"vepsala", "acme"},
		DenyRules:     defaultDenyRules(),
	}
	allowed := []struct{ method, path string }{
		{"GET", "/repos/vepsala/kotisivukamu"},
		{"GET", "/repos/vepsala/kotisivukamu/commits"},
		{"POST", "/repos/vepsala/kotisivukamu/issues"},        // create issue
		{"POST", "/repos/vepsala/kotisivukamu/pulls"},         // open PR
		{"PATCH", "/repos/vepsala/kotisivukamu/issues/1"},     // edit issue
		{"GET", "/user"},
		{"GET", "/orgs/acme/repos"},
	}
	for _, c := range allowed {
		ok, reason := p.checkAPI(c.method, c.path)
		if !ok {
			t.Errorf("checkAPI(%s %s) denied unexpectedly: %s", c.method, c.path, reason)
		}
	}
}

func TestCheckAPIDeniesDisasters(t *testing.T) {
	p := &Policy{
		AllowedOwners: []string{"vepsala", "acme"},
		DenyRules:     defaultDenyRules(),
	}
	denied := []struct {
		method, path, expectID string
	}{
		{"DELETE", "/repos/vepsala/kotisivukamu", "delete-repository"},
		{"DELETE", "/repos/vepsala/kotisivukamu/git/refs/heads/main", "delete-main-via-api"},
		{"DELETE", "/repos/vepsala/kotisivukamu/branches/main/protection", "remove-branch-protection"},
		{"PUT", "/repos/vepsala/kotisivukamu/branches/main/protection", "weaken-branch-protection"},
		{"DELETE", "/repos/vepsala/kotisivukamu/actions/secrets/PROD_TOKEN", "delete-repo-actions-secret"},
		{"DELETE", "/orgs/acme/actions/secrets/SHARED", "delete-org-actions-secret"},
		{"POST", "/repos/vepsala/kotisivukamu/hooks", "create-repo-webhook"},
		{"DELETE", "/repos/vepsala/kotisivukamu/hooks/123", "delete-repo-webhook"},
		{"POST", "/user/keys", "add-user-ssh-key"},
		{"DELETE", "/user/keys/1", "delete-user-ssh-key"},
		{"PATCH", "/user", "modify-user"},
		{"PATCH", "/orgs/acme", "modify-org-settings"},
		{"POST", "/repos/vepsala/kotisivukamu/transfer", "transfer-repository"},
		{"DELETE", "/orgs/acme", "delete-org"},
	}
	for _, c := range denied {
		ok, reason := p.checkAPI(c.method, c.path)
		if ok {
			t.Errorf("checkAPI(%s %s) allowed but should have been denied", c.method, c.path)
			continue
		}
		if !contains(reason, c.expectID) {
			t.Errorf("checkAPI(%s %s) denied with reason %q, expected rule %q", c.method, c.path, reason, c.expectID)
		}
	}
}

func TestCheckAPIDeniesUnknownOwner(t *testing.T) {
	p := &Policy{
		AllowedOwners: []string{"vepsala"},
		DenyRules:     defaultDenyRules(),
	}
	ok, reason := p.checkAPI("GET", "/repos/some-other-user/secret-repo")
	if ok {
		t.Fatalf("expected denial for off-allowlist owner; got ALLOW")
	}
	if !contains(reason, "allowed_owners") {
		t.Fatalf("denial reason should mention allowed_owners; got %q", reason)
	}
}

func TestCheckGitDelete(t *testing.T) {
	p := &Policy{DenyRules: defaultDenyRules()}
	for _, ref := range []string{"refs/heads/main", "refs/heads/master"} {
		ok, _ := p.checkGitDelete(ref)
		if ok {
			t.Errorf("expected delete of %s to be denied", ref)
		}
	}
	// Random feature branch deletion is fine.
	ok, _ := p.checkGitDelete("refs/heads/feature/x")
	if !ok {
		t.Errorf("expected delete of feature branch to be allowed; got DENY")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
