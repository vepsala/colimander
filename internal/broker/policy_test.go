package broker

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
		"/repos/vepsala/kotisivukamu":          "vepsala",
		"/repos/vepsala/kotisivukamu/git/refs": "vepsala",
		"/orgs/acme":                           "acme",
		"/orgs/acme/members/foo":               "acme",
		"/users/vepsala":                       "vepsala",
		"/user":                                "",
		"/user/keys":                           "",
		"/rate_limit":                          "",
		"/":                                    "",
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
		DenyRules:     DefaultDenyRules(),
	}
	allowed := []struct{ method, path string }{
		{"GET", "/repos/vepsala/kotisivukamu"},
		{"GET", "/repos/vepsala/kotisivukamu/commits"},
		{"POST", "/repos/vepsala/kotisivukamu/issues"},    // create issue
		{"POST", "/repos/vepsala/kotisivukamu/pulls"},     // open PR
		{"PATCH", "/repos/vepsala/kotisivukamu/issues/1"}, // edit issue
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
		DenyRules:     DefaultDenyRules(),
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

func TestCheckAPIDeniesPathsItCantCheck(t *testing.T) {
	p := &Policy{
		AllowedOwners: []string{"vepsala", "acme"},
		DenyRules:     DefaultDenyRules(),
	}
	denied := []struct{ method, path string }{
		// Reaches any repo by numeric ID, with no owner in the path.
		{"GET", "/repositories/123"},
		{"DELETE", "/repositories/123/labels/bug"},
		{"DELETE", "/repositories/123/git/refs/heads/main"},
		// Other owner-less prefixes the broker doesn't know.
		{"PUT", "/teams/1/memberships/someone"},
		{"DELETE", "/projects/1"},
		{"POST", "/graphql"}, // only via checkGraphQL, which reads the body
		{"POST", "/graphql/x"},
		// Shapes that match differently here than at GitHub.
		{"DELETE", "/repos/vepsala/kotisivukamu/"},
		{"DELETE", "/repos//vepsala/kotisivukamu"},
		{"DELETE", "/repos/vepsala/./kotisivukamu"},
		{"DELETE", "/repos/vepsala/x/../kotisivukamu"},
		{"POST", "/repos/vepsala/kotisivukamu/hooks?"}, // a decoded %3F
		{"POST", "/repos/vepsala/kotisivukamu/hooks#"},
		{"POST", "/repos/vepsala/kotisivukamu/hooks%2F"},
		{"POST", "/repos/vepsala/kotisivukamu/hooks\t"},
		// Case doesn't dodge a rule or the owner check.
		{"DELETE", "/Repos/vepsala/kotisivukamu"},
		{"POST", "/repos/vepsala/kotisivukamu/Hooks"},
		{"GET", "/REPOS/other/x"},
		{"GET", "/Repositories/123"},
	}
	for _, c := range denied {
		if ok, _ := p.checkAPI(c.method, c.path); ok {
			t.Errorf("checkAPI(%s %q) allowed but should have been denied", c.method, c.path)
		}
	}
	for _, path := range []string{"/", "/rate_limit", "/search/issues", "/user/repos", "/repos/vepsala/kotisivukamu/pulls/1"} {
		if ok, reason := p.checkAPI("GET", path); !ok {
			t.Errorf("checkAPI(GET %s) denied: %s", path, reason)
		}
	}
}

func TestCheckAPIDeniesUnknownOwner(t *testing.T) {
	p := &Policy{
		AllowedOwners: []string{"vepsala"},
		DenyRules:     DefaultDenyRules(),
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
	p := &Policy{DenyRules: DefaultDenyRules()}
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

func TestCheckGitPush(t *testing.T) {
	p := &Policy{DenyRules: []DenyRule{
		{ID: "no-push-kotisivukamu", Kind: "git-push", PathGlob: "/kotisivukamu/*",
			Reason: "kotisivukamu repos are pull-only from this profile."},
	}}
	ok, reason := p.checkGitPush("/kotisivukamu/kamu-pi-extension.git")
	if ok {
		t.Errorf("expected push to kotisivukamu repo to be denied")
	}
	if !contains(reason, "no-push-kotisivukamu") {
		t.Errorf("expected reason to name the rule, got %q", reason)
	}
	// Pushes to other owners are untouched by the rule.
	ok, _ = p.checkGitPush("/bossgloss/bg-backend.git")
	if !ok {
		t.Errorf("expected push to bossgloss repo to be allowed; got DENY")
	}
}
