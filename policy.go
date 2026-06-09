// Per-profile policy enforced by the broker.
//
// A policy answers two questions for each request that comes from the VM:
//
//  1. Is the request targeting an owner this profile is allowed to touch?
//     (allowed_owners — populated from the host user's gh login and the orgs
//     they pick during setup.)
//  2. Does the request match a deny rule? Default rules cover the operations
//     that are hard or impossible to recover from after a VM compromise:
//     repo delete/transfer, branch deletion of main/master, branch-protection
//     removal, secret deletion, webhook creation/modification, key changes,
//     org settings, etc. Anything not matched is allowed through.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// generateHandle returns a 32-char hex string suitable for use as the
// per-profile shared secret presented over HTTP Basic auth.
func generateHandle() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b[:])
}

const policyVersion = 1

// Policy is the on-disk policy file shape, one per profile at
// ~/.colima/<name>/policy.json.
//
// Handle is the per-profile shared secret the VM presents in HTTP Basic auth
// (username = profile name, password = handle). The broker uses this to
// identify which profile is calling and to gate access — source-IP-based
// identity doesn't work because lima/vz forwards the VM's outbound
// host.lima.internal connections via a host-side socket, so they arrive at
// the broker as loopback.
type Policy struct {
	Version       int        `json:"version"`
	Handle        string     `json:"handle"`
	AllowedOwners []string   `json:"allowed_owners"`
	DenyRules     []DenyRule `json:"deny_rules"`

	// Optional external-service brokers. nil means "this profile cannot call
	// that service" — the broker returns 403 on the corresponding route.
	// Unlike GitHub (which is denylist-based: allow everything except the
	// destructive rules), Fly and Doppler are allowlist-based: only methods
	// + paths matching AllowedEndpoints get through. Smaller blast radius.
	FlyPolicy     *FlyPolicy     `json:"fly_policy,omitempty"`
	DopplerPolicy *DopplerPolicy `json:"doppler_policy,omitempty"`
}

// EndpointRule is the allowlist primitive shared by Fly and Doppler. A request
// is allowed if at least one rule matches both Method and PathGlob.
type EndpointRule struct {
	Method      string `json:"method"`
	PathGlob    string `json:"path_glob"`
	Description string `json:"description,omitempty"`
}

// FlyPolicy gates which fly.io API operations a VM may call.
//
// AllowedApps is a soft scope check: when a path includes an app name
// (/v1/apps/<app>/...), the broker verifies that <app> is in this list.
// Paths without an app segment skip the check.
//
// AllowedEndpoints is the per-(method, path) allowlist. Endpoints not on the
// list are denied — there is no equivalent of DenyRules here, by design: the
// fly API surface is large and "default deny" is the safer model.
type FlyPolicy struct {
	AllowedApps      []string       `json:"allowed_apps"`
	AllowedEndpoints []EndpointRule `json:"allowed_endpoints"`
}

// DopplerPolicy gates doppler secrets access.
//
// AllowedProjects is a project-name allowlist. When the request carries a
// `project` query parameter (Doppler's standard scoping mechanism), the
// broker verifies it's in this list.
//
// AllowedEndpoints follows the same shape as Fly's. The default rule set is
// intentionally write-only (POST /v3/configs/config/secrets) to match the
// "agent can add secrets, never read them" use case.
type DopplerPolicy struct {
	AllowedProjects  []string       `json:"allowed_projects"`
	AllowedEndpoints []EndpointRule `json:"allowed_endpoints"`
}

// DenyRule describes one operation the broker refuses.
//
// Kind selects which surface the rule applies to:
//   - "api": matches Method + PathGlob against requests proxied to api.github.com.
//   - "git-delete-ref": matches RefGlob against ref-deletes inside git push
//     bodies (pkt-line with new-sha all zeros).
type DenyRule struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Method   string `json:"method,omitempty"`
	PathGlob string `json:"path_glob,omitempty"`
	RefGlob  string `json:"ref_glob,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func defaultDenyRules() []DenyRule {
	return []DenyRule{
		// Repo lifecycle.
		{ID: "delete-repository", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*",
			Reason: "Deleting a repository is destructive; recovery is slow/manual."},
		{ID: "transfer-repository", Kind: "api", Method: "POST", PathGlob: "/repos/*/*/transfer",
			Reason: "Transferring a repo to another owner is hard to reverse."},
		// Org lifecycle (the org DELETE endpoint exists internally even if rarely advertised).
		{ID: "delete-org", Kind: "api", Method: "DELETE", PathGlob: "/orgs/*",
			Reason: "Org deletion is catastrophic and difficult to recover."},
		// Branch refs via API.
		{ID: "delete-main-via-api", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/git/refs/heads/main",
			Reason: "Deleting main via the API."},
		{ID: "delete-master-via-api", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/git/refs/heads/master",
			Reason: "Deleting master via the API."},
		// Branch protection.
		{ID: "remove-branch-protection", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/branches/*/protection",
			Reason: "Removing branch protection invites force-push abuse next."},
		{ID: "weaken-branch-protection", Kind: "api", Method: "PUT", PathGlob: "/repos/*/*/branches/*/protection",
			Reason: "Weakening branch protection from inside the VM."},
		// Secrets.
		{ID: "delete-repo-actions-secret", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/actions/secrets/*",
			Reason: "Deleting Actions secrets (breaks CI silently)."},
		{ID: "delete-org-actions-secret", Kind: "api", Method: "DELETE", PathGlob: "/orgs/*/actions/secrets/*",
			Reason: "Deleting org-level Actions secrets."},
		{ID: "delete-env-secret", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/environments/*/secrets/*",
			Reason: "Deleting environment secrets."},
		{ID: "delete-dependabot-secret", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/dependabot/secrets/*",
			Reason: "Deleting Dependabot secrets."},
		{ID: "delete-codespaces-secret", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/codespaces/secrets/*",
			Reason: "Deleting Codespaces secrets."},
		// Webhooks (silent exfiltration channel if attacker adds their own).
		{ID: "create-repo-webhook", Kind: "api", Method: "POST", PathGlob: "/repos/*/*/hooks",
			Reason: "Adding a repo webhook would let an attacker exfiltrate events."},
		{ID: "patch-repo-webhook", Kind: "api", Method: "PATCH", PathGlob: "/repos/*/*/hooks/*",
			Reason: "Modifying a repo webhook."},
		{ID: "delete-repo-webhook", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/hooks/*",
			Reason: "Deleting a repo webhook could break recovery automation."},
		{ID: "create-org-webhook", Kind: "api", Method: "POST", PathGlob: "/orgs/*/hooks",
			Reason: "Adding an org webhook (exfiltration channel)."},
		{ID: "patch-org-webhook", Kind: "api", Method: "PATCH", PathGlob: "/orgs/*/hooks/*",
			Reason: "Modifying an org webhook."},
		{ID: "delete-org-webhook", Kind: "api", Method: "DELETE", PathGlob: "/orgs/*/hooks/*",
			Reason: "Deleting an org webhook."},
		// Keys (persistence — these survive even after VM destruction).
		{ID: "create-deploy-key", Kind: "api", Method: "POST", PathGlob: "/repos/*/*/keys",
			Reason: "Adding a deploy key grants persistent repo access from anywhere."},
		{ID: "delete-deploy-key", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/keys/*",
			Reason: "Removing a deploy key (breaks CI)."},
		{ID: "add-user-ssh-key", Kind: "api", Method: "POST", PathGlob: "/user/keys",
			Reason: "Adding an SSH key to YOUR user account = persistent attacker access."},
		{ID: "delete-user-ssh-key", Kind: "api", Method: "DELETE", PathGlob: "/user/keys/*",
			Reason: "Deleting your SSH keys would lock you out."},
		{ID: "add-user-gpg-key", Kind: "api", Method: "POST", PathGlob: "/user/gpg_keys",
			Reason: "Adding a GPG key lets the attacker sign commits that appear verified."},
		{ID: "delete-user-gpg-key", Kind: "api", Method: "DELETE", PathGlob: "/user/gpg_keys/*",
			Reason: "Deleting your GPG keys."},
		// Identity / org settings.
		{ID: "modify-user", Kind: "api", Method: "PATCH", PathGlob: "/user",
			Reason: "Changing your user profile (email, bio, etc.)."},
		{ID: "modify-org-settings", Kind: "api", Method: "PATCH", PathGlob: "/orgs/*",
			Reason: "Changing org settings (visibility, defaults, etc.)."},
		{ID: "set-membership-role", Kind: "api", Method: "PUT", PathGlob: "/orgs/*/memberships/*",
			Reason: "Changing an org member's role (privilege escalation)."},
		{ID: "remove-membership", Kind: "api", Method: "DELETE", PathGlob: "/orgs/*/memberships/*",
			Reason: "Removing an org member."},
		// Coverage / cleanup.
		{ID: "delete-release", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/releases/*",
			Reason: "Deleting releases (loses artifacts)."},
		{ID: "delete-actions-run", Kind: "api", Method: "DELETE", PathGlob: "/repos/*/*/actions/runs/*",
			Reason: "Deleting Actions runs (covers tracks)."},
		{ID: "change-actions-permissions", Kind: "api", Method: "PUT", PathGlob: "/repos/*/*/actions/permissions",
			Reason: "Changing Actions permissions (enabling unsafe runners)."},
		// Git smart-HTTP: ref deletions on the main lines.
		{ID: "git-delete-main", Kind: "git-delete-ref", RefGlob: "refs/heads/main",
			Reason: "Cannot delete main branch via git push."},
		{ID: "git-delete-master", Kind: "git-delete-ref", RefGlob: "refs/heads/master",
			Reason: "Cannot delete master branch via git push."},
	}
}

// policyPath returns the on-disk policy file for a profile.
func policyPath(profile string) string {
	return filepath.Join(colimaProfileDir(profile), "policy.json")
}

func loadPolicy(profile string) (*Policy, error) {
	data, err := os.ReadFile(policyPath(profile))
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid policy at %s: %w", policyPath(profile), err)
	}
	if p.Version == 0 {
		p.Version = policyVersion
	}
	return &p, nil
}

func savePolicy(profile string, p *Policy) error {
	if err := os.MkdirAll(colimaProfileDir(profile), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(policyPath(profile), data, 0o644)
}

// checkAPI returns (allowed, reason). Owner is checked first; then deny rules.
// An empty owner (e.g. paths under /user) skips the owner check.
func (p *Policy) checkAPI(method, path string) (bool, string) {
	if owner := extractAPIOwner(path); owner != "" {
		if !containsFold(p.AllowedOwners, owner) {
			return false, fmt.Sprintf("owner %q not in allowed_owners %v", owner, p.AllowedOwners)
		}
	}
	for _, r := range p.DenyRules {
		if r.Kind != "api" {
			continue
		}
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		if r.PathGlob != "" && !matchGlob(r.PathGlob, path) {
			continue
		}
		return false, fmt.Sprintf("%s: %s", r.ID, r.Reason)
	}
	return true, ""
}

// checkGitDelete returns (allowed, reason) for a single ref-deletion attempt
// observed in a git-receive-pack body.
func (p *Policy) checkGitDelete(ref string) (bool, string) {
	for _, r := range p.DenyRules {
		if r.Kind != "git-delete-ref" {
			continue
		}
		if r.RefGlob == "" || matchGlob(r.RefGlob, ref) {
			return false, fmt.Sprintf("%s: cannot delete %s", r.ID, ref)
		}
	}
	return true, ""
}

// checkGitOwner verifies the git URL owner is in allowed_owners.
func (p *Policy) checkGitOwner(owner string) (bool, string) {
	if !containsFold(p.AllowedOwners, owner) {
		return false, fmt.Sprintf("owner %q not in allowed_owners %v", owner, p.AllowedOwners)
	}
	return true, ""
}

// extractAPIOwner returns the {owner|org|user} segment from a GitHub API path,
// or "" if the path doesn't carry one (e.g. /user/..., /rate_limit, /).
func extractAPIOwner(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 2 {
		switch parts[0] {
		case "repos", "users", "orgs":
			return parts[1]
		}
	}
	return ""
}

func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// matchGlob is a slash-aware glob with `*` matching one segment chunk
// (non-/), `?` matching one char, and `**` matching zero-or-more segments.
// Examples that match:
//
//	/repos/*/*           → /repos/foo/bar
//	/repos/*/*/git/refs/heads/main → /repos/foo/bar/git/refs/heads/main
//	/repos/*/*/git/refs/**          → /repos/foo/bar/git/refs/heads/main
func matchGlob(pattern, path string) bool {
	patParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")
	return matchGlobSegments(patParts, pathParts)
}

func matchGlobSegments(pat, p []string) bool {
	for i := 0; i < len(pat); i++ {
		if pat[i] == "**" {
			rest := pat[i+1:]
			for j := 0; j <= len(p); j++ {
				if matchGlobSegments(rest, p[j:]) {
					return true
				}
			}
			return false
		}
		if i >= len(p) {
			return false
		}
		if !matchSingleSegment(pat[i], p[i]) {
			return false
		}
		_ = i // keep linter quiet
		// advance via loop, but len(p) check above used len, so trim p in tail:
		// we walk both by index together — finish loop with same offset.
	}
	return len(pat) == len(p)
}

func matchSingleSegment(pat, seg string) bool {
	if pat == "*" {
		return true
	}
	if !strings.ContainsAny(pat, "*?") {
		return pat == seg
	}
	// Fallback: simple in-segment glob via filepath.Match-style without separator.
	// We hand-roll because we want star to not match `/`, and `?` to match one char.
	pi, si := 0, 0
	star := -1
	starSi := 0
	for si < len(seg) {
		if pi < len(pat) {
			switch pat[pi] {
			case '*':
				star = pi
				starSi = si
				pi++
				continue
			case '?':
				pi++
				si++
				continue
			default:
				if pat[pi] == seg[si] {
					pi++
					si++
					continue
				}
			}
		}
		if star >= 0 {
			pi = star + 1
			starSi++
			si = starSi
			continue
		}
		return false
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}

// loadPolicyOrError surfaces a friendly error if no policy file exists yet.
var errNoPolicy = errors.New("no policy")

func loadPolicyForProfile(profile string) (*Policy, error) {
	p, err := loadPolicy(profile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNoPolicy
	}
	return p, err
}
