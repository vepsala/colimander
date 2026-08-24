// External-service brokers: fly.io and doppler.
//
// Same shape as the GitHub broker (HTTP proxy with policy enforcement +
// upstream token injection), but with two key differences:
//
//  1. *Allowlist*, not denylist. The GitHub policy is "allow everything except
//     these specific destructive operations". For Fly and Doppler the agent
//     should only ever hit a tiny, enumerated set of endpoints (log streams,
//     machine status; secret-add) — so we flip the default to deny and
//     require an explicit AllowedEndpoints rule. Less surface, less to keep
//     up-to-date as the upstream API grows.
//
//  2. *Bearer-token* identity instead of Basic. flyctl and the Doppler CLI
//     only respect their respective single-string env vars (FLY_API_TOKEN,
//     DOPPLER_TOKEN), which both get sent as `Authorization: Bearer <value>`.
//     We pack the profile identity as `<profile>:<handle>` in that field and
//     unpack it broker-side. (Yes, this is technically not a Bearer token in
//     the RFC sense; flyctl and Doppler don't care what's after Bearer, they
//     forward verbatim.)
//
// Upstream tokens live in ~/.colimander/tokens.json (0600) — see tokens.go.
// Treat that file like ~/.aws/credentials: per-machine, never in git.

package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	flyAPIBase     = "https://api.fly.io"
	dopplerAPIBase = "https://api.doppler.com"
)

// defaultFlyEndpoints — a conservative starter allowlist suitable for
// "agent can read app state and tail logs, nothing else". Extend by editing
// policy.json. The fly.io REST API base is https://api.fly.io/v1/...
func defaultFlyEndpoints() []EndpointRule {
	return []EndpointRule{
		{Method: "GET", PathGlob: "/v1/apps/*", Description: "App metadata"},
		{Method: "GET", PathGlob: "/v1/apps/*/machines", Description: "List machines"},
		{Method: "GET", PathGlob: "/v1/apps/*/machines/*", Description: "Machine state"},
		{Method: "GET", PathGlob: "/v1/apps/*/machines/*/events", Description: "Machine event history"},
		{Method: "GET", PathGlob: "/v1/apps/*/logs", Description: "App log stream"},
		{Method: "GET", PathGlob: "/v1/apps/*/releases", Description: "Release history (read-only)"},
	}
}

// defaultDopplerEndpoints — the "agent can add a secret, never read or
// delete one" shape. POST creates; GET to /v3/configs is metadata only
// (no secret values). DELETE / PATCH on secrets are deliberately absent.
func defaultDopplerEndpoints() []EndpointRule {
	return []EndpointRule{
		{Method: "POST", PathGlob: "/v3/configs/config/secrets", Description: "Create a new secret value (project-scoped)"},
		{Method: "GET", PathGlob: "/v3/configs", Description: "List configs (metadata only, no secret values)"},
		{Method: "GET", PathGlob: "/v3/configs/config", Description: "Get a single config's metadata"},
	}
}

// authProfileFromBearer reads `Authorization: Bearer <profile>:<handle>` and
// returns the profile name and its policy. Mirrors authProfile() in broker.go
// but for the Bearer-token shape required by fly/doppler CLIs.
func (b *broker) authProfileFromBearer(r *http.Request) (string, *Policy, error) {
	if b.devLoop {
		if pol, err := loadPolicyForProfile(b.devProfile); err == nil {
			return b.devProfile, pol, nil
		}
	}
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", nil, errors.New("missing Bearer authorization (broker expects `<profile>:<handle>` after Bearer)")
	}
	raw := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	colon := strings.Index(raw, ":")
	if colon < 0 {
		return "", nil, errors.New("bearer token must be `<profile>:<handle>`")
	}
	profile := raw[:colon]
	handle := raw[colon+1:]
	if profile == "" {
		return "", nil, errors.New("bearer token has empty profile")
	}
	pol, err := loadPolicyForProfile(profile)
	if err != nil {
		return profile, nil, fmt.Errorf("unknown profile %q (%v)", profile, err)
	}
	if pol.Handle == "" {
		return profile, nil, fmt.Errorf("profile %q has no handle; run `colimander broker rewire %s`", profile, profile)
	}
	if subtle.ConstantTimeCompare([]byte(pol.Handle), []byte(handle)) != 1 {
		return profile, nil, errors.New("handle mismatch")
	}
	return profile, pol, nil
}

// matchAllowedEndpoint returns true iff at least one rule matches the
// (method, path) pair. Default is deny.
func matchAllowedEndpoint(rules []EndpointRule, method, path string) bool {
	for _, r := range rules {
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		if r.PathGlob != "" && !matchGlob(r.PathGlob, path) {
			continue
		}
		return true
	}
	return false
}

// extractFlyApp pulls "<app>" from /v1/apps/<app>/... paths, or "" if the
// path doesn't carry an app segment (e.g. /v1/organizations, /v1/regions).
func extractFlyApp(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "v1" && parts[1] == "apps" {
		return parts[2]
	}
	return ""
}

// ----------------------------- fly.io ---------------------------------------

func (b *broker) handleFly(w http.ResponseWriter, r *http.Request) {
	profile, policy, err := b.authProfileFromBearer(r)
	if err != nil {
		b.audit(auditEntry{Profile: authFailProfile(profile), Surface: "FLY", Method: r.Method, Path: r.URL.Path, Action: "AUTH", Detail: err.Error()})
		b.errorResponse(w, http.StatusForbidden, "broker: "+err.Error())
		return
	}
	upstreamPath := strings.TrimPrefix(r.URL.Path, "/fly")
	if upstreamPath == "" {
		upstreamPath = "/"
	}

	if policy.FlyPolicy == nil {
		b.audit(auditEntry{Profile: profile, Surface: "FLY", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: "no fly_policy configured"})
		b.denyResponse(w, "no fly_policy configured for this profile")
		return
	}
	if !matchAllowedEndpoint(policy.FlyPolicy.AllowedEndpoints, r.Method, upstreamPath) {
		b.audit(auditEntry{Profile: profile, Surface: "FLY", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: "no allowed_endpoints match"})
		b.denyResponse(w, fmt.Sprintf("no fly_policy.allowed_endpoints rule matches %s %s", r.Method, upstreamPath))
		return
	}
	if app := extractFlyApp(upstreamPath); app != "" {
		if !containsFold(policy.FlyPolicy.AllowedApps, app) {
			b.audit(auditEntry{Profile: profile, Surface: "FLY", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: fmt.Sprintf("app %q not in allowed_apps", app)})
			b.denyResponse(w, fmt.Sprintf("fly app %q not in allowed_apps %v", app, policy.FlyPolicy.AllowedApps))
			return
		}
	}

	pt, _ := getProfileTokens(profile)
	if pt.Fly == "" {
		b.errorResponse(w, http.StatusBadGateway,
			fmt.Sprintf("no fly upstream token configured for %q. Set with: colimander tokens set %s fly <fly-token>", profile, profile))
		return
	}

	b.proxyTo(w, r, flyAPIBase, upstreamPath, pt.Fly, "FLY", profile)
}

// ----------------------------- doppler --------------------------------------

func (b *broker) handleDoppler(w http.ResponseWriter, r *http.Request) {
	profile, policy, err := b.authProfileFromBearer(r)
	if err != nil {
		b.audit(auditEntry{Profile: authFailProfile(profile), Surface: "DOPPLER", Method: r.Method, Path: r.URL.Path, Action: "AUTH", Detail: err.Error()})
		b.errorResponse(w, http.StatusForbidden, "broker: "+err.Error())
		return
	}
	upstreamPath := strings.TrimPrefix(r.URL.Path, "/doppler")
	if upstreamPath == "" {
		upstreamPath = "/"
	}

	if policy.DopplerPolicy == nil {
		b.audit(auditEntry{Profile: profile, Surface: "DOPPLER", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: "no doppler_policy configured"})
		b.denyResponse(w, "no doppler_policy configured for this profile")
		return
	}
	if !matchAllowedEndpoint(policy.DopplerPolicy.AllowedEndpoints, r.Method, upstreamPath) {
		b.audit(auditEntry{Profile: profile, Surface: "DOPPLER", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: "no allowed_endpoints match"})
		b.denyResponse(w, fmt.Sprintf("no doppler_policy.allowed_endpoints rule matches %s %s", r.Method, upstreamPath))
		return
	}
	// Doppler's project is carried as a query parameter on most endpoints.
	// When present we validate it; when absent on an endpoint that ought to
	// have one, we refuse — leaking a request without project scoping would
	// let the agent hit "the default project", which may not be allowlisted.
	if project := r.URL.Query().Get("project"); project != "" {
		if !containsFold(policy.DopplerPolicy.AllowedProjects, project) {
			b.audit(auditEntry{Profile: profile, Surface: "DOPPLER", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: fmt.Sprintf("project %q not in allowed_projects", project)})
			b.denyResponse(w, fmt.Sprintf("doppler project %q not in allowed_projects %v", project, policy.DopplerPolicy.AllowedProjects))
			return
		}
	} else if requiresDopplerProject(upstreamPath) {
		b.audit(auditEntry{Profile: profile, Surface: "DOPPLER", Method: r.Method, Path: upstreamPath, Action: "DENY", Detail: "missing project query param"})
		b.denyResponse(w, "endpoint requires `project` query parameter to be set, and matched against allowed_projects")
		return
	}

	pt, _ := getProfileTokens(profile)
	if pt.Doppler == "" {
		b.errorResponse(w, http.StatusBadGateway,
			fmt.Sprintf("no doppler upstream token configured for %q. Set with: colimander tokens set %s doppler <doppler-token>", profile, profile))
		return
	}

	b.proxyTo(w, r, dopplerAPIBase, upstreamPath, pt.Doppler, "DOPPLER", profile)
}

// requiresDopplerProject returns true for endpoints that operate on
// project-scoped resources. The current rule of thumb: anything under
// /v3/configs (configs + the secrets they hold) needs a project query param.
func requiresDopplerProject(path string) bool {
	return strings.HasPrefix(path, "/v3/configs")
}

// ----------------------------- proxy helper ---------------------------------

// proxyTo runs an httputil.ReverseProxy to the given upstream base with a
// path override and an injected Bearer token. FlushInterval=-1 makes the
// proxy flush each chunk, which is required for streaming endpoints (fly
// logs in particular send chunked HTTP).
func (b *broker) proxyTo(w http.ResponseWriter, r *http.Request, base, upstreamPath, upstreamToken, surface, profile string) {
	target, err := url.Parse(base)
	if err != nil {
		b.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = upstreamPath
			req.URL.RawQuery = r.URL.RawQuery
			req.Host = target.Host
			req.Header.Del("Authorization")
			req.Header.Set("Authorization", "Bearer "+upstreamToken)
			req.Header.Set("User-Agent", "colimander-broker/"+version)
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			b.errorResponse(w, http.StatusBadGateway, "upstream: "+err.Error())
		},
	}
	proxy.ServeHTTP(w, r)
	b.audit(auditEntry{Profile: profile, Surface: surface, Method: r.Method, Path: upstreamPath, Action: "ALLOW", Detail: "proxied"})
}
