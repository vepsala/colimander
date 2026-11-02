package broker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchAllowedEndpoint(t *testing.T) {
	rules := []EndpointRule{
		{Method: "GET", PathGlob: "/v1/apps/*/logs"},
		{Method: "GET", PathGlob: "/v1/apps/*"},
		{Method: "POST", PathGlob: "/v3/configs/config/secrets"},
	}
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/v1/apps/foo/logs", true},
		{"GET", "/v1/apps/foo", true},
		// Single * doesn't cross /, so the metadata rule shouldn't match a deeper path.
		{"GET", "/v1/apps/foo/machines", false},
		{"DELETE", "/v1/apps/foo", false}, // wrong method
		{"POST", "/v3/configs/config/secrets", true},
		{"GET", "/v3/configs/config/secrets", false},
		{"POST", "/v3/configs/config", false},
		// Empty rule list = default deny.
		{"GET", "/", false},
	}
	for _, c := range cases {
		got := matchAllowedEndpoint(rules, c.method, c.path)
		if got != c.want {
			t.Errorf("matchAllowedEndpoint(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
	// Sanity: empty rule list denies everything.
	if matchAllowedEndpoint(nil, "GET", "/v1/apps/foo") {
		t.Error("empty rule list should deny by default")
	}
}

func TestExtractFlyApp(t *testing.T) {
	cases := map[string]string{
		"/v1/apps/kotisivukamu":            "kotisivukamu",
		"/v1/apps/kotisivukamu/logs":       "kotisivukamu",
		"/v1/apps/kotisivukamu/machines/x": "kotisivukamu",
		"/v1/organizations":                "",
		"/v1/regions":                      "",
		"/":                                "",
		"/v1":                              "",
		"/v1/apps":                         "",
	}
	for path, want := range cases {
		got := extractFlyApp(path)
		if got != want {
			t.Errorf("extractFlyApp(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestRequiresDopplerProject(t *testing.T) {
	cases := map[string]bool{
		"/v3/configs":                true,
		"/v3/configs/config":         true,
		"/v3/configs/config/secrets": true,
		"/v3/workplaces":             false,
		"/":                          false,
	}
	for path, want := range cases {
		got := requiresDopplerProject(path)
		if got != want {
			t.Errorf("requiresDopplerProject(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestFlyPolicyAllowsApp(t *testing.T) {
	listed := &FlyPolicy{AllowedApps: []string{"kotisivukamu"}}
	if !listed.allowsApp("Kotisivukamu") || listed.allowsApp("other") {
		t.Error("listed apps: want only kotisivukamu allowed (case-insensitive)")
	}
	wild := &FlyPolicy{AllowedApps: []string{"*"}}
	if !wild.allowsApp("anything") {
		t.Error(`"*" should allow any app`)
	}
	empty := &FlyPolicy{}
	if empty.allowsApp("anything") {
		t.Error("empty allowed_apps must deny, not allow all")
	}
}

func TestLegacyTokensImportOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".colimander")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"version":1,"profiles":{"a":{"fly":"old-fly"}}}`
	if err := os.WriteFile(filepath.Join(dir, "tokens.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := getProfileTokens("a")
	if err != nil || got.Fly != "old-fly" {
		t.Fatalf("import: %+v, %v", got, err)
	}
	if err := clearProfileTokens("a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := getProfileTokens("a"); got.Fly != "" {
		t.Errorf("cleared tokens came back from the old file: %+v", got)
	}
}
