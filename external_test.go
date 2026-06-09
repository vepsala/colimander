package main

import "testing"

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
		"/v1/apps/kotisivukamu":               "kotisivukamu",
		"/v1/apps/kotisivukamu/logs":          "kotisivukamu",
		"/v1/apps/kotisivukamu/machines/x":    "kotisivukamu",
		"/v1/organizations":                   "",
		"/v1/regions":                         "",
		"/":                                   "",
		"/v1":                                 "",
		"/v1/apps":                            "",
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
		"/v3/configs":                  true,
		"/v3/configs/config":           true,
		"/v3/configs/config/secrets":   true,
		"/v3/workplaces":               false,
		"/":                            false,
	}
	for path, want := range cases {
		got := requiresDopplerProject(path)
		if got != want {
			t.Errorf("requiresDopplerProject(%q) = %v, want %v", path, got, want)
		}
	}
}
