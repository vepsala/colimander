package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(writeTemp(t, "hash_salt: abc\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:6432" {
		t.Errorf("default listen = %q", cfg.Listen)
	}
	if cfg.AdminListen != "127.0.0.1:6480" {
		t.Errorf("default admin_listen = %q", cfg.AdminListen)
	}
	if cfg.Database != "pgproxy.db" {
		t.Errorf("default database = %q", cfg.Database)
	}
	if cfg.SchemaFunction != "pgproxy_schema" {
		t.Errorf("default schema function = %q", cfg.SchemaFunction)
	}
	if cfg.RedactString != "[REDACTED]" {
		t.Errorf("default redact string = %q", cfg.RedactString)
	}
	if cfg.Approval.Mode != "auto_deny" {
		t.Errorf("default approval mode without url should be auto_deny, got %q", cfg.Approval.Mode)
	}
	if cfg.Approval.Timeout != 2*time.Minute {
		t.Errorf("default timeout = %v", cfg.Approval.Timeout)
	}
}

func TestApprovalModeDefaultsToHTTPWhenURLSet(t *testing.T) {
	cfg, err := Load(writeTemp(t, "approval:\n  url: http://localhost:9000/approve\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Approval.Mode != "http" {
		t.Errorf("mode = %q, want http", cfg.Approval.Mode)
	}
}

func TestLoadMissingFileUsesEnvAndDefaults(t *testing.T) {
	t.Setenv("PGPROXY_HASH_SALT", "fromenv")
	t.Setenv("PGPROXY_LISTEN", "0.0.0.0:7000")
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if cfg.HashSalt != "fromenv" {
		t.Errorf("hash_salt from env = %q", cfg.HashSalt)
	}
	if cfg.Listen != "0.0.0.0:7000" {
		t.Errorf("listen from env = %q", cfg.Listen)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	t.Setenv("PGPROXY_LISTEN", "0.0.0.0:9999")
	t.Setenv("PGPROXY_APPROVAL_TIMEOUT", "30s")
	cfg, err := Load(writeTemp(t, "listen: 127.0.0.1:6432\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "0.0.0.0:9999" {
		t.Errorf("env should override file listen, got %q", cfg.Listen)
	}
	if cfg.Approval.Timeout != 30*time.Second {
		t.Errorf("approval timeout from env = %v", cfg.Approval.Timeout)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := map[string]string{
		"bad approval mode":  "approval: {mode: maybe}",
		"http without url":   "approval: {mode: http}",
		"unknown field":      "nonsense: true",
		"acme without hosts": "tls: {mode: acme}",
		"file without paths": "tls: {mode: file}",
		"bad tls mode":       "tls: {mode: bogus}",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, body)); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}
