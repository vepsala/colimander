// Package config loads and validates the proxy-wide configuration file.
//
// Per-connection settings (upstream URL, credentials, PII and gating rules)
// live in the SQLite registry, not here. This file holds only process-wide
// settings shared by every connection.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the proxy-wide configuration.
type Config struct {
	// Listen is the address the PostgreSQL proxy accepts client connections on.
	Listen string `yaml:"listen"`

	// AdminListen is the address the management web UI / API listens on. Keep
	// it bound to localhost or behind your own auth — it is unauthenticated.
	AdminListen string `yaml:"admin_listen"`

	// Database is the path to the SQLite registry file.
	Database string `yaml:"database"`

	// HashSalt is mixed into every PII hash. Set a stable, secret value.
	HashSalt string `yaml:"hash_salt"`

	// RedactString replaces values for columns with action "redact".
	RedactString string `yaml:"redact_string"`

	// SchemaFunction is the pseudo-function clients call to fetch the live,
	// PII-annotated schema, e.g. "SELECT pgproxy_schema();".
	SchemaFunction string `yaml:"schema_function"`

	// Approval configures how gated statements are approved (process-wide).
	Approval ApprovalConfig `yaml:"approval"`
}

// ApprovalConfig configures the approval mechanism.
type ApprovalConfig struct {
	// Mode is "http", "auto_approve" or "auto_deny".
	Mode string `yaml:"mode"`
	// URL receives approval requests when Mode is "http".
	URL string `yaml:"url"`
	// Timeout bounds how long the proxy waits for a decision; a timeout fails
	// closed (deny). Defaults to 2m.
	Timeout time.Duration `yaml:"timeout"`
}

// Load builds the configuration from the YAML file at path (if it exists) with
// PGPROXY_* environment variables taking precedence, then defaults. A missing
// file is not an error: the proxy can be configured entirely from the
// environment, which is convenient for container deployments.
func Load(path string) (*Config, error) {
	var cfg Config

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	case os.IsNotExist(err):
		// No file — rely on environment variables and defaults.
	default:
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := cfg.applyEnv(); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyEnv overlays PGPROXY_* environment variables onto the config. An unset or
// empty variable leaves the existing value untouched.
func (c *Config) applyEnv() error {
	setString(&c.Listen, "PGPROXY_LISTEN")
	setString(&c.AdminListen, "PGPROXY_ADMIN_LISTEN")
	setString(&c.Database, "PGPROXY_DATABASE")
	setString(&c.HashSalt, "PGPROXY_HASH_SALT")
	setString(&c.RedactString, "PGPROXY_REDACT_STRING")
	setString(&c.SchemaFunction, "PGPROXY_SCHEMA_FUNCTION")
	setString(&c.Approval.Mode, "PGPROXY_APPROVAL_MODE")
	setString(&c.Approval.URL, "PGPROXY_APPROVAL_URL")
	if v := os.Getenv("PGPROXY_APPROVAL_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("config: PGPROXY_APPROVAL_TIMEOUT: %w", err)
		}
		c.Approval.Timeout = d
	}
	return nil
}

func setString(dst *string, env string) {
	if v := os.Getenv(env); v != "" {
		*dst = v
	}
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:6432"
	}
	if c.AdminListen == "" {
		c.AdminListen = "127.0.0.1:6480"
	}
	if c.Database == "" {
		c.Database = "pgproxy.db"
	}
	if c.SchemaFunction == "" {
		c.SchemaFunction = "pgproxy_schema"
	}
	if c.RedactString == "" {
		c.RedactString = "[REDACTED]"
	}
	if c.Approval.Timeout == 0 {
		c.Approval.Timeout = 2 * time.Minute
	}
	if c.Approval.Mode == "" {
		if c.Approval.URL != "" {
			c.Approval.Mode = "http"
		} else {
			c.Approval.Mode = "auto_deny"
		}
	}
}

func (c *Config) validate() error {
	switch c.Approval.Mode {
	case "http":
		if c.Approval.URL == "" {
			return fmt.Errorf("config: approval.url is required when approval.mode is http")
		}
	case "auto_approve", "auto_deny", "dashboard":
	default:
		return fmt.Errorf("config: approval.mode must be one of http, dashboard, auto_approve, auto_deny (got %q)", c.Approval.Mode)
	}
	return nil
}
