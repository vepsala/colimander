// Package certs builds the TLS configuration the proxy presents to PostgreSQL
// clients: publicly-trusted certificates via ACME (Let's Encrypt, Caddy-style),
// a persisted self-signed certificate, or a cert/key pair from disk.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/kotisivukamu/pg-agent-proxy/internal/config"
)

// pgALPN is the ALPN protocol identifier PostgreSQL clients (libpq 17+) offer.
const pgALPN = "postgresql"

// Provider supplies the TLS configuration used by both the Postgres proxy and
// the admin HTTPS listener (which also answers ACME TLS-ALPN-01 challenges).
type Provider struct {
	tlsConfig *tls.Config
}

func (p *Provider) base() *tls.Config {
	if p == nil {
		return nil
	}
	return p.tlsConfig
}

// AdminTLSConfig is the config for the admin HTTPS listener (and ACME
// TLS-ALPN-01 challenges). Returns nil when TLS is disabled.
func (p *Provider) AdminTLSConfig() *tls.Config {
	return p.base()
}

// ProxyTLSConfig is the config for the PostgreSQL proxy port. It negotiates the
// "postgresql" ALPN protocol that modern libpq requires. Returns nil when TLS
// is disabled.
func (p *Provider) ProxyTLSConfig() *tls.Config {
	b := p.base()
	if b == nil {
		return nil
	}
	c := b.Clone()
	c.NextProtos = []string{pgALPN}
	return c
}

// New builds a Provider from the TLS configuration. It returns nil (no error)
// when TLS is disabled.
func New(cfg config.TLSConfig, log *slog.Logger) (*Provider, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	switch cfg.Mode {
	case "acme":
		return newACME(cfg, log)
	case "self_signed":
		return newSelfSigned(cfg)
	case "file":
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls cert/key: %w", err)
		}
		return &Provider{tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}, nil
	default:
		return nil, fmt.Errorf("unknown tls mode %q", cfg.Mode)
	}
}

func cacheDir(cfg config.TLSConfig) string {
	if cfg.CacheDir != "" {
		return cfg.CacheDir
	}
	return "certs"
}

func newACME(cfg config.TLSConfig, log *slog.Logger) (*Provider, error) {
	dir := cacheDir(cfg)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create acme cache dir: %w", err)
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(dir),
		HostPolicy: autocert.HostWhitelist(cfg.Hosts...),
		Email:      cfg.ACMEEmail,
	}

	// A self-signed fallback covers connections that arrive before a trusted
	// cert is issued or without SNI (e.g. health probes), so they still get an
	// encrypted channel instead of a handshake failure.
	fallback, err := generateSelfSigned(cfg.Hosts)
	if err != nil {
		return nil, err
	}

	base := m.TLSConfig() // sets GetCertificate and the acme-tls/1 NextProto
	managed := base.GetCertificate
	base.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if isACMEChallenge(hello) {
			return managed(hello) // never fall back during a challenge
		}
		if hello.ServerName == "" {
			return &fallback, nil
		}
		cert, err := managed(hello)
		if err != nil {
			log.Warn("ACME certificate unavailable; serving self-signed fallback", "host", hello.ServerName, "err", err)
			return &fallback, nil
		}
		return cert, nil
	}
	log.Info("TLS: ACME enabled", "hosts", cfg.Hosts, "cache", dir)
	return &Provider{tlsConfig: base}, nil
}

func isACMEChallenge(hello *tls.ClientHelloInfo) bool {
	for _, p := range hello.SupportedProtos {
		if p == acme.ALPNProto {
			return true
		}
	}
	return false
}

func newSelfSigned(cfg config.TLSConfig) (*Provider, error) {
	certFile := cfg.CertFile
	keyFile := cfg.KeyFile
	if certFile == "" || keyFile == "" {
		dir := cacheDir(cfg)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		certFile = filepath.Join(dir, "self-signed.crt")
		keyFile = filepath.Join(dir, "self-signed.key")
	}

	if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		return &Provider{tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}, nil
	}

	certPEM, keyPEM, err := selfSignedPEM(cfg.Hosts)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &Provider{tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}, nil
}

func generateSelfSigned(hosts []string) (tls.Certificate, error) {
	certPEM, keyPEM, err := selfSignedPEM(hosts)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func selfSignedPEM(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "pg-agent-proxy"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string{"localhost"}, hosts...),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
