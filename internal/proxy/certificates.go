package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// CertificateProvider hands out certificates for the domains the control node
// serves. The default implementation mints and caches a self-signed certificate
// per name, so HTTPS resources work immediately; an ACME provider can be plugged
// in to get publicly trusted certificates instead.
type CertificateProvider interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// SelfSignedProvider issues and caches one certificate per hostname.
type SelfSignedProvider struct {
	mu    sync.Mutex
	certs map[string]*tls.Certificate
	// Fallback is used when the client sends no server name.
	Fallback string
}

// NewSelfSignedProvider creates a provider that caches certificates in memory.
func NewSelfSignedProvider() *SelfSignedProvider {
	return &SelfSignedProvider{certs: map[string]*tls.Certificate{}}
}

// GetCertificate implements CertificateProvider.
func (p *SelfSignedProvider) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSpace(hello.ServerName))
	if name == "" {
		name = p.Fallback
	}
	if name == "" {
		return nil, fmt.Errorf("proxy: no server name in the TLS handshake")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if cert, ok := p.certs[name]; ok {
		return cert, nil
	}
	cert, err := selfSignedCertificate(name)
	if err != nil {
		return nil, err
	}
	p.certs[name] = cert
	return cert, nil
}

// selfSignedCertificate mints a certificate for one hostname.
func selfSignedCertificate(name string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, Organization: []string{"noobtunnel"}},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: template}, nil
}

// FallbackProvider tries the primary provider and falls back to self-signed
// certificates, so a certificate authority outage never takes a service down.
type FallbackProvider struct {
	Primary  CertificateProvider
	Fallback *SelfSignedProvider
	// OnError is called when the primary provider fails.
	OnError func(name string, err error)
}

// GetCertificate implements CertificateProvider.
func (p *FallbackProvider) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p.Primary != nil {
		cert, err := p.Primary.GetCertificate(hello)
		if err == nil && cert != nil {
			return cert, nil
		}
		if err != nil && p.OnError != nil {
			p.OnError(hello.ServerName, err)
		}
	}
	if p.Fallback == nil {
		p.Fallback = NewSelfSignedProvider()
	}
	return p.Fallback.GetCertificate(hello)
}
