// Package tlsutil creates and pins the control node's TLS identity.
//
// A control node needs no domain name and no certificate authority: it
// generates a self-signed certificate on first start and every agent pins it by
// fingerprint. The same fingerprint is embedded in the install command so a
// freshly installed agent cannot be tricked into talking to an impostor.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cert bundles the loaded certificate with the raw DER used for pinning.
type Cert struct {
	Certificate tls.Certificate
	Leaf        *x509.Certificate
	DER         []byte
	// Fingerprint is the SHA-256 of the DER, formatted as colon separated hex.
	Fingerprint string
	// Pin is the curl --pinnedpubkey value for this certificate.
	Pin string
}

// LoadOrCreate loads cert.pem/key.pem from dir, generating a self-signed pair
// for hosts when they are missing.
func LoadOrCreate(dir string, hosts []string) (*Cert, error) {
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if fileExists(certPath) && fileExists(keyPath) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("tlsutil: load certificate: %w", err)
		}
		return finish(&cert)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPEM, keyPEM, err := generate(hosts)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return finish(&cert)
}

func finish(cert *tls.Certificate) (*Cert, error) {
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("tlsutil: certificate chain is empty")
	}
	der := cert.Certificate[0]
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	return &Cert{
		Certificate: *cert,
		Leaf:        leaf,
		DER:         der,
		Fingerprint: Fingerprint(der),
		Pin:         Pin(leaf),
	}, nil
}

// Fingerprint returns the colon separated SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	hexed := hex.EncodeToString(sum[:])
	var b strings.Builder
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexed[i : i+2])
	}
	return b.String()
}

// Pin returns the base64 SHA-256 of the certificate's public key, which is the
// value curl expects for --pinnedpubkey.
func Pin(leaf *x509.Certificate) string {
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(spki)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func generate(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"noobtunnel"}, CommonName: "noobtunnel control node"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	hosts = append([]string{"localhost", "127.0.0.1", "::1"}, hosts...)
	for _, hostName := range hosts {
		hostName = strings.TrimSpace(hostName)
		if hostName == "" {
			continue
		}
		if ip := net.ParseIP(strings.Trim(hostName, "[]")); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		if host, _, err := net.SplitHostPort(hostName); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
				continue
			}
			tmpl.DNSNames = append(tmpl.DNSNames, host)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, hostName)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
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

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// LocalHosts returns the machine's IP addresses, used as certificate SANs so
// agents can connect to any address the control node is reachable on.
func LocalHosts() []string {
	var hosts []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return hosts
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			hosts = append(hosts, ipNet.IP.String())
		}
	}
	return hosts
}
