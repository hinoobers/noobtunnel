package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedCert makes a certificate for tests.
func selfSignedCert(name string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// TestPeekClientHelloReadsSNI feeds a real ClientHello through the peeker: the
// bytes are produced by crypto/tls, so the parser is tested against genuine
// handshake data rather than a hand written fixture.
func TestPeekClientHelloReadsSNI(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		cfg := &tls.Config{ServerName: "home.example.com", InsecureSkipVerify: true}
		conn := tls.Client(clientConn, cfg)
		// The handshake cannot complete over a pipe, so an error here is fine:
		// all we need is the ClientHello on the wire.
		_ = conn.Handshake()
	}()

	hello, err := peekClientHello(serverConn)
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if hello.ServerName != "home.example.com" {
		t.Fatalf("ServerName = %q, want home.example.com", hello.ServerName)
	}
	if len(hello.Raw) < 50 {
		t.Fatalf("raw handshake is only %d bytes, it must be replayable", len(hello.Raw))
	}
	if hello.Raw[0] != 0x16 {
		t.Fatalf("raw handshake should start with a TLS handshake record, got 0x%02x", hello.Raw[0])
	}
	// Unblock the handshake goroutine; it can never complete over a bare pipe.
	_ = clientConn.Close()
}

func TestPeekClientHelloRejectsNonTLS(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go func() {
		_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()
	if _, err := peekClientHello(serverConn); err != ErrNotTLS {
		t.Fatalf("expected ErrNotTLS, got %v", err)
	}
}

func TestParseServerNameRejectsGarbage(t *testing.T) {
	for _, payload := range [][]byte{
		nil,
		{0x01},
		{0x02, 0x00, 0x00, 0x10}, // not a ClientHello
		append([]byte{0x01, 0x00, 0x00, 0x04}, 0, 0), // truncated body
	} {
		if _, err := parseServerName(payload); err == nil {
			t.Fatalf("parseServerName(%v) should fail", payload)
		}
	}
}
