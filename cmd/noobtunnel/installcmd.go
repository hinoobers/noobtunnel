package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/tlsutil"
)

// runInstall prints an install command for a token, optionally fetching the
// control node certificate to pin it.
func runInstall(args []string) error {
	fs := newFlagSet("install")
	var (
		serverAddr  = fs.String("server", env("NOOBTUNNEL_SERVER", ""), "control node address, host:port")
		token       = fs.String("token", env("NOOBTUNNEL_TOKEN", ""), "enrollment token")
		name        = fs.String("name", "", "agent name")
		advertise   = fs.String("advertise", "", "comma separated CIDRs to advertise")
		fingerprint = fs.String("fingerprint", "", "certificate fingerprint (fetched from the server when omitted)")
		noFetch     = fs.Bool("no-fetch", false, "do not contact the control node for its certificate")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	if *token == "" {
		return fmt.Errorf("--token is required")
	}
	if !strings.Contains(*serverAddr, ":") {
		*serverAddr = *serverAddr + ":8443"
	}
	pin := ""
	fp := *fingerprint
	if !*noFetch {
		fetched, pinValue, err := fetchCertificate(*serverAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not fetch the certificate (%v), the command will not pin it\n", err)
		} else {
			pin = pinValue
			if fp == "" {
				fp = fetched
			}
		}
	}

	var b strings.Builder
	b.WriteString("curl -fsSLk --retry 3")
	if pin != "" {
		b.WriteString(" --pinnedpubkey " + quote("sha256//"+pin))
	}
	b.WriteString(" https://" + *serverAddr + "/install.sh")
	b.WriteString(" | sudo sh -s --")
	b.WriteString(" --server " + quote(*serverAddr))
	b.WriteString(" --token " + quote(*token))
	if fp != "" {
		b.WriteString(" --fingerprint " + quote(fp))
	}
	if *name != "" {
		b.WriteString(" --name " + quote(*name))
	}
	if *advertise != "" {
		b.WriteString(" --advertise " + quote(strings.ReplaceAll(*advertise, " ", "")))
	}
	fmt.Println(b.String())
	return nil
}

// fetchCertificate downloads /cert.pem and derives both the fingerprint and the
// curl public key pin.
func fetchCertificate(serverAddr string) (fingerprint string, pin string, err error) {
	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	response, err := client.Get("https://" + serverAddr + "/cert.pem")
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("control node answered %s", response.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", "", fmt.Errorf("control node did not return a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	return tlsutil.Fingerprint(block.Bytes), tlsutil.Pin(cert), nil
}

func quote(value string) string {
	safe := value != ""
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '/', r == ':', r == ',', r == '@':
		default:
			safe = false
		}
	}
	if safe {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
