package proxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func tcpAddr(t *testing.T, raw string) net.Addr {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", raw)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestProxyHeaderV1(t *testing.T) {
	header := proxyHeaderV1(tcpAddr(t, "203.0.113.5:51234"), tcpAddr(t, "198.51.100.9:443"))
	want := "PROXY TCP4 203.0.113.5 198.51.100.9 51234 443\r\n"
	if string(header) != want {
		t.Fatalf("v1 header = %q, want %q", header, want)
	}
	if !bytes.HasSuffix(header, []byte("\r\n")) {
		t.Fatal("v1 headers must end with CRLF")
	}
}

func TestProxyHeaderV1IPv6(t *testing.T) {
	header := proxyHeaderV1(tcpAddr(t, "[2001:db8::1]:1234"), tcpAddr(t, "[2001:db8::2]:443"))
	if !strings.HasPrefix(string(header), "PROXY TCP6 2001:db8::1 2001:db8::2 ") {
		t.Fatalf("v6 header = %q", header)
	}
}

func TestProxyHeaderV1MixedFamiliesFallsBackToUnknown(t *testing.T) {
	header := proxyHeaderV1(tcpAddr(t, "[2001:db8::1]:1234"), tcpAddr(t, "198.51.100.9:443"))
	if string(header) != "PROXY UNKNOWN\r\n" {
		t.Fatalf("mixed families must degrade to UNKNOWN, got %q", header)
	}
}

func TestProxyHeaderV2IPv4Layout(t *testing.T) {
	header, err := proxyHeaderV2(tcpAddr(t, "203.0.113.5:51234"), tcpAddr(t, "198.51.100.9:443"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(header, signatureV2) {
		t.Fatal("v2 headers must start with the signature")
	}
	if len(header) != 12+4+12 {
		t.Fatalf("v2 header is %d bytes, want 28 for IPv4", len(header))
	}
	if header[12] != 0x21 { // version 2, command PROXY
		t.Fatalf("version/command byte = %#x, want 0x21", header[12])
	}
	if header[13] != 0x11 { // AF_INET, STREAM
		t.Fatalf("family byte = %#x, want 0x11", header[13])
	}
	if length := binary.BigEndian.Uint16(header[14:16]); length != 12 {
		t.Fatalf("address length = %d, want 12", length)
	}
	src := net.IP(header[16:20])
	dst := net.IP(header[20:24])
	if !src.Equal(net.ParseIP("203.0.113.5")) || !dst.Equal(net.ParseIP("198.51.100.9")) {
		t.Fatalf("addresses = %s → %s", src, dst)
	}
	if port := binary.BigEndian.Uint16(header[24:26]); port != 51234 {
		t.Fatalf("source port = %d", port)
	}
	if port := binary.BigEndian.Uint16(header[26:28]); port != 443 {
		t.Fatalf("destination port = %d", port)
	}
}

func TestProxyHeaderV2IPv6Layout(t *testing.T) {
	header, err := proxyHeaderV2(tcpAddr(t, "[2001:db8::1]:1234"), tcpAddr(t, "[2001:db8::2]:443"))
	if err != nil {
		t.Fatal(err)
	}
	if header[13] != 0x21 { // AF_INET6, STREAM
		t.Fatalf("family byte = %#x, want 0x21", header[13])
	}
	if length := binary.BigEndian.Uint16(header[14:16]); length != 36 {
		t.Fatalf("address length = %d, want 36", length)
	}
	if len(header) != 12+4+36 {
		t.Fatalf("v2 header is %d bytes, want 52 for IPv6", len(header))
	}
}

func TestWriteProxyHeaderRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		done <- writeProxyHeader(client, ProxyProtocolV1, tcpAddr(t, "203.0.113.5:1234"), tcpAddr(t, "198.51.100.9:80"))
	}()
	buf := make([]byte, 128)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(buf[:n]), "PROXY TCP4 ") {
		t.Fatalf("unexpected header: %q", buf[:n])
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// "none" writes nothing at all.
	if err := writeProxyHeader(client, ProxyProtocolNone, tcpAddr(t, "203.0.113.5:1234"), tcpAddr(t, "198.51.100.9:80")); err != nil {
		t.Fatal(err)
	}
}
