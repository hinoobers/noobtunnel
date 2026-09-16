package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// PROXY protocol versions understood by the forwarder.
const (
	ProxyProtocolNone = ""
	ProxyProtocolV1   = "v1"
	ProxyProtocolV2   = "v2"
)

// signatureV2 is the 12 byte magic that starts a version 2 header.
var signatureV2 = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// writeProxyHeader prepends a PROXY protocol header describing the client
// connection so the service behind the tunnel can recover the real client
// address even though the TCP connection comes from the control node.
func writeProxyHeader(conn net.Conn, version string, client net.Addr, target net.Addr) error {
	switch version {
	case ProxyProtocolV1:
		header := proxyHeaderV1(client, target)
		_, err := conn.Write(header)
		return err
	case ProxyProtocolV2:
		header, err := proxyHeaderV2(client, target)
		if err != nil {
			return err
		}
		_, err = conn.Write(header)
		return err
	default:
		return nil
	}
}

// proxyHeaderV1 renders the text header:
//
//	PROXY TCP4 192.0.2.1 198.51.100.7 56324 443\r\n
func proxyHeaderV1(client, target net.Addr) []byte {
	clientAddr, targetAddr := splitAddrs(client, target)
	if !clientAddr.IsValid() || !targetAddr.IsValid() || clientAddr.Is4() != targetAddr.Is4() {
		// Mixed families cannot be expressed in the text format.
		return []byte("PROXY UNKNOWN\r\n")
	}
	family := "TCP6"
	if clientAddr.Is4() {
		family = "TCP4"
	}
	header := fmt.Sprintf("PROXY %s %s %s %d %d\r\n", family,
		clientAddr, targetAddr, portOf(client), portOf(target))
	return []byte(header)
}

// proxyHeaderV2 renders the binary header.
func proxyHeaderV2(client, target net.Addr) ([]byte, error) {
	clientAddr, targetAddr := splitAddrs(client, target)
	if !clientAddr.IsValid() || !targetAddr.IsValid() {
		return nil, fmt.Errorf("proxy: cannot describe the connection addresses")
	}
	header := make([]byte, 0, 52)
	header = append(header, signatureV2...)

	var family byte = 0x00 // AF_UNSPEC
	var addresses []byte
	switch {
	case clientAddr.Is4() && targetAddr.Is4():
		family = 0x11 // AF_INET, STREAM
		addresses = make([]byte, 0, 12)
		c4, t4 := clientAddr.As4(), targetAddr.As4()
		addresses = append(addresses, c4[:]...)
		addresses = append(addresses, t4[:]...)
	case clientAddr.Is6() && targetAddr.Is6():
		family = 0x21 // AF_INET6, STREAM
		addresses = make([]byte, 0, 36)
		c16, t16 := clientAddr.As16(), targetAddr.As16()
		addresses = append(addresses, c16[:]...)
		addresses = append(addresses, t16[:]...)
	default:
		// Mixed families: use the UNSPEC form, which v2 supports cleanly.
		family = 0x00
	}
	if family != 0x00 {
		var ports [4]byte
		binary.BigEndian.PutUint16(ports[0:2], uint16(portOf(client)))
		binary.BigEndian.PutUint16(ports[2:4], uint16(portOf(target)))
		addresses = append(addresses, ports[:]...)
	}

	header = append(header, 0x21) // version 2, command PROXY
	header = append(header, family)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(addresses)))
	header = append(header, length[:]...)
	header = append(header, addresses...)
	return header, nil
}

// splitAddrs extracts the IP addresses from two net.Addr values, unmapped so
// IPv4-in-IPv6 forms are described as IPv4.
func splitAddrs(client, target net.Addr) (netip.Addr, netip.Addr) {
	clientIP := ipOf(client)
	targetIP := ipOf(target)
	if clientIP.IsValid() {
		clientIP = clientIP.Unmap()
	}
	if targetIP.IsValid() {
		targetIP = targetIP.Unmap()
	}
	return clientIP, targetIP
}

func ipOf(addr net.Addr) netip.Addr {
	if addr == nil {
		return netip.Addr{}
	}
	switch value := addr.(type) {
	case *net.TCPAddr:
		return ipFromBytes(value.IP)
	case *net.UDPAddr:
		return ipFromBytes(value.IP)
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}
	}
	return ipFromBytes(net.ParseIP(strings.Trim(host, "[]")))
}

func ipFromBytes(raw net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func portOf(addr net.Addr) int {
	switch value := addr.(type) {
	case *net.TCPAddr:
		return value.Port
	case *net.UDPAddr:
		return value.Port
	case nil:
		return 0
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}
