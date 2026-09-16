package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// maxClientHello caps how much of a TLS handshake we are willing to buffer while
// looking for the server name.
const maxClientHello = 16 * 1024

// ClientHello is the part of a TLS handshake a passthrough listener needs.
type ClientHello struct {
	ServerName string
	// Raw is everything read from the connection, so it can be replayed to the
	// real service untouched.
	Raw []byte
}

// errors returned while peeking.
var (
	ErrNotTLS          = errors.New("proxy: not a TLS handshake")
	ErrNoServerName    = errors.New("proxy: the TLS handshake carries no server name")
	ErrHandshakeTooBig = errors.New("proxy: TLS handshake is unusually large")
)

// peekClientHello reads a TLS ClientHello without consuming it: the bytes are
// returned so the caller can forward them verbatim. TLS is never terminated, so
// the service behind the tunnel keeps its own certificate.
func peekClientHello(conn net.Conn) (*ClientHello, error) {
	reader := bufio.NewReaderSize(conn, 4096)
	raw := make([]byte, 0, 4096)

	// TCP record header: type(1) version(2) length(2)
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	raw = append(raw, header...)
	if header[0] != 0x16 {
		return nil, ErrNotTLS
	}
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen <= 0 || recordLen > maxClientHello {
		return nil, ErrHandshakeTooBig
	}
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(reader, record); err != nil {
		return nil, err
	}
	raw = append(raw, record...)
	// Anything the bufio reader buffered beyond the record belongs to the next
	// record; hand it back so it is forwarded too.
	if buffered := reader.Buffered(); buffered > 0 {
		extra := make([]byte, buffered)
		if _, err := io.ReadFull(reader, extra); err == nil {
			raw = append(raw, extra...)
		}
	}

	name, err := parseServerName(record)
	if err != nil {
		return nil, err
	}
	return &ClientHello{ServerName: name, Raw: raw}, nil
}

// parseServerName walks a TLS handshake record and extracts the SNI extension.
func parseServerName(record []byte) (string, error) {
	// Handshake header: type(1) length(3)
	if len(record) < 4 {
		return "", ErrNoServerName
	}
	if record[0] != 0x01 { // ClientHello
		return "", ErrNoServerName
	}
	body := record[4:]
	// version(2) random(32) session id(1+n)
	if len(body) < 35 {
		return "", ErrNoServerName
	}
	pos := 34
	sessionLen := int(body[pos])
	pos++
	if pos+sessionLen+2 > len(body) {
		return "", ErrNoServerName
	}
	pos += sessionLen
	// cipher suites(2+n)
	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+cipherLen+1 > len(body) {
		return "", ErrNoServerName
	}
	pos += cipherLen
	// compression methods(1+n)
	compLen := int(body[pos])
	pos++
	if pos+compLen > len(body) {
		return "", ErrNoServerName
	}
	pos += compLen
	if pos+2 > len(body) {
		return "", ErrNoServerName
	}
	// extensions(2+n)
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extLen > len(body) {
		extLen = len(body) - pos
	}
	extensions := body[pos : pos+extLen]

	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[0:2])
		extSize := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extSize > len(extensions) {
			break
		}
		data := extensions[:extSize]
		extensions = extensions[extSize:]
		if extType != 0 { // 0 = server_name
			continue
		}
		// server name list: length(2) then entries of type(1) length(2) name
		if len(data) < 5 {
			break
		}
		listLen := int(binary.BigEndian.Uint16(data[0:2]))
		if listLen > len(data)-2 {
			listLen = len(data) - 2
		}
		entries := data[2 : 2+listLen]
		for len(entries) >= 3 {
			nameType := entries[0]
			nameLen := int(binary.BigEndian.Uint16(entries[1:3]))
			entries = entries[3:]
			if nameLen > len(entries) {
				break
			}
			name := string(entries[:nameLen])
			entries = entries[nameLen:]
			if nameType == 0 && name != "" {
				return strings.ToLower(name), nil
			}
		}
		break
	}
	return "", ErrNoServerName
}

// describeHelloError makes handshake failures readable in logs.
func describeHelloError(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
