package wg

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// PeerDump is one peer line from `wg show <iface> dump`.
type PeerDump struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	LatestHandshake     time.Time
	RxBytes             uint64
	TxBytes             uint64
	PersistentKeepalive int
}

// InterfaceDump is the parsed output of `wg show <iface> dump`.
type InterfaceDump struct {
	PrivateKey string
	PublicKey  string
	ListenPort int
	FwMark     int
	Peers      []PeerDump
}

// ErrEmptyDump means wg(8) produced no interface line.
var ErrEmptyDump = errors.New("wg: empty dump output")

// ParseDump parses the tab separated output of `wg show <iface> dump`.
//
// The format is stable and documented in wg(8):
//
//	private_key  public_key  listen_port  fwmark
//	public_key  preshared_key  endpoint  allowed_ips  latest_handshake  rx  tx  keepalive
//
// Missing values are rendered as "(none)" or "(hidden)".
func ParseDump(out string) (*InterfaceDump, error) {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, ErrEmptyDump
	}
	ifaceFields := strings.Split(lines[0], "\t")
	if len(ifaceFields) < 4 {
		return nil, errors.New("wg: malformed interface line in dump")
	}
	dump := &InterfaceDump{
		PrivateKey: cleanValue(ifaceFields[0]),
		PublicKey:  cleanValue(ifaceFields[1]),
		ListenPort: atoiOrZero(ifaceFields[2]),
		FwMark:     atoiOrZero(ifaceFields[3]),
	}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			continue
		}
		peer := PeerDump{
			PublicKey:           cleanValue(f[0]),
			PresharedKey:        cleanValue(f[1]),
			Endpoint:            cleanValue(f[2]),
			LatestHandshake:     time.Unix(int64(atoi64OrZero(f[4])), 0),
			RxBytes:             uint64(atoi64OrZero(f[5])),
			TxBytes:             uint64(atoi64OrZero(f[6])),
			PersistentKeepalive: atoiOrZero(f[7]),
		}
		if ips := cleanValue(f[3]); ips != "" {
			for _, s := range strings.Split(ips, ",") {
				if s = strings.TrimSpace(s); s != "" {
					peer.AllowedIPs = append(peer.AllowedIPs, s)
				}
			}
		}
		if peer.LatestHandshake.Unix() == 0 {
			peer.LatestHandshake = time.Time{}
		}
		dump.Peers = append(dump.Peers, peer)
	}
	return dump, nil
}

func cleanValue(s string) string {
	s = strings.TrimSpace(s)
	switch s {
	case "(none)", "(hidden)", "(no endpoint)", "off":
		return ""
	}
	return s
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

func atoi64OrZero(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
