// Package proto defines the JSON control channel spoken between an agent and
// the control node over the pinned TLS connection.
//
// The control channel is reliably delivered and ordered: it carries
// configuration (WireGuard peer sets), liveness probes, statistics and commands.
// The mesh traffic itself never flows over it.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Magic is written by the agent as the first bytes of the control channel so a
// misrouted HTTP request fails fast.
var Magic = []byte("NOOBTUNNEL1\n")

// UpgradeToken is the HTTP Upgrade value that opens an agent control channel.
const UpgradeToken = "noobtunnel/1"

// AgentPath is the HTTP path agents upgrade from.
const AgentPath = "/agent/connect"

// UpgradeRequest renders the HTTP request that opens a control channel.
func UpgradeRequest(host string) []byte {
	return []byte("GET " + AgentPath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: noobtunnel\r\n" +
		"Upgrade: " + UpgradeToken + "\r\n" +
		"Connection: Upgrade\r\n\r\n")
}

// MaxMessageSize caps a single control channel message.
const MaxMessageSize = 1 << 20

// Control channel message types.
const (
	THello   = "hello"
	TWelcome = "welcome"
	TPeers   = "peers"
	TPing    = "ping"
	TPong    = "pong"
	TStats   = "stats"
	TLog     = "log"
	TError   = "error"
	TRevoked = "revoked"
	TCommand = "command"
	TProbe   = "probeResult"
	TBye     = "bye"
)

// Hub describes how an agent reaches the control node's WireGuard interface.
// This is the path that always works, regardless of NAT.
type Hub struct {
	PublicKey string `json:"publicKey"`
	Endpoint  string `json:"endpoint"`
	Address   string `json:"address"`
	// PresharedKey is unique per agent and shared only with that agent.
	PresharedKey string `json:"presharedKey,omitempty"`
}

// Peer is one mesh member as described to an agent.
type Peer struct {
	ID        uint32   `json:"id"`
	Name      string   `json:"name"`
	Address   string   `json:"address"`
	PublicKey string   `json:"publicKey"`
	Advertise []string `json:"advertise,omitempty"`
	// Endpoint is the control node's latest observation of this agent's public
	// (post-NAT) UDP endpoint. Empty means the agent is not directly reachable.
	Endpoint string `json:"endpoint,omitempty"`
	Online   bool   `json:"online"`
	// PresharedKey is the pairwise key for this peer, only sent to the mesh
	// members that are part of the pair.
	PresharedKey string `json:"presharedKey,omitempty"`
	// Direct asks the agent to attempt a direct path to this peer.
	Direct bool `json:"direct"`
}

// Hello is the first message an agent sends after the TLS handshake.
type Hello struct {
	T          string   `json:"t"`
	Token      string   `json:"token"`
	PublicKey  string   `json:"publicKey"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	OS         string   `json:"os"`
	Arch       string   `json:"arch"`
	Hostname   string   `json:"hostname,omitempty"`
	ListenPort int      `json:"listenPort,omitempty"`
	Advertise  []string `json:"advertise,omitempty"`
	// Direct requests opportunistic direct paths to other agents.
	Direct bool `json:"direct"`
}

// Welcome is the answer to a successful Hello.
type Welcome struct {
	T            string `json:"t"`
	AgentID      uint32 `json:"agentId"`
	Name         string `json:"name"`
	Address      string `json:"address"`
	Prefix       int    `json:"prefix"`
	MeshCIDR     string `json:"meshCidr"`
	MTU          int    `json:"mtu"`
	KeepaliveSec int    `json:"keepaliveSec"`
	Interface    string `json:"interface"`
	Generation   uint64 `json:"generation"`
	ServerTime   int64  `json:"serverTime"`
	Hub          Hub    `json:"hub"`
	Peers        []Peer `json:"peers"`
	// Carry is what the mesh routes through this agent, as resolved by the
	// control node (see Peers.Carry).
	Carry []string `json:"carry,omitempty"`
	// Tuning values the agent needs so both ends agree on timing.
	StatsIntervalSec int `json:"statsIntervalSec"`
	DirectFreshSec   int `json:"directFreshSec"`
	DirectProbeSec   int `json:"directProbeSec"`
}

// Peers is a full membership snapshot; agents replace their view with it.
type Peers struct {
	T          string `json:"t"`
	Generation uint64 `json:"generation"`
	Peers      []Peer `json:"peers"`
	// Carry is what the mesh routes through this agent: the networks the control
	// node resolved to it. It is what the agent has to forward, which is not
	// necessarily what the agent offered - the operator can change the list here
	// after the machine enrolled, and the control node is the one that decides.
	Carry []string `json:"carry,omitempty"`
}

// Ping asks the agent to answer with a Pong.
type Ping struct {
	T   string `json:"t"`
	Seq uint64 `json:"seq"`
}

// Pong answers a Ping.
type Pong struct {
	T   string `json:"t"`
	Seq uint64 `json:"seq"`
}

// PeerStat is per-peer live state read from the agent's WireGuard device.
type PeerStat struct {
	ID              uint32 `json:"id"`
	PublicKey       string `json:"publicKey,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	LatestHandshake int64  `json:"latestHandshake"` // unix nanoseconds, 0 = never
	RxBytes         uint64 `json:"rxBytes"`
	TxBytes         uint64 `json:"txBytes"`
	// Direct reports whether the agent currently treats this peer as a direct
	// (non-relayed) path.
	Direct bool `json:"direct"`
}

// Stats is reported periodically by the agent.
type Stats struct {
	T          string     `json:"t"`
	UptimeSec  int64      `json:"uptimeSec"`
	RxBytes    uint64     `json:"rxBytes"`
	TxBytes    uint64     `json:"txBytes"`
	PeerStats  []PeerStat `json:"peerStats,omitempty"`
	Interface  string     `json:"interface,omitempty"`
	MTU        int        `json:"mtu,omitempty"`
	Routes     []string   `json:"routes,omitempty"`
	LastError  string     `json:"lastError,omitempty"`
	Generation uint64     `json:"generation"`
	Backend    string     `json:"backend,omitempty"`
}

// Log is a line from the agent's log.
type Log struct {
	T       string `json:"t"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Time    int64  `json:"time"`
}

// Error reports a control channel problem.
type Error struct {
	T       string `json:"t"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Revoked tells an agent that its token is no longer valid.
type Revoked struct {
	T      string `json:"t"`
	Reason string `json:"reason"`
}

// Command is a request from the control node to the agent.
type Command struct {
	T      string `json:"t"`
	Seq    uint64 `json:"seq,omitempty"`
	Action string `json:"action"` // reconnect | resync | shutdown
	// Targets are host:port pairs the agent should try to reach itself, used by
	// the control node's diagnostics. Only set for ActionProbe.
	Targets []string `json:"targets,omitempty"`
}

// Command actions.
const (
	ActionReconnect = "reconnect"
	ActionResync    = "resync"
	ActionShutdown  = "shutdown"
	// ActionProbe asks the agent to try reaching the targets from its own
	// machine and to describe the path it would take.
	ActionProbe = "probe"
)

// ProbeEntry is one connection an agent attempted on the control node's behalf.
type ProbeEntry struct {
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Millis int64  `json:"millis"`
	Error  string `json:"error,omitempty"`
	// LocalAddr is the source address the agent's kernel picked.
	LocalAddr string `json:"localAddr,omitempty"`
	// Meshed marks the attempt whose source was the agent's own mesh address,
	// which is what a connection arriving through the tunnel looks like to the
	// service on the other side.
	Meshed bool `json:"meshed,omitempty"`
}

// ProbeResult answers a probe command.
type ProbeResult struct {
	T       string       `json:"t"`
	Seq     uint64       `json:"seq"`
	Route   string       `json:"route,omitempty"`
	Results []ProbeEntry `json:"results"`
}

// Bye is sent by an agent that is shutting down cleanly.
type Bye struct {
	T      string `json:"t"`
	Reason string `json:"reason,omitempty"`
}

// Envelope is used to sniff the type of a decoded message.
type Envelope struct {
	T string `json:"t"`
}

// ErrMessageTooLarge means a peer sent an oversized control message.
var ErrMessageTooLarge = errors.New("proto: control message too large")

// WriteJSON writes one length-prefixed JSON message.
func WriteJSON(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > MaxMessageSize {
		return fmt.Errorf("proto: message of %d bytes exceeds limit", len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// ReadJSON reads one length-prefixed JSON message.
func ReadJSON(r io.Reader, v any) error {
	_, raw, err := ReadRaw(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// ReadRaw reads one length-prefixed message and returns its type and payload.
func ReadRaw(r io.Reader) (string, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxMessageSize {
		return "", nil, ErrMessageTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", nil, err
	}
	var env Envelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return "", nil, err
	}
	return env.T, buf, nil
}
