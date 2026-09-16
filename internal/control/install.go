package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/noobtunnel/noobtunnel/internal/install"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/version"
)

// InstallOptions carries the values baked into a one line install command.
type InstallOptions struct {
	ControlEndpoint string
	Fingerprint     string
	Pin             string
	Direct          bool
	Interface       string
}

// installOptions derives the enrollment parameters from the request the admin
// made. Using the browser's host means the generated command always points at
// the address that actually reaches this control node.
func (s *Server) installOptions(r *http.Request) InstallOptions {
	settings := s.store.Settings()
	host := ""
	if r != nil {
		host = r.Host
	}
	// With a domain configured, the browser address (https://domain on port 443)
	// is served by a certificate that gets renewed, so the pinned fingerprint
	// would stop matching. Agents are pointed at the control listener on the same
	// name instead: that is the control node's own certificate, which never
	// changes, so pinning keeps working across renewals.
	if strings.TrimSpace(s.opts.Domain) != "" {
		host = s.controlEndpoint()
	} else if host == "" {
		host = s.hubEndpoint("")
	}
	return InstallOptions{
		ControlEndpoint: host,
		Fingerprint:     s.cert.Fingerprint,
		Pin:             s.cert.Pin,
		Direct:          settings.DirectPaths,
		Interface:       settings.Interface,
	}
}

// InstallCommand renders the copy and paste command for an agent.
func (s *Server) InstallCommand(agent *store.Agent, opts InstallOptions) string {
	var b strings.Builder
	b.WriteString("curl -fsSLk --retry 3")
	if opts.Pin != "" {
		b.WriteString(" --pinnedpubkey " + shellQuote("sha256//"+opts.Pin))
	}
	b.WriteString(" https://" + opts.ControlEndpoint + "/install.sh")
	b.WriteString(" | sudo sh -s --")
	b.WriteString(" --server " + shellQuote(opts.ControlEndpoint))
	b.WriteString(" --token " + shellQuote(agent.Token))
	if opts.Fingerprint != "" {
		b.WriteString(" --fingerprint " + shellQuote(opts.Fingerprint))
	}
	b.WriteString(" --name " + shellQuote(agent.Name))
	if len(agent.Advertise) > 0 {
		b.WriteString(" --advertise " + shellQuote(strings.Join(agent.Advertise, ",")))
	}
	if agent.AdvertiseAll {
		b.WriteString(" --advertise-all")
	}
	if opts.Interface != "" && opts.Interface != "noobtun" {
		b.WriteString(" --interface " + shellQuote(opts.Interface))
	}
	if !opts.Direct {
		b.WriteString(" --no-direct")
	}
	return b.String()
}

// shellQuote wraps a value in single quotes when it contains anything that is
// not obviously safe.
func shellQuote(s string) string {
	safe := s != ""
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '/', r == ':', r == ',', r == '@':
		default:
			safe = false
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	script, err := install.Script()
	if err != nil {
		http.Error(w, "installer unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(script)
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(install.CertPEM(s.cert.DER))
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/download/")
	if name == "manifest.json" {
		s.writeManifest(w)
		return
	}
	if !validBinaryName(name) {
		http.Error(w, "unknown artifact", http.StatusNotFound)
		return
	}
	path := filepath.Join(s.opts.BinaryDir, name)
	if s.opts.BinaryDir == "" {
		http.Error(w, "no binaries are configured on this control node", http.StatusNotFound)
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, path)
}

func validBinaryName(name string) bool {
	if !strings.HasPrefix(name, "noobtunnel_") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return !strings.Contains(name, "..")
}

// ManifestEntry describes a downloadable artifact with its checksum.
type ManifestEntry struct {
	Name   string `json:"name"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

var (
	manifestMu    sync.Mutex
	manifestCache map[string]string
)

func (s *Server) writeManifest(w http.ResponseWriter) {
	binaries := s.AvailableBinaries()
	manifestMu.Lock()
	if manifestCache == nil {
		manifestCache = map[string]string{}
	}
	cache := manifestCache
	manifestMu.Unlock()

	entries := make([]ManifestEntry, 0, len(binaries))
	for _, b := range binaries {
		path := filepath.Join(s.opts.BinaryDir, b.Name)
		sum := cache[path]
		if sum == "" {
			computed, err := fileSHA256(path)
			if err != nil {
				continue
			}
			sum = computed
			manifestMu.Lock()
			manifestCache[path] = sum
			manifestMu.Unlock()
		}
		entries = append(entries, ManifestEntry{
			Name: b.Name, OS: b.OS, Arch: b.Arch, Size: b.Size,
			SHA256: sum, URL: "/download/" + b.Name,
		})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":  version.Version,
		"binaries": entries,
	})
}

func fileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ErrNoBinaries means the control node has no agent binaries to hand out.
var ErrNoBinaries = errors.New("control: no agent binaries are configured")
