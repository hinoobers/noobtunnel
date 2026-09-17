package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/control"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// loadServerEnvFile reads the installer's /etc/noobtunnel/server.env and applies
// the keys that are not already set in the environment. Keys in the file that are
// overridden on the command line still win, because flags are parsed after this.
func loadServerEnvFile() {
	path := os.Getenv("NOOBTUNNEL_ENV_FILE")
	if path == "" {
		path = "/etc/noobtunnel/server.env"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
}

func runServer(args []string) error {
	// Running the control node by hand (for --print-info, or a first start)
	// should see the same configuration the service uses: the domain and the ACME
	// email are flags, not stored settings, so without this the report says "no
	// public hostname" while the service is happily serving one.
	loadServerEnvFile()
	fs := newFlagSet("server")
	var (
		stateDir    = fs.String("state-dir", env("NOOBTUNNEL_STATE_DIR", defaultStateDir()), "directory for state, keys and certificates")
		listen      = fs.String("listen", env("NOOBTUNNEL_LISTEN", ":8443"), "TLS listen address for the web UI and agent channel")
		publicEP    = fs.String("public-endpoint", env("NOOBTUNNEL_PUBLIC_ENDPOINT", ""), "public host or host:port advertised to agents for WireGuard")
		adminPass   = fs.String("admin-password", env("NOOBTUNNEL_ADMIN_PASSWORD", ""), "admin password for the web UI (only used when none is set yet)")
		binaryDir   = fs.String("binary-dir", env("NOOBTUNNEL_BINARY_DIR", defaultBinaryDir()), "directory holding agent release binaries served to enrolling machines")
		backendName = fs.String("backend", env("NOOBTUNNEL_BACKEND", "kernel"), "WireGuard backend: kernel or fake")
		demo        = fs.Bool("demo", false, "run with simulated agents to preview the UI")
		demoAgents  = fs.Int("demo-agents", 4, "how many simulated agents to start with --demo")
		setupSystem = fs.Bool("setup-system", envBool("NOOBTUNNEL_SETUP_SYSTEM", true), "enable IP forwarding and firewall rules at startup (Linux)")
		interfaceIN = fs.String("interface", env("NOOBTUNNEL_INTERFACE", ""), "WireGuard interface name (default noobtun)")
		wgPort      = fs.Int("wg-port", envInt("NOOBTUNNEL_WG_PORT", 0), "WireGuard UDP port (default 51820)")
		meshCIDR    = fs.String("mesh", env("NOOBTUNNEL_MESH", ""), "mesh address range (default 10.77.0.0/16)")
		mtu         = fs.Int("mtu", 0, "WireGuard interface MTU (default 1420)")
		// Empty means "keep the persisted setting". DefaultSettings enables direct
		// paths for a fresh install; making the flag itself default to true used to
		// silently undo an operator disabling them on every server restart.
		direct     = fs.String("direct", env("NOOBTUNNEL_DIRECT", ""), "allow direct agent to agent paths (true or false)")
		logLevel   = fs.String("log-level", env("NOOBTUNNEL_LOG_LEVEL", "info"), "debug, info, warn or error")
		printOnly  = fs.Bool("print-info", false, "print the control node summary and exit")
		acmeEmail  = fs.String("acme-email", env("NOOBTUNNEL_ACME_EMAIL", ""), "email for Let's Encrypt certificates; empty uses self-signed certificates for HTTPS resources")
		domain     = fs.String("domain", env("NOOBTUNNEL_DOMAIN", ""), "hostname this control node is published on, for example noobtunnel.example.com; serves the UI on https://<domain> with a managed certificate")
		ipapiHost  = fs.String("ipapi-host", env("NOOBTUNNEL_IPAPI_HOST", ""), "hostname of the IP API used for country rules, for example iplog.example.com")
		ipapiToken = fs.String("ipapi-token", env("NOOBTUNNEL_IPAPI_TOKEN", ""), "token for that IP API, sent as a bearer token")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := newLogger(*logLevel)
	if *demo {
		// Demo mode uses the configured state directory like any other run, so
		// accounts, password changes, resources and exit nodes survive a restart.
		logger.Warn("demo mode writes to the normal state directory",
			"stateDir", *stateDir,
			"tip", "pass --state-dir to keep a throwaway demo mesh somewhere else")
	}
	backend, err := buildBackend(*backendName, logger, *demo)
	if err != nil {
		return err
	}
	server, err := control.New(control.Options{
		StateDir:       *stateDir,
		Listen:         *listen,
		PublicEndpoint: *publicEP,
		AdminPassword:  *adminPass,
		Backend:        backend,
		Logger:         logger,
		SetupSystem:    *setupSystem,
		BinaryDir:      *binaryDir,
		ACMEEmail:      *acmeEmail,
		Domain:         *domain,
		IPAPIHost:      *ipapiHost,
		IPAPIToken:     *ipapiToken,
	})
	if err != nil {
		return err
	}
	if err := applyServerOverrides(server, *interfaceIN, *wgPort, *meshCIDR, *mtu, *direct); err != nil {
		return err
	}
	if !server.Auth().HasPassword() {
		generated, err := generatePassword()
		if err != nil {
			return err
		}
		if err := server.Auth().EnsureAdmin(generated); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\n  The account is \"admin\" with the generated password: %s\n"+
			"  Change it from the account menu (top right) after signing in, and add accounts in the Users tab.\n\n", generated)
	}
	printStartupBanner(server, *listen, *stateDir, *adminPass)
	if *printOnly {
		printServerInfo(server)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *demo {
		return runDemo(ctx, server, *demoAgents, logger)
	}
	return server.Run(ctx)
}

func applyServerOverrides(server *control.Server, iface string, port int, cidr string, mtu int, direct string) error {
	st := server.Store().View()
	settings := st.Settings
	changed := false
	if iface != "" && iface != settings.Interface {
		settings.Interface = iface
		changed = true
	}
	if port > 0 && port != settings.WGListenPort {
		settings.WGListenPort = port
		changed = true
	}
	if cidr != "" && cidr != settings.MeshCIDR {
		settings.MeshCIDR = cidr
		changed = true
	}
	if mtu > 0 && mtu != settings.MTU {
		settings.MTU = mtu
		changed = true
	}
	switch strings.ToLower(strings.TrimSpace(direct)) {
	case "true", "1", "yes", "on":
		if !settings.DirectPaths {
			settings.DirectPaths = true
			changed = true
		}
	case "false", "0", "no", "off":
		if settings.DirectPaths {
			settings.DirectPaths = false
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return server.Store().Update(func(state *store.State) error {
		state.Settings = settings
		return nil
	})
}

func printServerInfo(server *control.Server) {
	st := server.Store().View()
	fmt.Printf("state directory   %s\n", server.Store().Path())
	fmt.Printf("certificate       %s\n", server.Cert().Fingerprint)
	fmt.Printf("mesh range        %s\n", st.Settings.MeshCIDR)
	fmt.Printf("wireguard port    %d (udp)\n", st.Settings.WGListenPort)
	fmt.Printf("interface         %s\n", st.Settings.Interface)
	fmt.Printf("hub public key    %s\n", st.Hub.PublicKey)
	fmt.Printf("user accounts     %d (%d admin)\n", len(server.Auth().Users()), server.Auth().AdminCount())
	// The hub's peers and handshakes are read from the kernel, so this works
	// while the service is running and answers the one question a published
	// service depends on: is there a live tunnel to the agent behind it?
	names := map[string]string{}
	for _, agent := range server.Store().Agents() {
		if agent.PublicKey != "" {
			names[agent.PublicKey] = agent.Name
		}
	}
	status, err := server.BackendValue().Status(context.Background(), st.Settings.Interface)
	switch {
	case err != nil:
		fmt.Printf("hub interface     unreadable: %v\n", err)
	case !status.Exists:
		fmt.Printf("hub interface     %s does not exist on this host\n", st.Settings.Interface)
	default:
		fmt.Printf("hub interface     %s is up, %d peer(s)\n", status.Name, len(status.Peers))
		for _, peer := range status.Peers {
			handshake := "no handshake yet"
			if !peer.LatestHandshake.IsZero() {
				handshake = "handshake " + time.Since(peer.LatestHandshake).Round(time.Second).String() + " ago"
			}
			name := names[peer.PublicKey]
			if name == "" {
				name = "unknown agent"
			}
			fmt.Printf("  %-20s %-24s %s\n", name, orDash(peer.Endpoint), handshake)
		}
	}
	for _, check := range server.RunChecks(context.Background()) {
		fmt.Printf("%-9s %-34s %s\n", check.Status, check.Title, check.Detail)
	}
}

// orDash renders an empty string as a dash.
func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return value
}

// printStartupBanner states plainly where the state lives, which URL to open and
// which account to sign in with, so a stale process or a forgotten password is
// obvious instead of mysterious.
func printStartupBanner(server *control.Server, listen, stateDir, adminPassword string) {
	accounts := server.Auth().Users()
	var names []string
	for _, account := range accounts {
		names = append(names, fmt.Sprintf("%s (%s)", account.Username, account.Role))
	}
	accountLine := "none yet"
	if len(names) > 0 {
		accountLine = strings.Join(names, ", ")
	}
	passwordLine := "unknown, use: noobtunnel user set-password --username admin"
	if adminPassword != "" {
		passwordLine = "the one you passed with --admin-password"
	}
	// With --domain the browser address and the agent address differ: the UI is
	// published on the domain, agents still dial the TLS listener so the
	// certificate they pin never changes under them.
	webLine := "web UI      " + webURL(listen)
	if domain, ok := server.RuntimeInfo()["domain"].(string); ok && domain != "" {
		webLine = "web UI      https://" + domain
		if _, port, err := net.SplitHostPort(listen); err == nil && port != "" && port != "443" {
			webLine += "\n  agents      https://" + net.JoinHostPort(domain, port) + " (pinned certificate)"
		}
	}
	fmt.Fprintf(os.Stderr, `
  noobtunnel control node
  ----------------------------------------------------------------
  %s
  state       %s
  accounts    %s
  password    %s
  certificate %s

  If a sign in is refused, check the log lines below: failed logins are
  reported with the username that was tried. To set a known password:

    noobtunnel user set-password --state-dir "%s" --username admin

`, webLine, stateDir, accountLine, passwordLine, server.Cert().Fingerprint, stateDir)
}

// webURL turns a listen address into something clickable.
func webURL(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "https://localhost" + listen
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "https://" + listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "https://" + net.JoinHostPort(host, port)
}

// buildBackend selects the WireGuard implementation.
func buildBackend(name string, logger *slog.Logger, demo bool) (wg.Backend, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "kernel", "real":
		if runtime.GOOS == "windows" && !demo {
			return nil, errors.New("the kernel backend needs WSL or a Linux host; use --backend fake to preview")
		}
		return &wg.ExecBackend{}, nil
	case "fake", "sim", "demo":
		return wg.NewFakeNetwork().NewHubDevice(), nil
	default:
		return nil, fmt.Errorf("unknown backend %q (use kernel or fake)", name)
	}
}

func generatePassword() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

var _ = flag.ErrHelp
var _ = time.Second
