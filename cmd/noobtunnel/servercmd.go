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

func runServer(args []string) error {
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
		direct      = fs.String("direct", env("NOOBTUNNEL_DIRECT", "true"), "allow direct agent to agent paths (true or false)")
		logLevel    = fs.String("log-level", env("NOOBTUNNEL_LOG_LEVEL", "info"), "debug, info, warn or error")
		printOnly   = fs.Bool("print-info", false, "print the control node summary and exit")
		acmeEmail   = fs.String("acme-email", env("NOOBTUNNEL_ACME_EMAIL", ""), "email for Let's Encrypt certificates; empty uses self-signed certificates for HTTPS resources")
		domain      = fs.String("domain", env("NOOBTUNNEL_DOMAIN", ""), "hostname this control node is published on, for example noobtunnel.example.com; serves the UI on https://<domain> with a managed certificate")
		geoipKey    = fs.String("geoip-license-key", env("NOOBTUNNEL_GEOIP_LICENSE_KEY", ""), "MaxMind licence key; enables country access rules")
		geoipUser   = fs.String("geoip-account-id", env("NOOBTUNNEL_GEOIP_ACCOUNT_ID", ""), "MaxMind account id used with the licence key")
		geoipDir    = fs.String("geoip-dir", env("NOOBTUNNEL_GEOIP_DIR", ""), "directory holding GeoLite2-Country data (default <state-dir>/geoip)")
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
		StateDir:        *stateDir,
		Listen:          *listen,
		PublicEndpoint:  *publicEP,
		AdminPassword:   *adminPass,
		Backend:         backend,
		Logger:          logger,
		SetupSystem:     *setupSystem,
		BinaryDir:       *binaryDir,
		ACMEEmail:       *acmeEmail,
		Domain:          *domain,
		GeoIPLicenceKey: *geoipKey,
		GeoIPAccountID:  *geoipUser,
		GeoIPDir:        *geoipDir,
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
	for _, check := range server.RunChecks(context.Background()) {
		fmt.Printf("%-9s %-34s %s\n", check.Status, check.Title, check.Detail)
	}
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
