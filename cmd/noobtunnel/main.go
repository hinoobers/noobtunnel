// Command noobtunnel is the single binary used for both the control node and
// the mesh agents.
//
//	noobtunnel server   run the control node (web UI, API, WireGuard hub)
//	noobtunnel agent    run an agent on a machine that should join the mesh
//	noobtunnel status   show this machine's local agent state
//	noobtunnel doctor   check that this machine can run an agent
//	noobtunnel keygen   print a WireGuard key pair
//	noobtunnel version  print version information
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "server":
		err = runServer(args)
	case "agent":
		err = runAgent(args)
	case "status":
		err = runStatus(args)
	case "doctor":
		err = runDoctor(args)
	case "keygen":
		err = runKeygen(args)
	case "install":
		err = runInstall(args)
	case "user", "users":
		err = runUser(args)
	case "version", "--version", "-v":
		printVersion()
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", command)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nnoobtunnel: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
noobtunnel - WireGuard mesh with a control node and outbound-only agents

usage: noobtunnel <command> [flags]

  server    run the control node (web UI on :8443, WireGuard hub on udp/51820)
  agent     run an agent that connects to a control node
  status    print this machine's local agent state
  doctor    check whether this machine can run an agent
  keygen    print a WireGuard private/public key pair
  install   print the install command for an agent token
  user      manage control node accounts (list, add, set-password, role, remove)
  version   print version information

Run "noobtunnel <command> --help" for the flags of a command.
`)+"\n")
}

func printVersion() {
	fmt.Printf("noobtunnel %s\n", versionString())
	fmt.Printf("commit     %s\n", commitString())
	fmt.Printf("built      %s\n", buildDateString())
	fmt.Printf("go         %s\n", goVersion())
	fmt.Printf("platform   %s/%s\n", goos(), goarch())
}
