// ardc-tunnel is the privileged half of ARDiscordBypass on macOS.
//
// macOS has no network namespaces, so the per-application tunnel is built from
// three pieces that this program owns:
//
//   - a userspace WireGuard tunnel (wireguard-go) on a utun interface that
//     never becomes the default route;
//   - pf rules that divert into that interface only the traffic of sockets
//     owned by one dedicated unix group (see pf.go);
//   - a rewrite of the source address of the diverted packets (see nat.go).
//
// The application to tunnel is started under that group by the ARDiscordBypass
// executable itself; this helper only reports which processes carry the group
// and closes them.
//
// Commands (all but status, pids, kill and gid require root):
//
//	up     --conf FILE [--mtu N] [--gid N] [--keep-tso]   start the tunnel
//	down                                                 close tunneled apps, stop, undo
//	status                                               key=value state, exit 0 if running
//	pids                                                 processes in the tunnel group
//	kill                                                 close those processes
//	gid                                                  group id used for the tunnel
//	diag                                                 state of everything, for bug reports
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const version = "1.0.0"

type tunnelOptions struct {
	conf             string
	mtu              int
	gid              int
	stateDir         string
	keepTSO          bool
	verbose          bool
	handshakeTimeout time.Duration
	inheritToken     string
	inheritTSO       string
}

func parseTunnelFlags(command string, args []string) (*tunnelOptions, error) {
	opts := &tunnelOptions{}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opts.conf, "conf", "", "WireGuard profile (.conf)")
	fs.IntVar(&opts.mtu, "mtu", defaultMTU, "tunnel MTU")
	fs.IntVar(&opts.gid, "gid", 0, "group id of the tunneled processes (0 = automatic)")
	fs.StringVar(&opts.stateDir, "state-dir", defaultStateDir, "directory for state and log files")
	fs.BoolVar(&opts.keepTSO, "keep-tso", false, "do not disable TCP segmentation offload")
	fs.BoolVar(&opts.verbose, "verbose", false, "verbose WireGuard log")
	fs.DurationVar(&opts.handshakeTimeout, "handshake-timeout", 8*time.Second, "how long to wait for the first handshake")
	fs.StringVar(&opts.inheritToken, "inherit-token", "", "internal")
	fs.StringVar(&opts.inheritTSO, "inherit-tso", "", "internal")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	if command == "up" || command == "serve" {
		if opts.conf == "" {
			return nil, errors.New("--conf is required")
		}
		abs, err := filepath.Abs(opts.conf)
		if err != nil {
			return nil, err
		}
		opts.conf = abs
		if opts.mtu < 576 || opts.mtu > 1500 {
			return nil, errors.New("--mtu must be between 576 and 1500")
		}
		if opts.handshakeTimeout < time.Second {
			opts.handshakeTimeout = time.Second
		}
	}
	if command == "serve" && opts.gid <= 0 {
		return nil, errors.New("--gid is required")
	}
	return opts, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ardc-tunnel <up|down|status|pids|kill|gid|diag|version> [options]")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command, args := os.Args[1], os.Args[2:]

	var err error
	ok := true
	switch command {
	case "up":
		err = cmdUp(args)
	case "serve":
		err = cmdServe(args)
	case "down":
		err = cmdDown(args)
	case "status":
		ok, err = cmdStatus(args)
	case "pids":
		ok, err = cmdPids(args)
	case "kill":
		err = cmdKill(args)
	case "gid":
		err = cmdGID(args)
	case "diag":
		err = cmdDiag(args)
	case "version", "--version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		// Same contract as the profile generators: one "Error: ..." line.
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if !ok {
		os.Exit(3)
	}
}
