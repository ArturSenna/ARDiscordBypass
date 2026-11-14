//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// macOS creates the interface as utunN and picks N itself.
const tunInterfaceName = "utun"

const (
	pfctlPath    = "/sbin/pfctl"
	ifconfigPath = "/sbin/ifconfig"
	sysctlPath   = "/usr/sbin/sysctl"
	tsoSysctl    = "net.inet.tcp.tso"
)

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s %s: %v: %s", filepath.Base(name), strings.Join(args, " "), err, lastLine(text))
	}
	return text, nil
}

func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func sysConfigureInterface(ifname string, addr netip.Addr, mtu int) error {
	// Same address on both ends of the point-to-point interface and no route:
	// only what the firewall diverts ever enters the tunnel.
	_, err := run(ifconfigPath, ifname, "inet", addr.String(), addr.String(),
		"netmask", "255.255.255.255", "mtu", strconv.Itoa(mtu), "up")
	return err
}

// pfMainRules returns the main ruleset (stdout only; pfctl prints unrelated
// ALTQ notices on stderr).
func pfMainRules() (string, error) {
	out, err := exec.Command(pfctlPath, "-sr").Output()
	if err != nil {
		return "", fmt.Errorf("pfctl -sr: %v", err)
	}
	return string(out), nil
}

func pfLoadAnchor(rules, stateDir string) error {
	path := filepath.Join(stateDir, "pf.rules")
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		return err
	}
	if out, err := run(pfctlPath, "-n", "-a", pfAnchor, "-f", path); err != nil {
		// The whole pfctl output goes to the daemon log; "diag" shows it.
		fmt.Println(out)
		return fmt.Errorf("pf refused the rules: %s", lastLine(out))
	}
	if _, err := run(pfctlPath, "-q", "-a", pfAnchor, "-f", path); err != nil {
		return err
	}
	return nil
}

var pfTokenPattern = regexp.MustCompile(`Token\s*:\s*(\d+)`)

func sysFirewallUp(ifname string, addr netip.Addr, gid int, stateDir string) (string, error) {
	main, err := pfMainRules()
	if err != nil {
		return "", err
	}
	if !strings.Contains(main, `anchor "com.apple/*"`) {
		if strings.TrimSpace(main) != "" {
			return "", errors.New(`the active pf ruleset was replaced by another program and has no anchor "com.apple/*"; the tunnel rules would never be evaluated`)
		}
		// Nothing is loaded at all: load the system default, which has the anchor.
		if _, err := run(pfctlPath, "-q", "-f", "/etc/pf.conf"); err != nil {
			return "", err
		}
		if main, err = pfMainRules(); err != nil || !strings.Contains(main, `anchor "com.apple/*"`) {
			return "", errors.New(`/etc/pf.conf has no anchor "com.apple/*"; the tunnel rules would never be evaluated`)
		}
	}

	if err := pfLoadAnchor(pfTunnelRules(ifname, addr, gid), stateDir); err != nil {
		return "", err
	}

	// -E enables pf with a reference: it stays on while any holder keeps a
	// token, and releasing ours (-X) never disables it for the others.
	out, _ := exec.Command(pfctlPath, "-E").CombinedOutput()
	match := pfTokenPattern.FindStringSubmatch(string(out))
	if match == nil {
		return "", fmt.Errorf("could not enable pf: %s", lastLine(string(out)))
	}

	// From here on the token is returned even on failure, so the caller can
	// release it.
	loaded, _ := exec.Command(pfctlPath, "-a", pfAnchor, "-sr").Output()
	if !strings.Contains(string(loaded), "route-to") {
		return match[1], errors.New("pf accepted the rules but the anchor is empty")
	}
	return match[1], nil
}

func sysFirewallKillSwitch(gid int, stateDir string) error {
	return pfLoadAnchor(pfKillSwitchRules(gid), stateDir)
}

// sysFirewallDown removes the anchor's rules and gives back the pf reference.
func sysFirewallDown(token string) {
	exec.Command(pfctlPath, "-q", "-a", pfAnchor, "-F", "all").Run()
	sysReleaseToken(token)
}

func sysReleaseToken(token string) {
	if token != "" {
		exec.Command(pfctlPath, "-q", "-X", token).Run()
	}
}

// sysDisableTSO turns off TCP segmentation offload and returns the previous
// value ("" when nothing was changed).
//
// With TSO the kernel hands the network card one oversized TCP segment to
// split. pf's route-to does not split it: a diverted segment larger than the
// tunnel MTU is dropped (xnu pf_route answers it with "fragmentation needed"),
// so any tunneled send bigger than one segment would stall. The setting is
// global and is restored when the tunnel goes down.
func sysDisableTSO() (string, error) {
	prev, err := run(sysctlPath, "-n", tsoSysctl)
	if err != nil {
		return "", err
	}
	if prev == "0" {
		return "", nil
	}
	if _, err := run(sysctlPath, "-w", tsoSysctl+"=0"); err != nil {
		return "", err
	}
	return prev, nil
}

func sysRestoreTSO(prev string) {
	if prev != "" {
		exec.Command(sysctlPath, "-w", tsoSysctl+"="+prev).Run()
	}
}

func sysListProcs() ([]procInfo, error) {
	kprocs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	procs := make([]procInfo, 0, len(kprocs))
	for i := range kprocs {
		kp := &kprocs[i]
		procs = append(procs, procInfo{
			PID:  int(kp.Proc.P_pid),
			RGID: int(kp.Eproc.Pcred.P_rgid),
			Name: unix.ByteSliceToString(kp.Proc.P_comm[:]),
		})
	}
	return procs, nil
}

func sysDiag(w io.Writer, st *tunnelState) {
	section := func(title string, name string, args ...string) {
		fmt.Fprintf(w, "\n--- %s\n", title)
		out, err := exec.Command(name, args...).CombinedOutput()
		w.Write(out)
		if err != nil {
			fmt.Fprintf(w, "(%v)\n", err)
		}
	}
	section("macOS", "/usr/bin/sw_vers")
	section("pf status", pfctlPath, "-s", "info")
	section("pf main ruleset", pfctlPath, "-sr")
	section("pf anchor "+pfAnchor, pfctlPath, "-a", pfAnchor, "-sr")
	section("pf states of the anchor (first 20)", "/bin/sh", "-c", pfctlPath+" -a "+pfAnchor+" -ss 2>/dev/null | head -20")
	section(tsoSysctl, sysctlPath, tsoSysctl)
	if st != nil && st.Ifname != "" {
		section("interface "+st.Ifname, ifconfigPath, st.Ifname)
	}
	section("default route", "/sbin/route", "-n", "get", "default")
}
