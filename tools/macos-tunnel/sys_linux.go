//go:build linux

package main

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Development build only. The helper is shipped for macOS; this file lets the
// tunnel, the address rewriting and the daemon logic be compiled and exercised
// on Linux, where the test that drives it configures the interface itself and
// there is no pf to load.

const tunInterfaceName = "ardcmac0"

func sysConfigureInterface(ifname string, addr netip.Addr, mtu int) error { return nil }

func sysFirewallUp(ifname string, addr netip.Addr, gid int, stateDir string) (string, error) {
	return "", os.WriteFile(filepath.Join(stateDir, "pf.rules"), []byte(pfTunnelRules(ifname, addr, gid)), 0o600)
}

func sysFirewallKillSwitch(gid int, stateDir string) error {
	return os.WriteFile(filepath.Join(stateDir, "pf.rules"), []byte(pfKillSwitchRules(gid)), 0o600)
}

func sysFirewallDown(token string) {}

func sysReleaseToken(token string) {}

func sysDisableTSO() (string, error) { return "", nil }

func sysRestoreTSO(prev string) {}

func sysListProcs() ([]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var procs []procInfo
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			continue
		}
		info := procInfo{PID: pid, RGID: -1}
		for _, line := range strings.Split(string(data), "\n") {
			if name, ok := strings.CutPrefix(line, "Name:"); ok {
				info.Name = strings.TrimSpace(name)
			} else if gids, ok := strings.CutPrefix(line, "Gid:"); ok {
				if fields := strings.Fields(gids); len(fields) > 0 {
					info.RGID, _ = strconv.Atoi(fields[0])
				}
			}
		}
		procs = append(procs, info)
	}
	return procs, nil
}

func sysDiag(w io.Writer, st *tunnelState) {
	fmt.Fprintln(w, "\n(system details are only collected on macOS)")
}
