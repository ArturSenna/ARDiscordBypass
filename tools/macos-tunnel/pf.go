package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// The rules live in their own anchor under "com.apple/": the stock macOS
// ruleset evaluates every anchor below it, so nothing in /etc/pf.conf has to be
// edited and unloading is a single flush.
const pfAnchor = "com.apple/ardiscordbypass"

// Destinations that keep their normal route even for tunneled processes: the
// local network (router DNS, printers, casting) is not reachable through a VPN.
var pfLocalRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"255.255.255.255",
}

// pfTunnelRules builds the split-tunnel ruleset. pf cannot match a packet by
// application, but it can match the unix group that owns the socket, so the
// tunneled app is started under a dedicated group and everything it sends is
// diverted into the tunnel interface.
//
// Both rules that pass traffic are "quick" and come before the block: the first
// match wins. "on ! lo0" keeps loopback out, otherwise the app would lose its
// own localhost connections. The last rule is the kill switch: anything from
// the group that was not handled above (IPv6 included, the tunnel is IPv4
// only) is refused at once instead of leaving through the normal connection.
func pfTunnelRules(ifname string, addr netip.Addr, gid int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "pass out quick on ! lo0 inet proto { tcp, udp } from any to { %s } group %d keep state\n",
		strings.Join(pfLocalRanges, ", "), gid)
	fmt.Fprintf(&b, "pass out quick on ! lo0 route-to (%s %s) inet proto { tcp, udp } from any to any group %d keep state\n",
		ifname, addr, gid)
	b.WriteString(pfKillSwitchRules(gid))
	return b.String()
}

// pfKillSwitchRules is what stays loaded when the tunnel is gone but processes
// of the group are still running: they are held offline until they quit.
func pfKillSwitchRules(gid int) string {
	return fmt.Sprintf("block return out quick on ! lo0 proto { tcp, udp } from any to any group %d\n", gid)
}
