package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// wgConf holds what the tunnel needs from a WireGuard profile (.conf): the
// [Interface] section and the first [Peer].
type wgConf struct {
	PrivateKey   string // hex
	Address      netip.Addr
	PublicKey    string // hex
	PresharedKey string // hex, optional
	Endpoint     string // host:port as written in the profile
	AllowedIPs   []netip.Prefix
	Keepalive    int
}

const defaultKeepalive = 25

func parseConfFile(path string) (*wgConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	conf := &wgConf{}
	section := ""
	peers := 0

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				peers++
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch {
		case section == "interface" && key == "privatekey":
			if conf.PrivateKey, err = keyToHex(value); err != nil {
				return nil, fmt.Errorf("invalid PrivateKey: %w", err)
			}
		case section == "interface" && key == "address":
			for _, item := range strings.Split(value, ",") {
				addr, err := parseAddress(strings.TrimSpace(item))
				if err == nil && addr.Is4() && !conf.Address.IsValid() {
					conf.Address = addr
				}
			}
		case section == "peer" && peers == 1 && key == "publickey":
			if conf.PublicKey, err = keyToHex(value); err != nil {
				return nil, fmt.Errorf("invalid PublicKey: %w", err)
			}
		case section == "peer" && peers == 1 && key == "presharedkey":
			if conf.PresharedKey, err = keyToHex(value); err != nil {
				return nil, fmt.Errorf("invalid PresharedKey: %w", err)
			}
		case section == "peer" && peers == 1 && key == "endpoint":
			conf.Endpoint = value
		case section == "peer" && peers == 1 && key == "allowedips":
			for _, item := range strings.Split(value, ",") {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				prefix, err := netip.ParsePrefix(item)
				if err != nil {
					addr, addrErr := netip.ParseAddr(item)
					if addrErr != nil {
						return nil, fmt.Errorf("invalid AllowedIPs entry %q", item)
					}
					prefix = netip.PrefixFrom(addr, addr.BitLen())
				}
				conf.AllowedIPs = append(conf.AllowedIPs, prefix.Masked())
			}
		case section == "peer" && peers == 1 && key == "persistentkeepalive":
			if n, err := strconv.Atoi(value); err == nil && n >= 0 && n <= 65535 {
				conf.Keepalive = n
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	switch {
	case conf.PrivateKey == "":
		return nil, errors.New("profile has no PrivateKey")
	case !conf.Address.IsValid():
		return nil, errors.New("profile has no IPv4 Address")
	case conf.PublicKey == "":
		return nil, errors.New("profile has no [Peer] PublicKey")
	case conf.Endpoint == "":
		return nil, errors.New("profile has no [Peer] Endpoint")
	}

	hasV4 := false
	for _, p := range conf.AllowedIPs {
		if p.Addr().Is4() {
			hasV4 = true
		}
	}
	if !hasV4 {
		return nil, errors.New("profile has no IPv4 AllowedIPs")
	}
	// Without a keepalive nothing would start the handshake until the first
	// tunneled packet, and the tunnel could not be verified before the app opens.
	if conf.Keepalive == 0 {
		conf.Keepalive = defaultKeepalive
	}
	return conf, nil
}

func parseAddress(s string) (netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Addr(), nil
	}
	return netip.ParseAddr(s)
}

func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", errors.New("not valid base64")
	}
	if len(raw) != 32 {
		return "", errors.New("key must be 32 bytes")
	}
	return hex.EncodeToString(raw), nil
}

// resolveEndpoint turns the profile's Endpoint into ip:port. Host names are
// resolved by the system resolver (outside the tunnel), preferring IPv4.
func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid Endpoint %q", endpoint)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid Endpoint port %q", port)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(addr.String(), port), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("could not resolve Endpoint host %q", host)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), port), nil
		}
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// uapi renders the configuration in the WireGuard cross-platform userspace
// format consumed by device.IpcSet.
func (c *wgConf) uapi(endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", c.PrivateKey)
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", c.PublicKey)
	if c.PresharedKey != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", c.PresharedKey)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.Keepalive)
	b.WriteString("replace_allowed_ips=true\n")
	for _, p := range c.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p.String())
	}
	return b.String()
}
