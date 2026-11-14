package main

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(fill byte) (b64, hexKey string) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	return base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(raw)
}

func writeConf(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseNordProfile(t *testing.T) {
	priv, privHex := testKey(1)
	pub, pubHex := testKey(2)
	conf, err := parseConfFile(writeConf(t, `# NordVPN WireGuard Configuration
[Interface]
PrivateKey = `+priv+`
Address = 10.5.0.2/32
DNS = 103.86.96.100, 103.86.99.100

[Peer]
PublicKey = `+pub+`
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.7:51820
PersistentKeepalive = 25
`))
	if err != nil {
		t.Fatal(err)
	}
	if conf.PrivateKey != privHex || conf.PublicKey != pubHex {
		t.Error("keys not converted to hex")
	}
	if conf.Address != netip.MustParseAddr("10.5.0.2") {
		t.Errorf("address = %v", conf.Address)
	}
	if conf.Endpoint != "198.51.100.7:51820" || conf.Keepalive != 25 {
		t.Errorf("endpoint/keepalive = %q/%d", conf.Endpoint, conf.Keepalive)
	}

	uapi := conf.uapi("198.51.100.7:51820")
	for _, want := range []string{
		"private_key=" + privHex + "\n",
		"public_key=" + pubHex + "\n",
		"endpoint=198.51.100.7:51820\n",
		"persistent_keepalive_interval=25\n",
		"allowed_ip=0.0.0.0/0\n",
	} {
		if !strings.Contains(uapi, want) {
			t.Errorf("uapi lacks %q", want)
		}
	}
	if strings.Contains(uapi, "preshared_key") {
		t.Error("uapi has a preshared key that the profile does not")
	}
}

func TestParseProtonStyleProfile(t *testing.T) {
	priv, _ := testKey(3)
	pub, _ := testKey(4)
	psk, pskHex := testKey(5)
	// IPv6 address first, lower-case keys, no keepalive, dual-stack AllowedIPs.
	conf, err := parseConfFile(writeConf(t, `[interface]
privatekey=`+priv+`
address = 2a07:b944::2:2/128, 10.2.0.2/32
MTU = 1420
[peer]
publickey=`+pub+`
presharedkey=`+psk+`
allowedips = 0.0.0.0/0, ::/0
endpoint = 203.0.113.9:51820 ; comment
[Peer]
PublicKey = ignored-second-peer
`))
	if err != nil {
		t.Fatal(err)
	}
	if conf.Address != netip.MustParseAddr("10.2.0.2") {
		t.Errorf("address = %v, want the IPv4 one", conf.Address)
	}
	if conf.Keepalive != defaultKeepalive {
		t.Errorf("keepalive = %d, want the default", conf.Keepalive)
	}
	if conf.PresharedKey != pskHex || len(conf.AllowedIPs) != 2 {
		t.Errorf("preshared key or allowed IPs not parsed: %+v", conf)
	}
}

func TestParseRejectsBrokenProfiles(t *testing.T) {
	priv, _ := testKey(1)
	pub, _ := testKey(2)
	base := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.5.0.2/32\n[Peer]\nPublicKey = " + pub +
		"\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.7:51820\n"

	cases := map[string]string{
		"no private key":  strings.Replace(base, "PrivateKey = "+priv+"\n", "", 1),
		"short key":       strings.Replace(base, priv, "c2hvcnQ=", 1),
		"no address":      strings.Replace(base, "Address = 10.5.0.2/32\n", "", 1),
		"ipv6 only":       strings.Replace(base, "10.5.0.2/32", "fd00::2/128", 1),
		"no peer":         "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.5.0.2/32\n",
		"no endpoint":     strings.Replace(base, "Endpoint = 198.51.100.7:51820\n", "", 1),
		"no allowed ips":  strings.Replace(base, "AllowedIPs = 0.0.0.0/0\n", "", 1),
		"bad allowed ips": strings.Replace(base, "0.0.0.0/0", "everything", 1),
	}
	for name, content := range cases {
		if _, err := parseConfFile(writeConf(t, content)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseConfFile(writeConf(t, base)); err != nil {
		t.Errorf("valid profile rejected: %v", err)
	}
}

func TestResolveEndpoint(t *testing.T) {
	if got, err := resolveEndpoint("198.51.100.7:51820"); err != nil || got != "198.51.100.7:51820" {
		t.Errorf("literal IPv4: %q, %v", got, err)
	}
	if got, err := resolveEndpoint("[2001:db8::1]:51820"); err != nil || got != "[2001:db8::1]:51820" {
		t.Errorf("literal IPv6: %q, %v", got, err)
	}
	for _, bad := range []string{"198.51.100.7", "198.51.100.7:0", "198.51.100.7:port"} {
		if _, err := resolveEndpoint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPFRules(t *testing.T) {
	rules := pfTunnelRules("utun7", netip.MustParseAddr("10.5.0.2"), 47823)
	lines := strings.Split(strings.TrimSpace(rules), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d rules, want 3:\n%s", len(lines), rules)
	}
	want := []string{
		"pass out quick on ! lo0 inet proto { tcp, udp } from any to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } group 47823 keep state",
		"pass out quick on ! lo0 route-to (utun7 10.5.0.2) inet proto { tcp, udp } from any to any group 47823 keep state",
		"block return out quick on ! lo0 proto { tcp, udp } from any to any group 47823",
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("rule %d:\n got  %s\n want %s", i+1, lines[i], want[i])
		}
	}
	if got := pfKillSwitchRules(47823); got != want[2]+"\n" {
		t.Errorf("kill switch = %q", got)
	}
}
