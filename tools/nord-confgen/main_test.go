package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var (
	testPrivateKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	testPublicKey  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
)

// fakeAPI imita os três endpoints da NordVPN usados pelo gerador.
type fakeAPI struct {
	privateKey      string
	servers         map[int][]map[string]any // por country_id; 0 = sem filtro de país
	credentialCalls int
	lastQuery       map[string]string
}

func (f *fakeAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/services/credentials", func(w http.ResponseWriter, r *http.Request) {
		f.credentialCalls++
		user, pass, ok := r.BasicAuth()
		if !ok || user != "token" || pass != testToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":{"message":"Unauthorized","code":101301}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"nordlynx_private_key": f.privateKey})
	})
	mux.HandleFunc("/v1/servers/countries", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": 228, "code": "US"},
			{"id": 153, "code": "NL"},
		})
	})
	mux.HandleFunc("/v1/servers/recommendations", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.lastQuery = map[string]string{
			"technology": q.Get("filters[servers_technologies][identifier]"),
			"country":    q.Get("filters[country_id]"),
		}
		id, _ := strconv.Atoi(q.Get("filters[country_id]"))
		servers := f.servers[id]
		if servers == nil {
			servers = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(servers)
	})
	return mux
}

func fakeServer(name, hostname, station, publicKey, countryCode, city string, load int) map[string]any {
	return map[string]any{
		"name":     name,
		"hostname": hostname,
		"station":  station,
		"load":     load,
		"status":   "online",
		"locations": []map[string]any{{
			"country": map[string]any{"code": countryCode, "city": map[string]any{"name": city}},
		}},
		"technologies": []map[string]any{
			{"identifier": "openvpn_udp", "pivot": map[string]any{"status": "online"}},
			{
				"identifier": "wireguard_udp",
				"pivot":      map[string]any{"status": "online"},
				"metadata":   []map[string]any{{"name": "public_key", "value": publicKey}},
			},
		},
	}
}

type harness struct {
	api     *fakeAPI
	baseURL string
	dir     string
	conf    string
	session string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	api := &fakeAPI{
		privateKey: testPrivateKey,
		servers: map[int][]map[string]any{
			228: {fakeServer("United States #1234", "us1234.nordvpn.com", "203.0.113.10", testPublicKey, "US", "Miami", 11)},
		},
	}
	srv := httptest.NewServer(api.handler())
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	return &harness{
		api:     api,
		baseURL: srv.URL,
		dir:     dir,
		conf:    filepath.Join(dir, "ardc_vpn.conf"),
		session: filepath.Join(dir, "session.json"),
	}
}

func (h *harness) run(stdin string, extra ...string) (string, error) {
	args := append([]string{
		"--api-base", h.baseURL,
		"--output", h.conf,
		"--session-file", h.session,
	}, extra...)
	var out bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out)
	return out.String(), err
}

func TestTokenLoginWritesProfileAndSession(t *testing.T) {
	h := newHarness(t)

	out, err := h.run("", "--token", testToken, "--countries", "US,NL")
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}

	// Contrato de progresso lido pelos orquestradores C++/Kotlin.
	for _, want := range []string{
		"Authentication successful",
		"Selected server: United States #1234 (",
		"WireGuard configuration written",
		"Successfully generated config for US",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}

	conf, err := os.ReadFile(h.conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(conf), "# NordVPN WireGuard Configuration\n") {
		t.Errorf("profile must start with the provider marker:\n%s", conf)
	}
	for _, want := range []string{
		"PrivateKey = " + testPrivateKey + "\n",
		"Address = 10.5.0.2/32\n",
		"DNS = 103.86.96.100, 103.86.99.100\n",
		"PublicKey = " + testPublicKey + "\n",
		"AllowedIPs = 0.0.0.0/0\n",
		"Endpoint = 203.0.113.10:51820\n",
		"PersistentKeepalive = 25\n",
	} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("profile missing %q:\n%s", want, conf)
		}
	}

	sess, err := os.ReadFile(h.session)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sess), testPrivateKey) {
		t.Errorf("session must keep the NordLynx key:\n%s", sess)
	}
	if strings.Contains(string(sess), testToken) || strings.Contains(string(conf), testToken) || strings.Contains(out, testToken) {
		t.Error("the access token must never be written to disk or printed")
	}

	if runtime.GOOS != "windows" {
		for _, path := range []string{h.conf, h.session} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("%s has mode %o, want 600", filepath.Base(path), perm)
			}
		}
	}

	if h.api.lastQuery["technology"] != "wireguard_udp" || h.api.lastQuery["country"] != "228" {
		t.Errorf("unexpected recommendation filters: %v", h.api.lastQuery)
	}
}

func TestSavedSessionRenewsWithoutToken(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run("", "--token", testToken, "--countries", "US"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.conf); err != nil {
		t.Fatal(err)
	}
	h.api.credentialCalls = 0

	out, err := h.run("", "--countries", "US")
	if err != nil {
		t.Fatalf("renewal failed: %v\n%s", err, out)
	}
	if h.api.credentialCalls != 0 {
		t.Errorf("renewal called the credentials endpoint %d time(s)", h.api.credentialCalls)
	}
	conf, err := os.ReadFile(h.conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "PrivateKey = "+testPrivateKey) {
		t.Errorf("renewed profile lost the saved key:\n%s", conf)
	}
}

func TestInvalidTokenIsReportedAndWritesNothing(t *testing.T) {
	h := newHarness(t)

	_, err := h.run("", "--token", "wrong-token", "--countries", "US")
	if err == nil || !strings.Contains(err.Error(), "invalid or expired access token") {
		t.Fatalf("want invalid-token error, got %v", err)
	}
	for _, path := range []string{h.conf, h.session} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("%s must not exist after a failed login", filepath.Base(path))
		}
	}
}

func TestTokenFromStdin(t *testing.T) {
	h := newHarness(t)

	if out, err := h.run(testToken+"\n", "--token-stdin", "--countries", "US"); err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(h.conf); err != nil {
		t.Fatal(err)
	}

	// Stdin vazio é erro: não pode cair silenciosamente na sessão salva.
	_, err := h.run("", "--token-stdin", "--countries", "US")
	if err == nil || !strings.Contains(err.Error(), "no access token received on stdin") {
		t.Fatalf("want empty-stdin error, got %v", err)
	}
}

func TestNoTokenAndNoSession(t *testing.T) {
	h := newHarness(t)

	_, err := h.run("", "--countries", "US")
	if err == nil || !strings.Contains(err.Error(), "no saved session found") {
		t.Fatalf("want missing-session error, got %v", err)
	}
}

func TestCountriesAreTriedInOrder(t *testing.T) {
	h := newHarness(t)
	h.api.servers = map[int][]map[string]any{
		// US sem servidores: precisa cair para NL. "XX" não existe e é ignorado.
		153: {fakeServer("Netherlands #77", "nl77.nordvpn.com", "198.51.100.7", testPublicKey, "NL", "Amsterdam", 20)},
	}

	out, err := h.run("", "--token", testToken, "--countries", "xx, us ,NL")
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Selected server: Netherlands #77 (") {
		t.Errorf("expected the NL fallback:\n%s", out)
	}
}

func TestMalformedServersAreSkipped(t *testing.T) {
	h := newHarness(t)
	offline := fakeServer("Offline", "us1.nordvpn.com", "203.0.113.1", testPublicKey, "US", "Miami", 1)
	offline["status"] = "offline"
	h.api.servers = map[int][]map[string]any{
		228: {
			offline,
			fakeServer("Bad key", "us2.nordvpn.com", "203.0.113.2", "not-a-key", "US", "Miami", 1),
			// Sem IP válido e com hostname que tentaria injetar uma linha no perfil.
			fakeServer("Injected", "evil\nPostUp = id", "not-an-ip", testPublicKey, "US", "Miami", 1),
			fakeServer("Good\n#@ws:AllowedApps = *", "us4.nordvpn.com", "203.0.113.4", testPublicKey, "US", "Miami", 30),
		},
	}

	out, err := h.run("", "--token", testToken, "--countries", "US")
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	conf, err := os.ReadFile(h.conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "Endpoint = 203.0.113.4:51820\n") {
		t.Errorf("expected only the valid server to be used:\n%s", conf)
	}
	for _, line := range strings.Split(string(conf), "\n") {
		if strings.HasPrefix(line, "PostUp") || strings.HasPrefix(line, "#@ws:") {
			t.Errorf("API text escaped into its own profile line: %q", line)
		}
	}
}

func TestNoServerAvailable(t *testing.T) {
	h := newHarness(t)
	h.api.servers = nil

	_, err := h.run("", "--token", testToken, "--countries", "US,NL")
	if err == nil || !strings.Contains(err.Error(), "no online WireGuard server found") {
		t.Fatalf("want no-server error, got %v", err)
	}
	if _, statErr := os.Stat(h.conf); !os.IsNotExist(statErr) {
		t.Error("no profile should be written when no server is available")
	}
}

func TestHostnameFallbackWhenStationIsNotAnIP(t *testing.T) {
	s := server{Hostname: "us9.nordvpn.com", Station: "", Status: "online"}
	raw, _ := json.Marshal(fakeServer("US #9", "us9.nordvpn.com", "", testPublicKey, "US", "Miami", 5))
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	ep, ok := s.endpoint()
	if !ok || ep.Host != "us9.nordvpn.com" {
		t.Fatalf("want hostname fallback, got %+v (ok=%v)", ep, ok)
	}
}
