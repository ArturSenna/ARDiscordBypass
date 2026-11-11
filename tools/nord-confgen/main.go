// nord-confgen gera um perfil WireGuard (NordLynx) para a NordVPN.
//
// Fluxo:
//  1. Com um token de acesso (--token ou --token-stdin) consulta a API da
//     NordVPN e obtém a chave privada NordLynx da conta.
//  2. Sem token, reutiliza a chave salva em ~/.nordvpn-session.json.
//  3. Escolhe o servidor recomendado no primeiro país de --countries que tiver
//     um servidor WireGuard online.
//  4. Grava o perfil WireGuard em --output.
//
// As linhas impressas em stdout seguem o mesmo contrato do proton-confgen
// ("Authentication successful", "Selected server:", "WireGuard configuration
// written", "Successfully generated config" e "Error: ..."), para que os
// orquestradores em C++ e Kotlin reutilizem o mesmo parser de progresso.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	defaultAPIBase = "https://api.nordvpn.com"
	userAgent      = "nord-confgen/1.0"

	wireGuardTech = "wireguard_udp"
	wireGuardPort = "51820"

	// Endereço e DNS internos do NordLynx: iguais para todas as contas, o
	// servidor faz o NAT por cliente.
	clientAddress = "10.5.0.2/32"
	clientDNS     = "103.86.96.100, 103.86.99.100"

	defaultCountries = "US,NL,JP"
	defaultOutput    = "ardc_vpn.conf"
	sessionFileName  = ".nordvpn-session.json"

	maxResponseBytes = 4 << 20
)

type options struct {
	token       string
	tokenStdin  bool
	countries   []string
	output      string
	sessionFile string
	apiBase     string
}

type session struct {
	Provider   string `json:"provider"`
	PrivateKey string `json:"private_key"`
	SavedAt    string `json:"saved_at"`
}

type country struct {
	ID   int    `json:"id"`
	Code string `json:"code"`
}

type server struct {
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	Station   string `json:"station"`
	Load      int    `json:"load"`
	Status    string `json:"status"`
	Locations []struct {
		Country struct {
			Code string `json:"code"`
			City struct {
				Name string `json:"name"`
			} `json:"city"`
		} `json:"country"`
	} `json:"locations"`
	Technologies []struct {
		Identifier string `json:"identifier"`
		Pivot      struct {
			Status string `json:"status"`
		} `json:"pivot"`
		Metadata []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"metadata"`
	} `json:"technologies"`
}

// endpoint é um servidor já validado, pronto para virar a seção [Peer].
type endpoint struct {
	Name      string
	Hostname  string
	Host      string
	PublicKey string
	Country   string
	City      string
	Load      int
}

type client struct {
	base string
	http *http.Client
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}

	token, err := resolveToken(opts, stdin)
	if err != nil {
		return err
	}

	sessionPath, err := resolveSessionPath(opts.sessionFile)
	if err != nil {
		return err
	}

	api := &client{base: opts.apiBase, http: &http.Client{Timeout: 20 * time.Second}}

	var privateKey string
	if token != "" {
		privateKey, err = api.privateKey(token)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		fmt.Fprintln(stdout, "Authentication successful!")
		if err := saveSession(sessionPath, privateKey); err != nil {
			// O perfil ainda pode ser gerado; só a renovação automática fica indisponível.
			fmt.Fprintf(stdout, "Warning: could not save session: %v\n", err)
		}
	} else {
		privateKey, err = loadSession(sessionPath)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Using saved NordLynx key.")
	}

	ep, err := api.pickServer(opts.countries)
	if err != nil {
		return fmt.Errorf("failed to select a server: %w", err)
	}
	fmt.Fprintf(stdout, "Selected server: %s (Country: %s, City: %s, Load: %d%%)\n",
		ep.Name, ep.Country, ep.City, ep.Load)

	if err := writePrivateFile(opts.output, []byte(buildConfig(privateKey, ep, time.Now()))); err != nil {
		return fmt.Errorf("failed to write WireGuard config: %w", err)
	}
	fmt.Fprintf(stdout, "WireGuard configuration written to: %s\n", opts.output)
	fmt.Fprintf(stdout, "\nSuccessfully generated config for %s\n", ep.Country)
	return nil
}

func parseOptions(args []string) (*options, error) {
	fs := flag.NewFlagSet("nord-confgen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	opts := &options{}
	var countries string
	fs.StringVar(&opts.token, "token", "", "NordVPN access token")
	fs.BoolVar(&opts.tokenStdin, "token-stdin", false, "read the access token from the first line of stdin")
	fs.StringVar(&countries, "countries", defaultCountries, "country codes in order of preference (empty = nearest server)")
	fs.StringVar(&opts.output, "output", defaultOutput, "path of the WireGuard profile to write")
	fs.StringVar(&opts.sessionFile, "session-file", "", "where the NordLynx key is kept (default ~/"+sessionFileName+")")
	fs.StringVar(&opts.apiBase, "api-base", defaultAPIBase, "NordVPN API base URL")

	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("%w (flags: --token, --token-stdin, --countries, --output, --session-file)", err)
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if opts.output == "" {
		return nil, errors.New("--output must not be empty")
	}

	seen := map[string]bool{}
	for _, code := range strings.Split(countries, ",") {
		code = strings.ToUpper(strings.TrimSpace(code))
		if code != "" && !seen[code] {
			seen[code] = true
			opts.countries = append(opts.countries, code)
		}
	}
	opts.apiBase = strings.TrimRight(opts.apiBase, "/")
	return opts, nil
}

// resolveToken devolve o token informado, ou "" quando a sessão salva deve ser usada.
func resolveToken(opts *options, stdin io.Reader) (string, error) {
	if opts.tokenStdin {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("failed to read access token from stdin: %w", err)
		}
		token := strings.TrimSpace(line)
		if token == "" {
			return "", errors.New("no access token received on stdin")
		}
		return token, nil
	}
	return strings.TrimSpace(opts.token), nil
}

func (c *client) getJSON(path string, query url.Values, token string, out any) error {
	target := c.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.SetBasicAuth("token", token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// O erro do net/http cita a URL, nunca o cabeçalho de autenticação.
		return fmt.Errorf("could not reach the NordVPN API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("could not read the NordVPN API response: %w", err)
	}
	if token != "" && resp.StatusCode == http.StatusUnauthorized {
		return errors.New("invalid or expired access token (HTTP 401)")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NordVPN API returned HTTP %d for %s", resp.StatusCode, path)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("unexpected NordVPN API response for %s: %w", path, err)
	}
	return nil
}

func (c *client) privateKey(token string) (string, error) {
	var creds struct {
		NordLynxPrivateKey string `json:"nordlynx_private_key"`
	}
	if err := c.getJSON("/v1/users/services/credentials", nil, token, &creds); err != nil {
		return "", err
	}
	key := strings.TrimSpace(creds.NordLynxPrivateKey)
	if key == "" {
		return "", errors.New("account has no NordLynx key (is the NordVPN subscription active?)")
	}
	if !validWireGuardKey(key) {
		return "", errors.New("NordVPN API returned a malformed NordLynx key")
	}
	return key, nil
}

// pickServer percorre os países na ordem de preferência e devolve o primeiro
// servidor recomendado pela NordVPN que esteja online com WireGuard.
func (c *client) pickServer(countries []string) (*endpoint, error) {
	if len(countries) == 0 {
		return c.recommended(0, "any country")
	}

	var list []country
	if err := c.getJSON("/v1/servers/countries", nil, "", &list); err != nil {
		return nil, err
	}
	ids := make(map[string]int, len(list))
	for _, ct := range list {
		ids[strings.ToUpper(ct.Code)] = ct.ID
	}

	var lastErr error
	for _, code := range countries {
		id, ok := ids[code]
		if !ok {
			lastErr = fmt.Errorf("unknown country code %q", code)
			continue
		}
		ep, err := c.recommended(id, code)
		if err == nil {
			return ep, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *client) recommended(countryID int, label string) (*endpoint, error) {
	query := url.Values{}
	query.Set("filters[servers_technologies][identifier]", wireGuardTech)
	query.Set("limit", "5")
	if countryID != 0 {
		query.Set("filters[country_id]", strconv.Itoa(countryID))
	}

	var servers []server
	if err := c.getJSON("/v1/servers/recommendations", query, "", &servers); err != nil {
		return nil, err
	}
	for i := range servers {
		if ep, ok := servers[i].endpoint(); ok {
			return ep, nil
		}
	}
	return nil, fmt.Errorf("no online WireGuard server found for %s", label)
}

// endpoint valida tudo o que vai para o arquivo de perfil. Qualquer campo fora
// do formato esperado descarta o servidor em vez de ser gravado como veio.
func (s *server) endpoint() (*endpoint, bool) {
	if s.Status != "" && s.Status != "online" {
		return nil, false
	}

	publicKey := ""
	for _, tech := range s.Technologies {
		if tech.Identifier != wireGuardTech {
			continue
		}
		if tech.Pivot.Status != "" && tech.Pivot.Status != "online" {
			continue
		}
		for _, meta := range tech.Metadata {
			if meta.Name == "public_key" {
				publicKey = strings.TrimSpace(meta.Value)
			}
		}
	}
	if !validWireGuardKey(publicKey) {
		return nil, false
	}

	hostname := strings.TrimSpace(s.Hostname)
	host := strings.TrimSpace(s.Station)
	if net.ParseIP(host) == nil {
		if !validHostname(hostname) {
			return nil, false
		}
		host = hostname
	}

	ep := &endpoint{
		Name:      oneLine(s.Name),
		Hostname:  oneLine(hostname),
		Host:      host,
		PublicKey: publicKey,
		Load:      s.Load,
	}
	if ep.Name == "" {
		ep.Name = ep.Hostname
	}
	if len(s.Locations) > 0 {
		ep.Country = oneLine(s.Locations[0].Country.Code)
		ep.City = oneLine(s.Locations[0].Country.City.Name)
	}
	return ep, true
}

func buildConfig(privateKey string, ep *endpoint, now time.Time) string {
	var b strings.Builder
	// A primeira linha identifica o provedor para a renovação automática do app.
	b.WriteString("# NordVPN WireGuard Configuration\n")
	fmt.Fprintf(&b, "# Generated: %s\n", now.Format("2006-01-02 15:04:05 MST"))
	b.WriteString("#\n# Server Information:\n")
	fmt.Fprintf(&b, "# - Name: %s\n", ep.Name)
	fmt.Fprintf(&b, "# - Hostname: %s\n", ep.Hostname)
	fmt.Fprintf(&b, "# - Country: %s\n", ep.Country)
	fmt.Fprintf(&b, "# - City: %s\n", ep.City)
	fmt.Fprintf(&b, "# - Load: %d%%\n", ep.Load)
	b.WriteString("#\n\n")

	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privateKey)
	fmt.Fprintf(&b, "Address = %s\n", clientAddress)
	fmt.Fprintf(&b, "DNS = %s\n\n", clientDNS)

	b.WriteString("[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", ep.PublicKey)
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", net.JoinHostPort(ep.Host, wireGuardPort))
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

func resolveSessionPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate the home directory: %w", err)
	}
	return filepath.Join(home, sessionFileName), nil
}

// saveSession guarda apenas a chave NordLynx. O token de acesso dá poder sobre
// a conta inteira e nunca é gravado em disco.
func saveSession(path, privateKey string) error {
	data, err := json.MarshalIndent(session{
		Provider:   "nordvpn",
		PrivateKey: privateKey,
		SavedAt:    time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(path, append(data, '\n'))
}

func loadSession(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", errors.New("no access token provided and no saved session found")
	}
	if err != nil {
		return "", fmt.Errorf("cannot read saved session: %w", err)
	}
	var s session
	if err := json.Unmarshal(data, &s); err != nil || !validWireGuardKey(s.PrivateKey) {
		return "", errors.New("saved session is corrupted; log in again with an access token")
	}
	return s.PrivateKey, nil
}

// writePrivateFile substitui path por um arquivo completo com permissão 0600,
// usando um temporário no mesmo diretório para a troca ser atômica.
func writePrivateFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace non-regular file: %s", path)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".nordvpn-private-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// validWireGuardKey confere se o valor é uma chave Curve25519 em base64 (32 bytes).
func validWireGuardKey(key string) bool {
	raw, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(raw) == 32
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, r := range host {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !isAlnum && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// oneLine deixa um texto vindo da API seguro para uma linha de comentário ou de log.
func oneLine(text string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text)
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	if runes := []rune(cleaned); len(runes) > 80 {
		cleaned = string(runes[:80])
	}
	return cleaned
}
