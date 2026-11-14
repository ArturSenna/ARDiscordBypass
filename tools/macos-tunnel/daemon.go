package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	defaultStateDir = "/var/run/ardiscordbypass"
	defaultMTU      = 1280

	// First group id tried for the tunneled processes. The group needs no
	// record in the directory: pf matches the number, and nothing else looks
	// it up. An id that some real group already uses is skipped.
	baseGID = 47823

	stateFile = "state.json"
	statsFile = "stats.json"
	logFile   = "tunnel.log"
)

// tunnelState is what the running daemon leaves on disk so that "down",
// "status" and the next "up" know what has to be undone. It holds no secrets.
type tunnelState struct {
	PID            int    `json:"pid"`
	Ifname         string `json:"ifname"`
	GID            int    `json:"gid"`
	Address        string `json:"address"`
	Endpoint       string `json:"endpoint"`
	MTU            int    `json:"mtu"`
	PFToken        string `json:"pf_token,omitempty"`
	TSOPrev        string `json:"tso_prev,omitempty"`
	KillSwitchOnly bool   `json:"kill_switch_only,omitempty"`
	StartedAt      int64  `json:"started_at"`
}

type tunnelStats struct {
	UpdatedAt     int64    `json:"updated_at"`
	HandshakeUnix int64    `json:"handshake_unix"`
	RxBytes       uint64   `json:"rx_bytes"`
	TxBytes       uint64   `json:"tx_bytes"`
	NAT           natStats `json:"nat"`
}

type procInfo struct {
	PID  int
	RGID int
	Name string
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	// Readable by the unprivileged "status" whatever umask sudo passed on.
	os.Chmod(tmp, 0o644)
	return os.Rename(tmp, path)
}

func readState(stateDir string) *tunnelState {
	data, err := os.ReadFile(filepath.Join(stateDir, stateFile))
	if err != nil {
		return nil
	}
	st := &tunnelState{}
	if json.Unmarshal(data, st) != nil {
		return nil
	}
	return st
}

func writeState(stateDir string, st *tunnelState) error {
	return writeJSON(filepath.Join(stateDir, stateFile), st)
}

func removeState(stateDir string) {
	for _, name := range []string{stateFile, statsFile, "pf.rules"} {
		os.Remove(filepath.Join(stateDir, name))
	}
}

// pickGID returns the group id used for tunneled processes: the first one from
// baseGID that no existing group owns. The choice is stable between runs.
func pickGID() int {
	for gid := baseGID; gid < baseGID+64; gid++ {
		if _, err := user.LookupGroupId(strconv.Itoa(gid)); err != nil {
			return gid
		}
	}
	return baseGID
}

func currentGID(stateDir string, flagGID int) int {
	if flagGID > 0 {
		return flagGID
	}
	if st := readState(stateDir); st != nil && st.GID > 0 {
		return st.GID
	}
	return pickGID()
}

func isAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// isDaemon tells whether pid is a running instance of this helper, so that a
// recycled pid from an old state file is never signalled.
func isDaemon(pid int) bool {
	if !isAlive(pid) {
		return false
	}
	self := filepath.Base(os.Args[0])
	if exe, err := os.Executable(); err == nil {
		self = filepath.Base(exe)
	}
	procs, err := sysListProcs()
	if err != nil {
		return false
	}
	for _, p := range procs {
		if p.PID == pid {
			// The kernel truncates process names (15 or 16 characters).
			return p.Name != "" && strings.HasPrefix(self, p.Name)
		}
	}
	return false
}

func groupProcs(gid int) []procInfo {
	procs, err := sysListProcs()
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var out []procInfo
	for _, p := range procs {
		if p.RGID == gid && p.PID != self && p.PID > 1 {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// killGroupProcs asks the tunneled processes to quit and forces whatever is
// still there after the grace period.
func killGroupProcs(gid int, grace time.Duration) {
	procs := groupProcs(gid)
	if len(procs) == 0 {
		return
	}
	for _, p := range procs {
		syscall.Kill(p.PID, syscall.SIGTERM)
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if len(groupProcs(gid)) == 0 {
			return
		}
	}
	for _, p := range groupProcs(gid) {
		syscall.Kill(p.PID, syscall.SIGKILL)
	}
	time.Sleep(200 * time.Millisecond)
}

func stopDaemon(pid int) {
	if !isDaemon(pid) {
		return
	}
	syscall.Kill(pid, syscall.SIGTERM)
	for i := 0; i < 50 && isAlive(pid); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if isAlive(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		time.Sleep(200 * time.Millisecond)
	}
}

// releaseSystem undoes the system changes recorded in st. While processes of
// the tunnel group are still running (and force is false) it leaves only the
// kill switch loaded, with pf still enabled, so they stay offline instead of
// silently falling back to the normal connection; the next "up" or "down"
// finishes the cleanup.
func releaseSystem(st *tunnelState, stateDir string, force bool) {
	sysRestoreTSO(st.TSOPrev)
	st.TSOPrev = ""

	if !force && len(groupProcs(st.GID)) > 0 {
		if err := sysFirewallKillSwitch(st.GID, stateDir); err == nil {
			st.PID = 0
			st.Ifname = ""
			st.KillSwitchOnly = true
			writeState(stateDir, st)
			os.Remove(filepath.Join(stateDir, statsFile))
			return
		}
	}
	sysFirewallDown(st.PFToken)
	removeState(stateDir)
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this command must run as root (sudo)")
	}
	return nil
}

// cmdUp starts the tunnel daemon in the background and waits until it reports
// that the tunnel is usable.
func cmdUp(args []string) error {
	opts, err := parseTunnelFlags("up", args)
	if err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if _, err := parseConfFile(opts.conf); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(opts.conf), err)
	}
	if err := os.MkdirAll(opts.stateDir, 0o755); err != nil {
		return err
	}
	os.Chmod(opts.stateDir, 0o755)

	// A previous daemon is stopped first. What it leaves behind (the kill
	// switch while tunneled processes still run, or everything after a crash)
	// is handed over to the new daemon instead of being undone here, so those
	// processes are never released onto the normal connection in between.
	old := readState(opts.stateDir)
	if old != nil {
		stopDaemon(old.PID)
		old = readState(opts.stateDir)
	}
	gid := opts.gid
	if gid <= 0 {
		if old != nil && old.GID > 0 {
			gid = old.GID
		} else {
			gid = pickGID()
		}
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	logOut, err := os.OpenFile(filepath.Join(opts.stateDir, logFile), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer logOut.Close()
	logOut.Chmod(0o644)
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readyR.Close()

	serveArgs := []string{"serve",
		"--conf", opts.conf,
		"--mtu", strconv.Itoa(opts.mtu),
		"--gid", strconv.Itoa(gid),
		"--state-dir", opts.stateDir,
		"--handshake-timeout", opts.handshakeTimeout.String(),
	}
	if opts.keepTSO {
		serveArgs = append(serveArgs, "--keep-tso")
	}
	if opts.verbose {
		serveArgs = append(serveArgs, "--verbose")
	}
	if old != nil {
		if old.PFToken != "" {
			serveArgs = append(serveArgs, "--inherit-token", old.PFToken)
		}
		if old.TSOPrev != "" {
			serveArgs = append(serveArgs, "--inherit-tso", old.TSOPrev)
		}
	}

	cmd := exec.Command(self, serveArgs...)
	cmd.Stdout = logOut
	cmd.Stderr = logOut
	cmd.ExtraFiles = []*os.File{readyW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Dir = "/"
	if err := cmd.Start(); err != nil {
		readyW.Close()
		return err
	}
	readyW.Close()
	pid := cmd.Process.Pid
	cmd.Process.Release()

	result := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(readyR).ReadString('\n')
		result <- strings.TrimSpace(line)
	}()

	select {
	case line := <-result:
		if line == "OK" {
			st := readState(opts.stateDir)
			if st == nil {
				return errors.New("tunnel started but left no state file")
			}
			fmt.Printf("READY ifname=%s gid=%d address=%s endpoint=%s\n", st.Ifname, st.GID, st.Address, st.Endpoint)
			return nil
		}
		if msg, ok := strings.CutPrefix(line, "ERR "); ok {
			return errors.New(msg)
		}
		return fmt.Errorf("tunnel daemon exited before the tunnel was ready (see %s)", filepath.Join(opts.stateDir, logFile))
	case <-time.After(opts.handshakeTimeout + 20*time.Second):
		syscall.Kill(pid, syscall.SIGTERM)
		return errors.New("timed out waiting for the tunnel daemon")
	}
}

// cmdServe is the daemon itself: it owns the tunnel interface and the system
// changes for as long as it runs.
func cmdServe(args []string) error {
	opts, err := parseTunnelFlags("serve", args)
	if err != nil {
		return err
	}
	ready := os.NewFile(3, "ready")
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)

	st := &tunnelState{
		PID:       os.Getpid(),
		GID:       opts.gid,
		MTU:       opts.mtu,
		PFToken:   opts.inheritToken,
		TSOPrev:   opts.inheritTSO,
		StartedAt: time.Now().Unix(),
	}
	var dev *device.Device
	fail := func(err error) error {
		fmt.Println("error:", err)
		if dev != nil {
			dev.Close()
		}
		releaseSystem(st, opts.stateDir, false)
		if ready != nil {
			fmt.Fprintf(ready, "ERR %s\n", err)
			ready.Close()
		}
		return err
	}

	conf, err := parseConfFile(opts.conf)
	if err != nil {
		return fail(err)
	}
	endpoint, err := resolveEndpoint(conf.Endpoint)
	if err != nil {
		return fail(err)
	}
	st.Address = conf.Address.String()
	st.Endpoint = endpoint

	tdev, err := tun.CreateTUN(tunInterfaceName, opts.mtu)
	if err != nil {
		return fail(fmt.Errorf("could not create the tunnel interface: %w", err))
	}
	ifname, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return fail(err)
	}
	st.Ifname = ifname

	level := device.LogLevelError
	if opts.verbose {
		level = device.LogLevelVerbose
	}
	nat := newNATDevice(tdev, conf.Address.As4(), opts.mtu)
	dev = device.NewDevice(nat, conn.NewDefaultBind(), device.NewLogger(level, "("+ifname+") "))
	if err := dev.IpcSet(conf.uapi(endpoint)); err != nil {
		return fail(fmt.Errorf("WireGuard rejected the profile: %w", err))
	}
	if err := sysConfigureInterface(ifname, conf.Address, opts.mtu); err != nil {
		return fail(err)
	}
	if !opts.keepTSO {
		prev, err := sysDisableTSO()
		if err != nil {
			fmt.Println("warning: could not disable TCP segmentation offload:", err)
		} else if st.TSOPrev == "" {
			st.TSOPrev = prev
		}
	}

	token, err := sysFirewallUp(ifname, conf.Address, opts.gid, opts.stateDir)
	if token != "" {
		// The new reference is held before the inherited one is given back,
		// so pf never switches off in between.
		if st.PFToken != token {
			sysReleaseToken(st.PFToken)
		}
		st.PFToken = token
	}
	if err != nil {
		return fail(err)
	}

	if err := dev.Up(); err != nil {
		return fail(fmt.Errorf("could not bring the tunnel up: %w", err))
	}
	if !waitHandshake(dev, opts.handshakeTimeout) {
		return fail(fmt.Errorf("no WireGuard handshake with %s after %s (server unreachable, UDP blocked, or the key is not accepted)",
			endpoint, opts.handshakeTimeout))
	}

	if err := writeState(opts.stateDir, st); err != nil {
		return fail(err)
	}
	writeStats(opts.stateDir, dev, nat)
	fmt.Printf("tunnel up: %s -> %s, group %d\n", ifname, endpoint, opts.gid)
	if ready != nil {
		fmt.Fprintln(ready, "OK")
		ready.Close()
		ready = nil
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-term:
			break loop
		case <-dev.Wait():
			break loop
		case <-ticker.C:
			writeStats(opts.stateDir, dev, nat)
		}
	}

	dev.Close()
	releaseSystem(st, opts.stateDir, false)
	fmt.Println("tunnel down")
	return nil
}

// deviceCounters reads the peer's handshake time and byte counters.
func deviceCounters(dev *device.Device) (handshake int64, rx, tx uint64) {
	text, err := dev.IpcGet()
	if err != nil {
		return 0, 0, 0
	}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "last_handshake_time_sec":
			handshake, _ = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			rx, _ = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			tx, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	return handshake, rx, tx
}

func waitHandshake(dev *device.Device, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if handshake, _, _ := deviceCounters(dev); handshake > 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func writeStats(stateDir string, dev *device.Device, nat *natDevice) {
	handshake, rx, tx := deviceCounters(dev)
	writeJSON(filepath.Join(stateDir, statsFile), &tunnelStats{
		UpdatedAt:     time.Now().Unix(),
		HandshakeUnix: handshake,
		RxBytes:       rx,
		TxBytes:       tx,
		NAT:           nat.stats(),
	})
}

// cmdDown closes the tunneled processes, stops the daemon and removes every
// system change, whatever state a previous run left behind.
func cmdDown(args []string) error {
	opts, err := parseTunnelFlags("down", args)
	if err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	st := readState(opts.stateDir)
	killGroupProcs(currentGID(opts.stateDir, opts.gid), 3*time.Second)
	if st != nil {
		stopDaemon(st.PID)
	}
	// A daemon that stopped cleanly has removed its own state; anything still
	// on disk comes from a crash or from kill-switch mode.
	if st = readState(opts.stateDir); st != nil {
		releaseSystem(st, opts.stateDir, true)
	} else {
		sysFirewallDown("")
	}
	removeState(opts.stateDir)
	fmt.Println("DOWN")
	return nil
}

// cmdStatus prints the tunnel state as key=value lines. It needs no
// privileges. The exit status is 0 only while the daemon is running.
func cmdStatus(args []string) (bool, error) {
	opts, err := parseTunnelFlags("status", args)
	if err != nil {
		return false, err
	}
	st := readState(opts.stateDir)
	running := st != nil && isDaemon(st.PID)
	fmt.Printf("running=%d\n", boolInt(running))
	gid := currentGID(opts.stateDir, opts.gid)
	fmt.Printf("gid=%d\n", gid)
	if st != nil {
		fmt.Printf("kill_switch_only=%d\n", boolInt(st.KillSwitchOnly))
		if running {
			fmt.Printf("ifname=%s\naddress=%s\nendpoint=%s\nmtu=%d\n", st.Ifname, st.Address, st.Endpoint, st.MTU)
		}
	}
	if running {
		if data, err := os.ReadFile(filepath.Join(opts.stateDir, statsFile)); err == nil {
			var stats tunnelStats
			if json.Unmarshal(data, &stats) == nil {
				age := int64(-1)
				if stats.HandshakeUnix > 0 {
					age = time.Now().Unix() - stats.HandshakeUnix
				}
				fmt.Printf("handshake_age=%d\nrx_bytes=%d\ntx_bytes=%d\n", age, stats.RxBytes, stats.TxBytes)
				fmt.Printf("nat_out=%d\nnat_in=%d\nnat_dropped=%d\nmss_clamped=%d\nflows=%d\n",
					stats.NAT.Out, stats.NAT.In, stats.NAT.Dropped, stats.NAT.Clamped, stats.NAT.Flows)
			}
		}
	}
	var pids []string
	for _, p := range groupProcs(gid) {
		pids = append(pids, strconv.Itoa(p.PID))
	}
	fmt.Printf("tunneled_processes=%d\npids=%s\n", len(pids), strings.Join(pids, ","))
	return running, nil
}

// cmdPids lists the processes running under the tunnel group. The exit status
// is 0 only when there is at least one.
func cmdPids(args []string) (bool, error) {
	opts, err := parseTunnelFlags("pids", args)
	if err != nil {
		return false, err
	}
	procs := groupProcs(currentGID(opts.stateDir, opts.gid))
	for _, p := range procs {
		fmt.Printf("%d %s\n", p.PID, p.Name)
	}
	return len(procs) > 0, nil
}

func cmdKill(args []string) error {
	opts, err := parseTunnelFlags("kill", args)
	if err != nil {
		return err
	}
	killGroupProcs(currentGID(opts.stateDir, opts.gid), 3*time.Second)
	return nil
}

func cmdGID(args []string) error {
	opts, err := parseTunnelFlags("gid", args)
	if err != nil {
		return err
	}
	fmt.Println(currentGID(opts.stateDir, opts.gid))
	return nil
}

// cmdDiag prints everything needed to understand a tunnel that does not work.
func cmdDiag(args []string) error {
	opts, err := parseTunnelFlags("diag", args)
	if err != nil {
		return err
	}
	fmt.Printf("ardc-tunnel %s\n", version)
	fmt.Println("\n--- status")
	cmdStatus(args)
	st := readState(opts.stateDir)
	sysDiag(os.Stdout, st)
	fmt.Println("\n--- daemon log")
	if data, err := os.ReadFile(filepath.Join(opts.stateDir, logFile)); err == nil {
		os.Stdout.Write(data)
	} else {
		fmt.Println("(no log)")
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
