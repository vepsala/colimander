package broker

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vepsala/colimander/internal/egress"
)

const (
	firstEgressPort     = 18800
	egressReconcileTick = 3 * time.Second
)

// serveEgress keeps a pair of listeners open for each sandbox with monitoring on,
// following policy files so `egress enable` needs no daemon restart.
func (b *broker) serveEgress() (stop func()) {
	done := make(chan struct{})
	go func() {
		open := map[string][]net.Listener{}
		defer func() {
			for _, ls := range open {
				closeAll(ls)
			}
		}()
		for {
			b.reconcileEgress(open)
			select {
			case <-done:
				return
			case <-time.After(egressReconcileTick):
			}
		}
	}()
	return func() { close(done) }
}

// reconcileEgress opens and closes listeners to match policy. A key includes the
// port, so a changed port is a close plus an open.
func (b *broker) reconcileEgress(open map[string][]net.Listener) {
	want := egressPorts()
	for key, ls := range open {
		if _, ok := want[key]; !ok {
			closeAll(ls)
			delete(open, key)
		}
	}
	for key, profile := range want {
		if _, ok := open[key]; ok {
			continue
		}
		_, portStr, _ := strings.Cut(key, "|")
		port, _ := strconv.Atoi(portStr)
		var ls []net.Listener
		for i, dst := range []string{"443", "80"} {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+i))
			if err != nil {
				log.Printf("egress %s: listen on %d: %v", profile, port+i, err)
				break
			}
			ls = append(ls, ln)
			f := &egress.Forwarder{Profile: profile, Port: dst, Record: b.recordFlow}
			go f.Serve(ln)
		}
		if len(ls) == 2 {
			open[key] = ls
		} else {
			closeAll(ls) // try again on the next tick
		}
	}
}

func closeAll(ls []net.Listener) {
	for _, l := range ls {
		l.Close()
	}
}

// egressPorts maps "profile|port" to the profile for every monitored sandbox.
func egressPorts() map[string]string {
	out := map[string]string{}
	for _, name := range policyProfiles() {
		if pol, err := LoadPolicy(name); err == nil && pol.EgressPort != 0 {
			out[fmt.Sprintf("%s|%d", name, pol.EgressPort)] = name
		}
	}
	return out
}

func policyProfiles() []string {
	home, _ := os.UserHomeDir()
	paths, _ := filepath.Glob(filepath.Join(home, ".colima", "*", "policy.json"))
	names := make([]string, 0, len(paths))
	for _, p := range paths {
		names = append(names, filepath.Base(filepath.Dir(p)))
	}
	return names
}

func (b *broker) recordFlow(f egress.Flow) {
	action := "ALLOW"
	if f.Err != "" {
		action = "ERROR"
	}
	host := f.Host
	if host == "" {
		host = "(no name)"
	}
	b.audit(auditEntry{
		Profile: f.Profile, Surface: "EGRESS", Method: "TCP", Path: host + ":" + f.Port, Action: action,
		Detail: f.Err, BytesOut: f.BytesOut, BytesIn: f.BytesIn,
	})
}

// EgressHost is one destination's totals in a summary.
type EgressHost struct {
	Profile     string    `json:"profile"`
	Destination string    `json:"destination"`
	Connections int       `json:"connections"`
	Errors      int       `json:"errors"`
	BytesOut    int64     `json:"bytes_out"`
	BytesIn     int64     `json:"bytes_in"`
	LastSeen    time.Time `json:"last_seen"`
}

// egressTotals keeps running totals, so the app's polling reads only what's new
// rather than the whole log every few seconds.
type egressTotals struct {
	mu     sync.Mutex
	path   string
	offset int64
	totals map[string]*EgressHost
}

// get returns totals by destination, most data sent first. An empty profile means
// every sandbox. The first read includes the rotated log.
func (t *egressTotals) get(path, profile string) ([]EgressHost, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.totals == nil || t.path != path {
		t.totals, t.path, t.offset = map[string]*EgressHost{}, path, 0
		old, _, err := readAuditFrom(path+".1", 0)
		if err != nil {
			t.totals = nil
			return nil, err
		}
		t.add(old)
	}
	entries, offset, err := readAuditFrom(path, t.offset)
	if err != nil {
		return nil, err
	}
	t.offset = offset
	t.add(entries)
	out := []EgressHost{}
	for _, h := range t.totals {
		if profile == "" || h.Profile == profile {
			out = append(out, *h)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BytesOut != out[j].BytesOut {
			return out[i].BytesOut > out[j].BytesOut
		}
		return out[i].Destination < out[j].Destination
	})
	return out, nil
}

func (t *egressTotals) add(entries []auditEntry) {
	for _, e := range entries {
		if e.Surface != "EGRESS" {
			continue
		}
		key := e.Profile + "|" + e.Path
		h := t.totals[key]
		if h == nil {
			h = &EgressHost{Profile: e.Profile, Destination: e.Path}
			t.totals[key] = h
		}
		h.Connections++
		if e.Action == "ERROR" {
			h.Errors++
		}
		h.BytesOut += e.BytesOut
		h.BytesIn += e.BytesIn
		if e.Time.After(h.LastSeen) {
			h.LastSeen = e.Time
		}
	}
}

func egressSummary(profile string) ([]EgressHost, error) {
	var t egressTotals
	return t.get(auditFile(), profile)
}

func nextEgressPort() int {
	used := map[int]bool{}
	for _, name := range policyProfiles() {
		if pol, err := LoadPolicy(name); err == nil && pol.EgressPort != 0 {
			used[pol.EgressPort] = true
		}
	}
	port := firstEgressPort
	for used[port] {
		port += 2
	}
	return port
}

const (
	egressRulesPath = "/etc/colimander/egress.nft"
	egressUnitPath  = "/etc/systemd/system/colimander-egress.service"
	egressUnit      = `[Unit]
Description=Colimander egress monitoring rules
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/colimander/egress.nft

[Install]
WantedBy=multi-user.target
`
)

func vmRoot(profile, stdin, script string) error {
	cmd := exec.Command("colima", "ssh", "-p", profile, "--", "sudo", "bash", "-c", script)
	cmd.Stdin = strings.NewReader(stdin)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func enableEgress(name string) error {
	pol, err := LoadPolicy(name)
	if err != nil {
		return fmt.Errorf("load policy for %q: %w", name, err)
	}
	if pol.EgressPort == 0 {
		pol.EgressPort = nextEgressPort()
		if err := SavePolicy(name, pol); err != nil {
			return err
		}
	}
	if err := ensureBrokerRunning(); err != nil {
		return err
	}
	// The rules send the VM's web traffic here, so don't apply them until the
	// daemon is really listening, or the sandbox would lose its internet.
	if err := waitForPort(pol.EgressPort, 2*egressReconcileTick+time.Second); err != nil {
		return fmt.Errorf("the daemon isn't listening on port %d, so the VM wasn't changed (is an older broker running? try `colimander broker stop`): %w", pol.EgressPort, err)
	}
	if err := vmRoot(name, egress.Rules(pol.EgressPort), "mkdir -p /etc/colimander && cat > "+egressRulesPath); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}
	if err := vmRoot(name, egressUnit, "cat > "+egressUnitPath+" && systemctl daemon-reload && systemctl enable -q colimander-egress && systemctl restart colimander-egress"); err != nil {
		return fmt.Errorf("apply rules: %w", err)
	}
	return nil
}

func disableEgress(name string) error {
	pol, err := LoadPolicy(name)
	if err != nil {
		return fmt.Errorf("load policy for %q: %w", name, err)
	}
	// Take the rules out first: while they're in, the VM needs the listeners.
	if err := vmRoot(name, egress.RemoveRules(), "nft -f - && systemctl disable -q colimander-egress; rm -f "+egressRulesPath+" "+egressUnitPath+"; systemctl daemon-reload"); err != nil {
		return fmt.Errorf("remove rules: %w", err)
	}
	pol.EgressPort = 0
	return SavePolicy(name, pol)
}

func waitForPort(port int, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// CmdEgress is `colimander egress {enable|disable|status} <name>`.
func CmdEgress(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: colimander egress {enable|disable|status} <name>")
	}
	name := args[1]
	switch args[0] {
	case "enable":
		if err := enableEgress(name); err != nil {
			return err
		}
		fmt.Printf("Recording web traffic from %q. Nothing is blocked. If the daemon stops, this VM loses HTTPS and HTTP until it's back or you run `colimander egress disable %s`.\n", name, name)
	case "disable":
		if err := disableEgress(name); err != nil {
			return err
		}
		fmt.Printf("Stopped recording web traffic from %q.\n", name)
	case "status":
		pol, err := LoadPolicy(name)
		if err != nil {
			return fmt.Errorf("load policy for %q: %w", name, err)
		}
		if pol.EgressPort == 0 {
			fmt.Printf("Egress monitoring is off for %q.\n", name)
		} else {
			fmt.Printf("Egress monitoring is on for %q (ports %d-%d).\n", name, pol.EgressPort, pol.EgressPort+1)
		}
		hosts, err := egressSummary(name)
		if err != nil {
			return err
		}
		if len(hosts) > 0 {
			fmt.Printf("\n%-44s %6s %10s %10s  %s\n", "DESTINATION", "CONNS", "SENT", "RECEIVED", "LAST SEEN")
		}
		for _, h := range hosts {
			fmt.Printf("%-44s %6d %10s %10s  %s\n", h.Destination, h.Connections, byteSize(h.BytesOut), byteSize(h.BytesIn), h.LastSeen.Local().Format("Jan 2 15:04"))
		}
	default:
		return fmt.Errorf("unknown egress command %q", args[0])
	}
	return nil
}

func byteSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
