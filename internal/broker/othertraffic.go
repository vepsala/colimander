package broker

import (
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

const otherTrafficTick = 5 * time.Second

// OtherConnection is an address VMs connected to outside egress monitoring.
type OtherConnection struct {
	Remote    string    `json:"remote"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// otherTraffic watches Lima's shared network process on the Mac. Traffic the
// forwarder relays leaves from the daemon instead, so what's left here didn't go
// through monitoring. Rules inside a VM can't hide it, but the process is shared
// by all VMs, so it can't say which one, and it's only sampled. It also doesn't
// see a VM's second route (col0), which doesn't use this process.
type otherTraffic struct {
	mu   sync.Mutex
	seen map[string]*OtherConnection
}

func (o *otherTraffic) watch() (stop func()) {
	done := make(chan struct{})
	go func() {
		for {
			o.sample()
			select {
			case <-done:
				return
			case <-time.After(otherTrafficTick):
			}
		}
	}()
	return func() { close(done) }
}

func (o *otherTraffic) sample() {
	pid, err := exec.Command("pgrep", "-f", "limactl usernet").Output()
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, p := range strings.Fields(string(pid)) {
		// lsof exits non-zero when there's nothing to list.
		out, _ := exec.Command("lsof", "-nP", "-a", "-p", p, "-iTCP", "-sTCP:ESTABLISHED", "-Fn").Output()
		o.note(parseLsofRemotes(string(out)), now)
	}
}

func (o *otherTraffic) note(remotes []string, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen == nil {
		o.seen = map[string]*OtherConnection{}
	}
	for _, r := range remotes {
		if c := o.seen[r]; c != nil {
			c.LastSeen = now
		} else {
			o.seen[r] = &OtherConnection{Remote: r, FirstSeen: now, LastSeen: now}
		}
	}
}

func (o *otherTraffic) list() []OtherConnection {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]OtherConnection, 0, len(o.seen))
	for _, c := range o.seen {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// parseLsofRemotes pulls public remote addresses from `lsof -Fn` output.
func parseLsofRemotes(out string) []string {
	var remotes []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "n") {
			continue
		}
		_, remote, ok := strings.Cut(line, "->")
		if !ok {
			continue
		}
		host, _, err := net.SplitHostPort(remote)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		remotes = append(remotes, remote)
	}
	return remotes
}
