// Package egress records where a sandbox's web traffic goes. Firewall rules in
// the VM send outbound ports 443 and 80 to per-sandbox ports on the Mac, where
// Forwarder reads the destination name, connects onward and counts bytes.
//
// It never decrypts anything, so it knows where data went and how much, not what
// it was. Root in the VM can remove the rules, and other ports aren't captured.
package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// maxPeek bounds how much of a connection is buffered to find its destination.
const maxPeek = 64 << 10

const peekTimeout = 10 * time.Second

// Flow describes one finished connection.
type Flow struct {
	Profile  string
	Host     string // empty when the client didn't name a destination
	Port     string
	BytesOut int64
	BytesIn  int64
	Duration time.Duration
	Err      string
}

// Forwarder relays one sandbox's connections for one destination port.
type Forwarder struct {
	Profile string
	Port    string // "443" reads the TLS server name; "80" the HTTP Host header
	Record  func(Flow)
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error) // tests only

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// Serve accepts until ln closes.
func (f *Forwarder) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go f.handle(c)
	}
}

func (f *Forwarder) handle(c net.Conn) {
	defer c.Close()
	start := time.Now()
	flow := Flow{Profile: f.Profile, Port: f.Port}
	defer func() {
		flow.Duration = time.Since(start)
		if f.Record != nil {
			f.Record(flow)
		}
	}()

	var seen bytes.Buffer
	_ = c.SetReadDeadline(time.Now().Add(peekTimeout))
	tee := io.TeeReader(io.LimitReader(c, maxPeek), &seen)
	if f.Port == "443" {
		flow.Host = serverName(tee)
	} else {
		flow.Host = httpHost(tee)
	}
	_ = c.SetReadDeadline(time.Time{})
	if flow.Host == "" {
		flow.Err = "no destination name"
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dial := f.Dial
	if dial == nil {
		dial = publicDialer.DialContext
	}
	up, err := dial(ctx, "tcp", net.JoinHostPort(flow.Host, f.Port))
	if err != nil {
		flow.Err = err.Error()
		return
	}
	defer up.Close()

	var out, in atomic.Int64
	n, err := up.Write(seen.Bytes())
	out.Add(int64(n))
	if err != nil {
		flow.Err = err.Error()
		flow.BytesOut = out.Load()
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, _ := io.Copy(up, c)
		out.Add(n)
		closeWrite(up)
	}()
	n2, _ := io.Copy(c, up)
	in.Add(n2)
	closeWrite(c)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second)) // the client may not hang up
	<-done
	flow.BytesOut, flow.BytesIn = out.Load(), in.Load()
}

func closeWrite(c net.Conn) {
	if t, ok := c.(interface{ CloseWrite() error }); ok {
		_ = t.CloseWrite()
	}
}

// serverName reads a TLS ClientHello far enough to get its server name.
func serverName(r io.Reader) string {
	var name string
	_ = tls.Server(readOnlyConn{r}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name = h.ServerName
			return nil, errors.New("stop after hello")
		},
	}).Handshake()
	return name
}

// httpHost reads an HTTP request's Host, without any port: the forwarder always
// connects to its own port, so a client can't use it to reach another service.
func httpHost(r io.Reader) string {
	req, err := http.ReadRequest(bufio.NewReader(r))
	if err != nil {
		return ""
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

// publicDialer won't connect to the Mac itself. A sandbox names the destination,
// so "localhost" must not become a way to reach services on the host.
var publicDialer = &net.Dialer{Control: refuseLocal}

func refuseLocal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("refusing to connect to %s", host)
	}
	return nil
}

// readOnlyConn lets crypto/tls parse a ClientHello without answering it.
type readOnlyConn struct{ r io.Reader }

func (c readOnlyConn) Read(b []byte) (int, error)     { return c.r.Read(b) }
func (readOnlyConn) Write(b []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                     { return nil }
func (readOnlyConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (readOnlyConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

// HostAddr is the Mac as seen from a Lima VM.
const HostAddr = "192.168.5.2"

// Rules returns the nftables ruleset for a sandbox whose forwarder listens on
// port (HTTPS) and port+1 (HTTP). Private destinations are left alone. Both
// hooks are needed: output covers the VM, prerouting covers its containers. QUIC
// is rejected so clients fall back to TCP, which is what gets recorded.
func Rules(port int) string {
	const private = "{ 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 }"
	nat := fmt.Sprintf(`ip daddr %s return
    tcp dport 443 dnat to %s:%d
    tcp dport 80 dnat to %s:%d`, private, HostAddr, port, HostAddr, port+1)
	return fmt.Sprintf(`table ip colimander_egress
delete table ip colimander_egress
table ip colimander_egress {
  chain vm {
    type nat hook output priority -100;
    %s
  }
  chain containers {
    type nat hook prerouting priority -100;
    %s
  }
  chain vm_quic {
    type filter hook output priority 0;
    ip daddr != %s udp dport 443 reject
  }
  chain containers_quic {
    type filter hook forward priority 0;
    ip daddr != %s udp dport 443 reject
  }
}
`, nat, nat, private, private)
}

// RemoveRules returns the ruleset that takes the rules away again.
func RemoveRules() string {
	return "table ip colimander_egress\ndelete table ip colimander_egress\n"
}
