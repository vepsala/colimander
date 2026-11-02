package egress

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// start runs a forwarder that sends every connection to target and returns its
// address and the flows it records.
func start(t *testing.T, port, target string) (string, <-chan Flow) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	flows := make(chan Flow, 4)
	f := &Forwarder{Profile: "demo", Port: port, Record: func(fl Flow) { flows <- fl }}
	if target != "" {
		f.Dial = func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, target)
		}
	}
	go f.Serve(ln)
	return ln.Addr().String(), flows
}

func wait(t *testing.T, flows <-chan Flow) Flow {
	t.Helper()
	select {
	case f := <-flows:
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("no flow recorded")
	}
	return Flow{}
}

func TestHTTPSRecordsNameAndBytesWithoutDecrypting(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer up.Close()
	addr, flows := start(t, "443", up.Listener.Addr().String())

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: "api.example.test"},
		DisableKeepAlives: true,
	}}
	resp, err := client.Post("https://"+addr+"/", "text/plain", strings.NewReader(strings.Repeat("y", 20000)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(body) != 5000 {
		t.Errorf("body = %d bytes", len(body))
	}
	f := wait(t, flows)
	if f.Host != "api.example.test" || f.Profile != "demo" || f.Port != "443" {
		t.Errorf("flow = %+v", f)
	}
	if f.BytesOut < 20000 || f.BytesIn < 5000 {
		t.Errorf("bytes out=%d in=%d", f.BytesOut, f.BytesIn)
	}
}

func TestHTTPRecordsHostWithoutItsPort(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer up.Close()
	addr, flows := start(t, "80", up.Listener.Addr().String())
	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	req.Host = "site.example.test:9999"
	req.Close = true
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if f := wait(t, flows); f.Host != "site.example.test" {
		t.Errorf("flow = %+v", f)
	}
}

func TestNoNameIsRecordedAndRefused(t *testing.T) {
	addr, flows := start(t, "443", "")
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		c.Close()
		t.Error("handshake should fail")
	}
	if f := wait(t, flows); f.Host != "" || f.Err == "" {
		t.Errorf("flow = %+v", f)
	}
}

func TestSandboxCantReachTheMacByName(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("forwarder reached a local service")
	}))
	defer local.Close()
	addr, flows := start(t, "80", "")
	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	req.Host = "localhost"
	req.Close = true
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	if f := wait(t, flows); !strings.Contains(f.Err, "refus") {
		t.Errorf("flow = %+v", f)
	}
}

func TestRulesExcludePrivateAndUsePerSandboxPorts(t *testing.T) {
	r := Rules(18800)
	for _, want := range []string{"192.168.5.2:18800", "192.168.5.2:18801", "192.168.0.0/16", "hook prerouting", "hook output", "udp dport 443 reject"} {
		if !strings.Contains(r, want) {
			t.Errorf("rules missing %q", want)
		}
	}
}
