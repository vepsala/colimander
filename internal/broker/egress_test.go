package broker

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vepsala/colimander/internal/egress"
)

func TestSummaryTotalsByDestination(t *testing.T) {
	shortHome(t)
	b := &broker{auditPath: auditFile()}
	b.recordFlow(egress.Flow{Profile: "a", Host: "api.example.test", Port: "443", BytesOut: 100, BytesIn: 5})
	b.recordFlow(egress.Flow{Profile: "a", Host: "api.example.test", Port: "443", BytesOut: 50, BytesIn: 5})
	b.recordFlow(egress.Flow{Profile: "a", Host: "big.example.test", Port: "443", BytesOut: 900})
	b.recordFlow(egress.Flow{Profile: "a", Port: "443", Err: "no destination name"})
	b.recordFlow(egress.Flow{Profile: "b", Host: "other.example.test", Port: "80", BytesOut: 1})

	got, err := egressSummary("a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Destination != "big.example.test:443" {
		t.Fatalf("summary = %+v", got)
	}
	if got[1].Connections != 2 || got[1].BytesOut != 150 || got[1].BytesIn != 10 {
		t.Errorf("totals = %+v", got[1])
	}
	if got[2].Destination != "(no name):443" || got[2].Errors != 1 {
		t.Errorf("no-name flow = %+v", got[2])
	}
	if all, _ := egressSummary(""); len(all) != 4 {
		t.Errorf("all sandboxes = %d", len(all))
	}
}

func TestDaemonFollowsPolicyForListeners(t *testing.T) {
	shortHome(t)
	if err := SavePolicy("demo", &Policy{Version: PolicyVersion, Handle: "h", EgressPort: 18990}); err != nil {
		t.Fatal(err)
	}
	b := &broker{auditPath: auditFile()}
	stop := b.serveEgress()
	defer stop()
	if err := waitForPort(18991, 2*time.Second); err != nil {
		t.Fatalf("HTTP listener: %v", err)
	}
	if got := nextEgressPort(); got != firstEgressPort {
		t.Errorf("next port = %d", got)
	}
}

func TestTotalsSurviveRotationAndCountOnce(t *testing.T) {
	shortHome(t)
	b := &broker{auditPath: auditFile()}
	b.recordFlow(egress.Flow{Profile: "a", Host: "x.test", Port: "443", BytesOut: 10})
	var totals egressTotals
	if got, err := totals.get(auditFile(), "a"); err != nil || got[0].BytesOut != 10 {
		t.Fatalf("first: %+v, %v", got, err)
	}
	if err := os.Rename(auditFile(), auditFile()+".1"); err != nil {
		t.Fatal(err)
	}
	b.recordFlow(egress.Flow{Profile: "a", Host: "x.test", Port: "443", BytesOut: 5})
	got, err := totals.get(auditFile(), "a")
	if err != nil || got[0].BytesOut != 15 || got[0].Connections != 2 {
		t.Errorf("running totals: %+v, %v", got, err)
	}
	if fresh, _ := egressSummary("a"); fresh[0].BytesOut != 15 {
		t.Errorf("after restart: %+v", fresh)
	}
}

func TestRotateAuditKeepsOneOldFile(t *testing.T) {
	shortHome(t)
	path := auditFile()
	if err := os.WriteFile(path, make([]byte, maxAuditSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	rotateAudit(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("log should have moved: %v", err)
	}
	if info, err := os.Stat(path + ".1"); err != nil || info.Size() != maxAuditSize+1 {
		t.Errorf("rotated: %v", err)
	}
}

func TestTailStartsAtAWholeLine(t *testing.T) {
	shortHome(t)
	b := &broker{auditPath: auditFile()}
	long := strings.Repeat("x", 1000)
	for i := 0; i < (auditTailSize/1000)+50; i++ {
		b.recordFlow(egress.Flow{Profile: "a", Host: long, Port: "443"})
	}
	got, err := readAuditTail(auditFile())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0].Profile != "a" {
		t.Errorf("tail = %d entries", len(got))
	}
}

func TestParseOtherTraffic(t *testing.T) {
	in := "p6363\nf12\nn192.168.1.102:59660->1.1.1.1:443\nf13\nn192.168.1.102:5000->140.82.1.1:22\nf14\nn192.168.1.102:5001->192.168.1.5:5432\nf15\nn[fe80::1]:1->[2606:4700::1]:443\n"
	got := parseLsofRemotes(in)
	if len(got) != 3 || got[0] != "1.1.1.1:443" || got[1] != "140.82.1.1:22" || got[2] != "[2606:4700::1]:443" {
		t.Errorf("remotes = %v", got)
	}
}
