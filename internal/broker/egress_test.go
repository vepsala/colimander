package broker

import (
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
