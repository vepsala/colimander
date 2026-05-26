package main

import (
	"fmt"
	"testing"
)

// pkt builds a single pkt-line for testing: 4-char hex length + payload.
func pkt(payload string) []byte {
	line := payload
	total := 4 + len(line)
	return []byte(fmt.Sprintf("%04x%s", total, line))
}

func flushPkt() []byte { return []byte("0000") }

func TestParseReceivePackCommands_SimplePush(t *testing.T) {
	old := "1111111111111111111111111111111111111111"
	new := "2222222222222222222222222222222222222222"
	// First pkt-line carries capabilities after a NUL.
	body := []byte{}
	body = append(body, pkt(old+" "+new+" refs/heads/main\x00 report-status side-band-64k\n")...)
	body = append(body, flushPkt()...)
	body = append(body, []byte("PACK...")...) // packfile is ignored

	got := parseReceivePackCommands(body)
	if len(got) != 1 {
		t.Fatalf("got %d updates, want 1", len(got))
	}
	if got[0].Old != old || got[0].New != new || got[0].Ref != "refs/heads/main" {
		t.Fatalf("update parsed wrong: %+v", got[0])
	}
	if got[0].isDelete() {
		t.Errorf("regular push should not be a delete")
	}
}

func TestParseReceivePackCommands_DeleteRef(t *testing.T) {
	old := "1111111111111111111111111111111111111111"
	body := []byte{}
	body = append(body, pkt(old+" "+zeroSha+" refs/heads/main\x00 report-status\n")...)
	body = append(body, flushPkt()...)

	got := parseReceivePackCommands(body)
	if len(got) != 1 {
		t.Fatalf("got %d updates, want 1", len(got))
	}
	if !got[0].isDelete() {
		t.Errorf("expected isDelete() true for zero new-sha; got %+v", got[0])
	}
	if got[0].Ref != "refs/heads/main" {
		t.Errorf("ref parsed wrong: %q", got[0].Ref)
	}
}

func TestParseReceivePackCommands_MultipleRefs(t *testing.T) {
	a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	body := []byte{}
	body = append(body, pkt(a+" "+b+" refs/heads/main\x00 report-status\n")...)
	body = append(body, pkt(a+" "+zeroSha+" refs/heads/feature/x\n")...)
	body = append(body, flushPkt()...)

	got := parseReceivePackCommands(body)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].isDelete() {
		t.Errorf("first should not be delete")
	}
	if !got[1].isDelete() {
		t.Errorf("second should be delete")
	}
}

func TestParseReceivePackCommands_Malformed(t *testing.T) {
	// Just garbage — parser should return empty.
	got := parseReceivePackCommands([]byte("not even close to a pkt-line"))
	if len(got) != 0 {
		t.Errorf("expected empty parse for garbage; got %+v", got)
	}
}
