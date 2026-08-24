package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAuditFrom(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	line1 := `{"time":"2026-08-24T08:00:00Z","profile":"bg-backend","surface":"GIT","method":"GET","path":"/o/r.git/info/refs","action":"ALLOW","detail":"upstream=200"}` + "\n"
	line2 := `{"time":"2026-08-24T08:00:01Z","profile":"bg-backend","surface":"GIT","method":"POST","path":"/o/r.git/git-receive-pack","action":"DENY","detail":"no-push"}` + "\n"

	// Missing file is not an error — just no entries yet.
	entries, off, err := readAuditFrom(path, 0)
	if err != nil || len(entries) != 0 || off != 0 {
		t.Fatalf("missing file: got %d entries, off %d, err %v", len(entries), off, err)
	}

	if err := os.WriteFile(path, []byte(line1), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, off, err = readAuditFrom(path, 0)
	if err != nil || len(entries) != 1 || entries[0].Action != "ALLOW" {
		t.Fatalf("first read: got %d entries, err %v", len(entries), err)
	}

	// A partial trailing line must be left for the next poll.
	if err := os.WriteFile(path, []byte(line1+`{"time":"2026-08-`), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, off2, err := readAuditFrom(path, off)
	if err != nil || len(entries) != 0 || off2 != off {
		t.Fatalf("partial line: got %d entries, off %d→%d, err %v", len(entries), off, off2, err)
	}

	// Once completed, only the new entry comes back.
	if err := os.WriteFile(path, []byte(line1+line2), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, off, err = readAuditFrom(path, off)
	if err != nil || len(entries) != 1 || entries[0].Action != "DENY" {
		t.Fatalf("incremental read: got %d entries, err %v", len(entries), err)
	}
	if off != int64(len(line1)+len(line2)) {
		t.Fatalf("offset: got %d, want %d", off, len(line1)+len(line2))
	}

	// Truncation/rotation: file shrank below offset → reread from start.
	if err := os.WriteFile(path, []byte(line2), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, _, err = readAuditFrom(path, off)
	if err != nil || len(entries) != 1 || entries[0].Action != "DENY" {
		t.Fatalf("after rotation: got %d entries, err %v", len(entries), err)
	}
}
