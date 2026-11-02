package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const (
	// maxAuditSize is when the log moves to audit.log.1, replacing the previous one.
	maxAuditSize = 50 << 20
	// auditTailSize bounds what a request for recent events reads.
	auditTailSize = 4 << 20
)

func rotateAudit(path string) {
	if info, err := os.Stat(path); err == nil && info.Size() > maxAuditSize {
		_ = os.Rename(path, path+".1")
	}
}

// readAuditTail returns the entries in the last part of the log.
func readAuditTail(path string) ([]auditEntry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var skipped bool
	if info.Size() > auditTailSize {
		if _, err := f.Seek(-auditTailSize, io.SeekEnd); err != nil {
			return nil, err
		}
		skipped = true
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if skipped { // the read probably began mid-line
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	var out []auditEntry
	for _, line := range bytes.Split(data, []byte("\n")) {
		var e auditEntry
		if len(line) > 0 && json.Unmarshal(line, &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}
