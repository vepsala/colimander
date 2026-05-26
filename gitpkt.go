// Minimal git pkt-line parser, just enough to spot ref-deletions inside a
// git-receive-pack request body.
//
// A receive-pack body is a sequence of pkt-lines followed by 0000 (flush)
// and then a packfile. Each pkt-line begins with 4 hex chars giving its total
// length (including the 4 hex chars themselves). Within the command portion
// each pkt-line looks like:
//
//	"<old-sha> <new-sha> <ref>\n"
//
// with the first one carrying capabilities appended after a NUL byte:
//
//	"<old> <new> <ref>\x00 report-status ...\n"
//
// A ref deletion is the special case where <new-sha> is all-zeros.

package main

import "strings"

const zeroSha = "0000000000000000000000000000000000000000"

type refUpdate struct {
	Old string
	New string
	Ref string
}

// isDelete reports whether the update is a ref deletion (new = 40 zero chars).
func (u refUpdate) isDelete() bool { return u.New == zeroSha }

// parseReceivePackCommands scans the leading pkt-lines of a git-receive-pack
// body and returns the ref updates. Stops at the flush packet ("0000") or at
// any malformed input, returning what it has so far. The packfile that
// follows is intentionally ignored — we only inspect the command list, which
// is enough to enforce "don't delete refs/heads/main" policies.
func parseReceivePackCommands(body []byte) []refUpdate {
	var updates []refUpdate
	pos := 0
	for pos+4 <= len(body) {
		lenHex := string(body[pos : pos+4])
		if lenHex == "0000" {
			break
		}
		lineLen, ok := parseHex4(lenHex)
		if !ok || lineLen < 4 || pos+lineLen > len(body) {
			break
		}
		payload := string(body[pos+4 : pos+lineLen])
		pos += lineLen

		// Strip trailing LF if present.
		payload = strings.TrimRight(payload, "\n")
		// Strip capabilities (everything after a NUL).
		if i := strings.IndexByte(payload, 0); i >= 0 {
			payload = payload[:i]
		}
		parts := strings.SplitN(payload, " ", 3)
		if len(parts) != 3 {
			continue
		}
		updates = append(updates, refUpdate{Old: parts[0], New: parts[1], Ref: parts[2]})
	}
	return updates
}

func parseHex4(s string) (int, bool) {
	if len(s) != 4 {
		return 0, false
	}
	n := 0
	for i := 0; i < 4; i++ {
		c := s[i]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return 0, false
		}
		n = n*16 + d
	}
	return n, true
}
