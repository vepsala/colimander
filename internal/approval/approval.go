// Package approval decides whether a gated statement may proceed.
package approval

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kotisivukamu/pg-agent-proxy/internal/config"
)

// Reason describes why a statement was gated.
type Reason string

const (
	// ReasonMutation is a write/DDL statement.
	ReasonMutation Reason = "mutation"
	// ReasonLargeRead is a read returning more rows than the configured limit.
	ReasonLargeRead Reason = "large_read"
)

// Request is the payload describing a statement awaiting approval.
type Request struct {
	ID        string `json:"id"`
	Reason    Reason `json:"reason"`
	Statement string `json:"statement"`
	Query     string `json:"query"`
	RowCount  int    `json:"row_count,omitempty"`
	Client    string `json:"client"`
}

// Decision is the outcome of an approval request.
type Decision struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
}

// Approver decides whether a gated request may proceed. Implementations must
// fail closed (deny) on error or timeout.
type Approver interface {
	Approve(ctx context.Context, req Request) Decision
}

// New builds an Approver from configuration.
func New(cfg config.ApprovalConfig) Approver {
	switch cfg.Mode {
	case "auto_approve":
		return staticApprover{decision: Decision{Approved: true, Reason: "auto_approve"}}
	case "auto_deny":
		return staticApprover{decision: Decision{Approved: false, Reason: "auto_deny"}}
	case "dashboard":
		return NewBroker(cfg.Timeout)
	default: // "http"
		return &httpApprover{
			url:     cfg.URL,
			timeout: cfg.Timeout,
			client:  &http.Client{},
		}
	}
}

// NewID returns a short random identifier for an approval request.
func NewID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-unknown"
	}
	return "req-" + hex.EncodeToString(b[:])
}

type staticApprover struct {
	decision Decision
}

func (s staticApprover) Approve(_ context.Context, _ Request) Decision {
	return s.decision
}

type httpApprover struct {
	url     string
	timeout time.Duration
	client  *http.Client
}

func (h *httpApprover) Approve(ctx context.Context, req Request) Decision {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	body, err := json.Marshal(req)
	if err != nil {
		return denied(fmt.Sprintf("encode request: %v", err))
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return denied(fmt.Sprintf("build request: %v", err))
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		// Timeout or connection failure: fail closed.
		return denied(fmt.Sprintf("approval endpoint unreachable: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return denied(fmt.Sprintf("approval endpoint returned %s", resp.Status))
	}

	var dec Decision
	if err := json.NewDecoder(resp.Body).Decode(&dec); err != nil {
		return denied(fmt.Sprintf("decode decision: %v", err))
	}
	return dec
}

func denied(reason string) Decision {
	return Decision{Approved: false, Reason: reason}
}
