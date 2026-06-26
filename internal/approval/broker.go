package approval

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Broker is an in-process Approver whose decisions are made from the admin
// dashboard. A gated statement blocks in Approve until a human decides via the
// admin UI, or until the timeout elapses (which denies, failing closed).
type Broker struct {
	mu      sync.Mutex
	pending map[string]*pendingReq
	timeout time.Duration
}

type pendingReq struct {
	req       Request
	createdAt time.Time
	decided   chan Decision
}

// PendingView is the admin-facing snapshot of a waiting request.
type PendingView struct {
	ID        string    `json:"id"`
	Reason    Reason    `json:"reason"`
	Statement string    `json:"statement"`
	Query     string    `json:"query"`
	RowCount  int       `json:"row_count,omitempty"`
	Client    string    `json:"client"`
	CreatedAt time.Time `json:"created_at"`
}

// NewBroker creates a dashboard-backed approver. timeout bounds how long a
// request waits for a human decision before being denied.
func NewBroker(timeout time.Duration) *Broker {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return &Broker{pending: map[string]*pendingReq{}, timeout: timeout}
}

// Approve registers the request as pending and blocks until it is decided in the
// dashboard, the context is cancelled, or the timeout elapses.
func (b *Broker) Approve(ctx context.Context, req Request) Decision {
	p := &pendingReq{req: req, createdAt: time.Now(), decided: make(chan Decision, 1)}

	b.mu.Lock()
	b.pending[req.ID] = p
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.pending, req.ID)
		b.mu.Unlock()
	}()

	timer := time.NewTimer(b.timeout)
	defer timer.Stop()

	select {
	case dec := <-p.decided:
		return dec
	case <-timer.C:
		return Decision{Approved: false, Reason: "timed out waiting for dashboard approval"}
	case <-ctx.Done():
		return Decision{Approved: false, Reason: "client disconnected"}
	}
}

// Pending returns the currently waiting requests, oldest first.
func (b *Broker) Pending() []PendingView {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]PendingView, 0, len(b.pending))
	for _, p := range b.pending {
		out = append(out, PendingView{
			ID:        p.req.ID,
			Reason:    p.req.Reason,
			Statement: p.req.Statement,
			Query:     p.req.Query,
			RowCount:  p.req.RowCount,
			Client:    p.req.Client,
			CreatedAt: p.createdAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Decide resolves a pending request. It returns false if no such request is
// waiting (e.g. it already timed out).
func (b *Broker) Decide(id string, approved bool, reason string) bool {
	b.mu.Lock()
	p, ok := b.pending[id]
	b.mu.Unlock()
	if !ok {
		return false
	}
	if reason == "" {
		if approved {
			reason = "approved in dashboard"
		} else {
			reason = "denied in dashboard"
		}
	}
	select {
	case p.decided <- Decision{Approved: approved, Reason: reason}:
		return true
	default:
		return false // already decided
	}
}
