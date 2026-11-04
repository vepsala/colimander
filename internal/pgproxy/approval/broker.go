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

	// version counts changes to pending, and changed is closed (and replaced)
	// on each one, which wakes every Watch at once.
	version uint64
	changed chan struct{}
}

type pendingReq struct {
	req       Request
	createdAt time.Time
	decided   chan Decision
}

// PendingView is the admin-facing snapshot of a waiting request.
type PendingView struct {
	ID         string    `json:"id"`
	Reason     Reason    `json:"reason"`
	Statement  string    `json:"statement"`
	Query      string    `json:"query"`
	RowCount   int       `json:"row_count,omitempty"`
	Client     string    `json:"client"`
	Connection string    `json:"connection"`
	Database   string    `json:"database"`
	CreatedAt  time.Time `json:"created_at"`
}

// NewBroker creates a dashboard-backed approver. timeout bounds how long a
// request waits for a human decision before being denied.
func NewBroker(timeout time.Duration) *Broker {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return &Broker{pending: map[string]*pendingReq{}, timeout: timeout, changed: make(chan struct{})}
}

// Approve registers the request as pending and blocks until it is decided in the
// dashboard, the context is cancelled, or the timeout elapses.
func (b *Broker) Approve(ctx context.Context, req Request) Decision {
	p := &pendingReq{req: req, createdAt: time.Now(), decided: make(chan Decision, 1)}

	b.mu.Lock()
	b.pending[req.ID] = p
	b.bumpLocked()
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.pending, req.ID)
		b.bumpLocked()
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

func (b *Broker) bumpLocked() {
	b.version++
	close(b.changed)
	b.changed = make(chan struct{})
}

// Watch waits until the set of pending requests differs from version after,
// or ctx ends, and returns the current version and count. Pass 0 the first
// time to get the current state at once. It lets a client keep a pending count
// up to date without polling.
func (b *Broker) Watch(ctx context.Context, after uint64) (version uint64, count int) {
	for {
		b.mu.Lock()
		version, count, ch := b.version+1, len(b.pending), b.changed
		b.mu.Unlock()
		// Versions handed out start at 1, so 0 always differs.
		if version != after {
			return version, count
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return version, count
		}
	}
}

// Pending returns the currently waiting requests, oldest first.
func (b *Broker) Pending() []PendingView {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]PendingView, 0, len(b.pending))
	for _, p := range b.pending {
		out = append(out, PendingView{
			ID:         p.req.ID,
			Reason:     p.req.Reason,
			Statement:  p.req.Statement,
			Query:      p.req.Query,
			RowCount:   p.req.RowCount,
			Client:     p.req.Client,
			Connection: p.req.Connection,
			Database:   p.req.Database,
			CreatedAt:  p.createdAt,
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
