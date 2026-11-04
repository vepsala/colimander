package approval

import (
	"context"
	"testing"
	"time"
)

func TestBrokerApproveThenDecide(t *testing.T) {
	b := NewBroker(2 * time.Second)
	req := Request{ID: "r1", Reason: ReasonMutation, Query: "DELETE FROM t"}

	result := make(chan Decision, 1)
	go func() { result <- b.Approve(context.Background(), req) }()

	// Wait for it to register as pending.
	waitPending(t, b, 1)
	if got := b.Pending(); got[0].ID != "r1" || got[0].Reason != ReasonMutation {
		t.Fatalf("unexpected pending view: %+v", got[0])
	}

	if !b.Decide("r1", true, "ok") {
		t.Fatal("Decide should succeed for a pending request")
	}
	select {
	case dec := <-result:
		if !dec.Approved {
			t.Fatalf("expected approval, got %+v", dec)
		}
	case <-time.After(time.Second):
		t.Fatal("Approve did not return after Decide")
	}
	if len(b.Pending()) != 0 {
		t.Error("request should be removed from pending after decision")
	}
}

func TestBrokerTimeoutDenies(t *testing.T) {
	b := NewBroker(50 * time.Millisecond)
	dec := b.Approve(context.Background(), Request{ID: "r2"})
	if dec.Approved {
		t.Fatal("timeout must deny (fail closed)")
	}
}

func TestBrokerContextCancelDenies(t *testing.T) {
	b := NewBroker(5 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { waitPending(t, b, 1); cancel() }()
	dec := b.Approve(ctx, Request{ID: "r3"})
	if dec.Approved {
		t.Fatal("cancelled client must deny")
	}
}

func TestBrokerDecideUnknownReturnsFalse(t *testing.T) {
	b := NewBroker(time.Second)
	if b.Decide("nope", true, "") {
		t.Error("deciding an unknown id should return false")
	}
}

func waitPending(t *testing.T, b *Broker, n int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if len(b.Pending()) == n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d pending", n)
}

func TestWatchWakesOnChange(t *testing.T) {
	b := NewBroker(time.Minute)
	v0, n := b.Watch(context.Background(), 0)
	if n != 0 {
		t.Fatalf("count = %d", n)
	}
	// Nothing changes: Watch holds until the context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if v, _ := b.Watch(ctx, v0); v != v0 {
		t.Errorf("version moved without a change")
	}
	cancel()

	got := make(chan int, 1)
	go func() { _, n := b.Watch(context.Background(), v0); got <- n }()
	reqCtx, stop := context.WithCancel(context.Background())
	go b.Approve(reqCtx, Request{ID: "a"})
	select {
	case n := <-got:
		if n != 1 {
			t.Errorf("pending = %d, want 1", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch didn't wake when a request arrived")
	}

	v1, _ := b.Watch(context.Background(), 0)
	stop() // the request ends
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if v, n := b.Watch(ctx2, v1); v == v1 || n != 0 {
		t.Errorf("after the request ended: version %d (was %d), pending %d", v, v1, n)
	}
}
